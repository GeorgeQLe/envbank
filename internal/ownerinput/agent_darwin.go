//go:build darwin && cgo

package ownerinput

/*
#cgo LDFLAGS: -framework Foundation
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Thin glue for the long-lived agent channel. Policy and parsing live in Go:
// C only queues incoming events, flattens a dictionary into typed records and
// builds replies from records.

enum { AE_TIMEOUT = 0, AE_MESSAGE = 1, AE_INTERRUPTED = 2, AE_INVALID = 3, AE_PEER = 4 };
enum { AE_QUEUE_MAX = 64, AE_FLAT_MAX = 128 * 1024 };

typedef struct ae_node { struct ae_node *next; int kind; xpc_object_t msg; } ae_node;

typedef struct {
	xpc_connection_t conn;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	ae_node *head, *tail;
	int count;
	int refs; // Go's handle + the event handler (until CONNECTION_INVALID)
} ae_chan;

static void ae_free(ae_chan *c) {
	ae_node *n = c->head;
	while (n) {
		ae_node *next = n->next;
		if (n->msg) xpc_release(n->msg);
		free(n);
		n = next;
	}
	pthread_mutex_destroy(&c->mu);
	pthread_cond_destroy(&c->cv);
	xpc_release(c->conn);
	free(c);
}

static void ae_unref(ae_chan *c) {
	pthread_mutex_lock(&c->mu);
	int left = --c->refs;
	pthread_mutex_unlock(&c->mu);
	if (left == 0) ae_free(c);
}

// ae_busy answers a message the queue cannot hold, without Go:
// {v, route_id, response:{v:1, ok:false, code:"BROKER_BUSY"}}.
static void ae_busy(xpc_object_t msg, const char *version) {
	xpc_object_t reply = xpc_dictionary_create_reply(msg);
	if (!reply) return;
	xpc_dictionary_set_string(reply, "v", version);
	xpc_object_t r = xpc_dictionary_get_value(msg, "route_id");
	if (r && xpc_get_type(r) == XPC_TYPE_UINT64) xpc_dictionary_set_uint64(reply, "route_id", xpc_uint64_get_value(r));
	xpc_object_t resp = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_int64(resp, "v", 1);
	xpc_dictionary_set_bool(resp, "ok", false);
	xpc_dictionary_set_string(resp, "code", "BROKER_BUSY");
	xpc_dictionary_set_value(reply, "response", resp);
	xpc_release(resp);
	xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
	xpc_release(reply);
}

static void ae_push(ae_chan *c, int kind, xpc_object_t msg, const char *version) {
	ae_node *n = calloc(1, sizeof(*n));
	pthread_mutex_lock(&c->mu);
	if (!n || (kind == AE_MESSAGE && c->count >= AE_QUEUE_MAX)) {
		pthread_mutex_unlock(&c->mu);
		if (msg) { ae_busy(msg, version); xpc_release(msg); }
		free(n);
		return;
	}
	n->kind = kind;
	n->msg = msg;
	if (c->tail) c->tail->next = n; else c->head = n;
	c->tail = n;
	c->count++;
	pthread_cond_signal(&c->cv);
	pthread_mutex_unlock(&c->mu);
}

static ae_chan *ae_open(const char *service, const char *requirement, const char *version_in) {
	ae_chan *c = calloc(1, sizeof(*c));
	if (!c) return NULL;
	c->conn = xpc_connection_create_mach_service(service, NULL, 0);
	if (!c->conn) { free(c); return NULL; }
	if (xpc_connection_set_peer_code_signing_requirement(c->conn, requirement) != 0) {
		xpc_connection_cancel(c->conn);
		xpc_release(c->conn);
		free(c);
		return NULL;
	}
	pthread_mutex_init(&c->mu, NULL);
	pthread_cond_init(&c->cv, NULL);
	c->refs = 2;
	char *version = strdup(version_in); // owned by the handler block for its lifetime
	xpc_connection_set_event_handler(c->conn, ^(xpc_object_t e) {
		xpc_type_t t = xpc_get_type(e);
		if (t == XPC_TYPE_DICTIONARY) {
			ae_push(c, AE_MESSAGE, xpc_retain(e), version);
		} else if (e == XPC_ERROR_CONNECTION_INTERRUPTED) {
			ae_push(c, AE_INTERRUPTED, NULL, version);
		} else if (e == XPC_ERROR_CONNECTION_INVALID) {
			ae_push(c, AE_INVALID, NULL, version); // the final event
			free(version);
			ae_unref(c);
		} else {
			ae_push(c, AE_PEER, NULL, version); // peer requirement failed, or another error
		}
	});
	xpc_connection_resume(c->conn);
	return c;
}

static void ae_close(ae_chan *c) {
	xpc_connection_cancel(c->conn); // the handler then receives CONNECTION_INVALID
	ae_unref(c);
}

// ae_next pops the next event, waiting at most timeout_ms.
static int ae_next(ae_chan *c, int64_t timeout_ms, xpc_object_t *msg) {
	*msg = NULL;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout_ms / 1000;
	ts.tv_nsec += (timeout_ms % 1000) * 1000000;
	if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
	pthread_mutex_lock(&c->mu);
	while (!c->head) {
		if (pthread_cond_timedwait(&c->cv, &c->mu, &ts) != 0 && !c->head) {
			pthread_mutex_unlock(&c->mu);
			return AE_TIMEOUT;
		}
	}
	ae_node *n = c->head;
	c->head = n->next;
	if (!c->head) c->tail = NULL;
	c->count--;
	pthread_mutex_unlock(&c->mu);
	int kind = n->kind;
	*msg = n->msg;
	free(n);
	return kind;
}

// ae_hello sends {v, kind:"broker_hello"} and copies the reply's outcome.
static int ae_hello(ae_chan *c, const char *version, int64_t timeout_ms, char *outcome, size_t n) {
	outcome[0] = 0;
	xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(msg, "v", version);
	xpc_dictionary_set_string(msg, "kind", "broker_hello");
	__block xpc_object_t reply = NULL;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	xpc_connection_send_message_with_reply(c->conn, msg, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(xpc_object_t r) {
		reply = xpc_retain(r);
		dispatch_semaphore_signal(done);
	});
	xpc_release(msg);
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC)) != 0) {
		// Cancelling makes the pending reply handler run with an error.
		xpc_connection_cancel(c->conn);
		if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0) {
			dispatch_release(done);
			if (reply) xpc_release(reply);
		}
		return AE_TIMEOUT;
	}
	dispatch_release(done);
	int rc = AE_MESSAGE;
	if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
		rc = AE_PEER;
	} else {
		const char *v = xpc_dictionary_get_string(reply, "v");
		const char *k = xpc_dictionary_get_string(reply, "kind");
		const char *o = xpc_dictionary_get_string(reply, "outcome");
		if (v && strcmp(v, version) == 0 && k && strcmp(k, "broker_hello") == 0 && o && strlen(o) < n) strcpy(outcome, o);
	}
	xpc_release(reply);
	return rc;
}

// ae_request sends one dictionary built from instructions (see ae_build) on
// the long-lived connection and waits at most timeout_ms for its reply. On
// AE_MESSAGE *reply_out holds the reply dictionary (the caller releases it).
static int ae_build(xpc_object_t root, const char **types, const char **keys, const char **vals, int n);
static void ae_ref(ae_chan *c) {
	pthread_mutex_lock(&c->mu);
	c->refs++;
	pthread_mutex_unlock(&c->mu);
}

// ae_request holds its own reference: a concurrent ae_close cannot free c
// while a request (an entry waiting for the owner) is outstanding.
static int ae_request_locked(ae_chan *c, const char **types, const char **keys, const char **vals, int n, int64_t timeout_ms, xpc_object_t *reply_out);
static int ae_request(ae_chan *c, const char **types, const char **keys, const char **vals, int n, int64_t timeout_ms, xpc_object_t *reply_out) {
	ae_ref(c);
	int rc = ae_request_locked(c, types, keys, vals, n, timeout_ms, reply_out);
	ae_unref(c);
	return rc;
}

// ae_value copies the reply's top-level `value` data into a malloc'd buffer
// (the caller zeroes and frees it). It returns 1 with no value, 2 with a
// value, and 0 if `value` is present but not data or longer than 4096 bytes.
static int ae_value(xpc_object_t reply, uint8_t **out, size_t *len) {
	*out = NULL;
	*len = 0;
	xpc_object_t v = xpc_dictionary_get_value(reply, "value");
	if (!v) return 1;
	if (xpc_get_type(v) != XPC_TYPE_DATA || xpc_data_get_length(v) > 4096) return 0;
	*len = xpc_data_get_length(v);
	*out = malloc(*len ? *len : 1);
	if (!*out) return 0;
	memcpy(*out, xpc_data_get_bytes_ptr(v), *len);
	return 2;
}

static void ae_wipe_free(uint8_t *p, size_t n) {
	if (!p) return;
	volatile uint8_t *v = p;
	for (size_t i = 0; i < n; i++) v[i] = 0;
	free(p);
}

static int ae_request_locked(ae_chan *c, const char **types, const char **keys, const char **vals, int n, int64_t timeout_ms, xpc_object_t *reply_out) {
	*reply_out = NULL;
	xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
	if (!ae_build(msg, types, keys, vals, n)) {
		xpc_release(msg);
		return AE_INVALID;
	}
	__block xpc_object_t reply = NULL;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	xpc_connection_send_message_with_reply(c->conn, msg, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(xpc_object_t r) {
		reply = xpc_retain(r);
		dispatch_semaphore_signal(done);
	});
	xpc_release(msg);
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC)) != 0) {
		xpc_connection_cancel(c->conn); // the pending reply handler then runs with an error
		if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0) {
			dispatch_release(done);
			if (reply) xpc_release(reply);
		}
		return AE_TIMEOUT;
	}
	dispatch_release(done);
	if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
		xpc_release(reply);
		return AE_PEER;
	}
	*reply_out = reply;
	return AE_MESSAGE;
}

static int ae_put(uint8_t *buf, size_t *len, char type, const char *key, const char *val, size_t vl) {
	size_t kl = strlen(key);
	if (*len + 1 + kl + 1 + vl + 1 > AE_FLAT_MAX) return 0;
	buf[(*len)++] = (uint8_t)type;
	memcpy(buf + *len, key, kl + 1); *len += kl + 1;
	memcpy(buf + *len, val, vl); *len += vl;
	buf[(*len)++] = 0;
	return 1;
}

typedef struct { char *b; size_t n, cap; int ok; } ae_js;

static void js_raw(ae_js *j, const char *s, size_t n) {
	if (!j->ok) return;
	if (j->n + n > j->cap) { j->ok = 0; return; }
	memcpy(j->b + j->n, s, n);
	j->n += n;
}

static void js_str(ae_js *j, const char *s) {
	static const char hex[] = "0123456789abcdef";
	js_raw(j, "\"", 1);
	for (const unsigned char *p = (const unsigned char *)s; *p && j->ok; p++) {
		if (*p == '"' || *p == '\\') { char e[2] = {'\\', (char)*p}; js_raw(j, e, 2); }
		else if (*p < 0x20) { char e[6] = {'\\', 'u', '0', '0', hex[*p >> 4], hex[*p & 15]}; js_raw(j, e, 6); }
		else js_raw(j, (const char *)p, 1);
	}
	js_raw(j, "\"", 1);
}

// js_value renders strings, integers, bools, null, arrays and dictionaries
// (at most 6 levels) as JSON; any other type fails the whole message.
static void js_value(ae_js *j, xpc_object_t v, int depth) {
	if (!j->ok) return;
	if (depth > 6) { j->ok = 0; return; }
	xpc_type_t t = xpc_get_type(v);
	char num[32];
	if (t == XPC_TYPE_STRING) js_str(j, xpc_string_get_string_ptr(v));
	else if (t == XPC_TYPE_INT64) { int n = snprintf(num, sizeof num, "%lld", (long long)xpc_int64_get_value(v)); js_raw(j, num, (size_t)n); }
	else if (t == XPC_TYPE_UINT64) { int n = snprintf(num, sizeof num, "%llu", (unsigned long long)xpc_uint64_get_value(v)); js_raw(j, num, (size_t)n); }
	else if (t == XPC_TYPE_BOOL) { if (xpc_bool_get_value(v)) js_raw(j, "true", 4); else js_raw(j, "false", 5); }
	else if (t == XPC_TYPE_NULL) js_raw(j, "null", 4);
	else if (t == XPC_TYPE_ARRAY) {
		js_raw(j, "[", 1);
		__block int first = 1;
		xpc_array_apply(v, ^bool(size_t i, xpc_object_t e) {
			(void)i;
			if (!first) js_raw(j, ",", 1);
			first = 0;
			js_value(j, e, depth + 1);
			return j->ok;
		});
		js_raw(j, "]", 1);
	} else if (t == XPC_TYPE_DICTIONARY) {
		js_raw(j, "{", 1);
		__block int first = 1;
		xpc_dictionary_apply(v, ^bool(const char *k, xpc_object_t e) {
			if (!first) js_raw(j, ",", 1);
			first = 0;
			js_str(j, k);
			js_raw(j, ":", 1);
			js_value(j, e, depth + 1);
			return j->ok;
		});
		js_raw(j, "}", 1);
	} else j->ok = 0;
}

// ae_flatten writes typed records "T key\0 value\0" for the top level:
// strings, integers and bools as text, dictionaries as JSON ('D'), anything
// else as 'X'. It returns NULL (and *overflow = 1) past AE_FLAT_MAX or on a
// dictionary holding an unsupported type.
static uint8_t *ae_flatten(xpc_object_t msg, size_t *out_len, int *overflow) {
	*out_len = 0;
	*overflow = 0;
	uint8_t *buf = malloc(AE_FLAT_MAX);
	char *js = malloc(AE_FLAT_MAX);
	if (!buf || !js) { free(buf); free(js); *overflow = 1; return NULL; }
	__block size_t len = 0;
	__block int ok = 1;
	xpc_dictionary_apply(msg, ^bool(const char *key, xpc_object_t v) {
		xpc_type_t t = xpc_get_type(v);
		char num[32];
		if (t == XPC_TYPE_STRING) { const char *s = xpc_string_get_string_ptr(v); ok = ae_put(buf, &len, 'S', key, s, strlen(s)); }
		else if (t == XPC_TYPE_UINT64) { int n = snprintf(num, sizeof num, "%llu", (unsigned long long)xpc_uint64_get_value(v)); ok = ae_put(buf, &len, 'U', key, num, (size_t)n); }
		else if (t == XPC_TYPE_INT64) { int n = snprintf(num, sizeof num, "%lld", (long long)xpc_int64_get_value(v)); ok = ae_put(buf, &len, 'I', key, num, (size_t)n); }
		else if (t == XPC_TYPE_BOOL) ok = ae_put(buf, &len, 'B', key, xpc_bool_get_value(v) ? "1" : "0", 1);
		else if (t == XPC_TYPE_DICTIONARY) {
			ae_js j = { js, 0, AE_FLAT_MAX - 1, 1 };
			js_value(&j, v, 0);
			ok = j.ok && memchr(js, 0, j.n) == NULL && ae_put(buf, &len, 'D', key, js, j.n);
		} else ok = ae_put(buf, &len, 'X', key, "", 0);
		return ok;
	});
	free(js);
	if (!ok) { free(buf); *overflow = 1; return NULL; }
	*out_len = len;
	return buf;
}

// ae_build fills root from instructions (see xpcField in agent.go). It
// returns 0 on unbalanced or too deeply nested instructions.
static int ae_build(xpc_object_t root, const char **types, const char **keys, const char **vals, int n) {
	xpc_object_t stack[8];
	int top = 0;
	stack[0] = root;
	for (int i = 0; i < n; i++) {
		char t = types[i][0];
		xpc_object_t cur = stack[top];
		int in_array = xpc_get_type(cur) == XPC_TYPE_ARRAY;
		if (t == '}') { if (top == 0) return 0; top--; continue; }
		if (t == '{' || t == '[') {
			if (top == 7) return 0;
			xpc_object_t child = t == '{' ? xpc_dictionary_create(NULL, NULL, 0) : xpc_array_create(NULL, 0);
			if (in_array) xpc_array_append_value(cur, child); else xpc_dictionary_set_value(cur, keys[i], child);
			xpc_release(child); // the parent holds it
			stack[++top] = child;
			continue;
		}
		xpc_object_t v;
		if (t == 'U') v = xpc_uint64_create(strtoull(vals[i], NULL, 10));
		else if (t == 'I') v = xpc_int64_create(strtoll(vals[i], NULL, 10));
		else if (t == 'B') v = xpc_bool_create(vals[i][0] == '1');
		else v = xpc_string_create(vals[i]);
		if (in_array) xpc_array_append_value(cur, v); else xpc_dictionary_set_value(cur, keys[i], v);
		xpc_release(v);
	}
	return top == 0;
}

// ae_reply builds the reply from instructions, sends it and releases msg.
static void ae_reply(xpc_object_t msg, const char **types, const char **keys, const char **vals, int n) {
	xpc_object_t reply = xpc_dictionary_create_reply(msg);
	if (reply) {
		if (ae_build(reply, types, keys, vals, n)) xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
		xpc_release(reply);
	}
	xpc_release(msg);
}

static void ae_release(xpc_object_t msg) { if (msg) xpc_release(msg); }

// ae_selftest_value builds {value: <kind>} (0 none, 1 data "pass\0word",
// 2 a string, 3 5000 bytes of data) for the value-extraction test. It sends
// nothing.
static xpc_object_t ae_selftest_value(int kind) {
	xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
	static uint8_t big[5000];
	if (kind == 1) xpc_dictionary_set_data(m, "value", "pass\0word", 9);
	if (kind == 2) xpc_dictionary_set_string(m, "value", "x");
	if (kind == 3) xpc_dictionary_set_data(m, "value", big, sizeof big);
	return m;
}

// ae_selftest_message builds an agent_request-shaped dictionary (plus an
// int64, a bool and a top-level data value) for the flatten test. It sends
// nothing.
static xpc_object_t ae_selftest_message(void) {
	xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t s = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t r = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t a = xpc_array_create(NULL, 0);
	xpc_dictionary_set_string(m, "v", "envbank.owner-input-xpc/v1");
	xpc_dictionary_set_string(m, "kind", "agent_request");
	xpc_dictionary_set_uint64(m, "route_id", 18446744073709551615ULL);
	xpc_dictionary_set_int64(m, "n", -5);
	xpc_dictionary_set_bool(m, "b", true);
	xpc_dictionary_set_data(m, "blob", "x", 1);
	xpc_dictionary_set_string(s, "session_id", "AbCdEfGhIjKlMnOpQrStUvWx");
	xpc_dictionary_set_string(s, "workspace", "ws-main");
	xpc_dictionary_set_string(s, "agent_kind", "claude");
	xpc_dictionary_set_string(s, "label", "Say \"hi\"\n");
	xpc_dictionary_set_value(m, "session", s);
	xpc_dictionary_set_string(r, "op", "run");
	xpc_array_set_string(a, XPC_ARRAY_APPEND, "API_KEY");
	xpc_dictionary_set_value(r, "secrets", a);
	xpc_dictionary_set_int64(r, "timeout_seconds", 30);
	xpc_dictionary_set_bool(r, "always", true);
	xpc_dictionary_set_value(m, "request", r);
	xpc_release(s); xpc_release(r); xpc_release(a);
	return m;
}

// ae_selftest_reply builds a reply-shaped dictionary from instructions into
// a plain dictionary and renders it as JSON (tests only; sends nothing).
static char *ae_selftest_build(const char **types, const char **keys, const char **vals, int n) {
	xpc_object_t root = xpc_dictionary_create(NULL, NULL, 0);
	if (!ae_build(root, types, keys, vals, n)) { xpc_release(root); return NULL; }
	char *js = malloc(AE_FLAT_MAX);
	ae_js j = { js, 0, AE_FLAT_MAX - 1, 1 };
	js_value(&j, root, 0);
	xpc_release(root);
	if (!j.ok) { free(js); return NULL; }
	js[j.n] = 0;
	return js;
}
*/
import "C"

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type xpcAgentConn struct {
	c       *C.ae_chan
	once    sync.Once
	version *C.char

	mu     sync.Mutex
	closed bool // Request refuses after Close (entries run beside serve)
}

func dialAgentXPC(service, requirement string) (agentConn, error) {
	cs, cr, cv := C.CString(service), C.CString(requirement), C.CString(XPCVersion)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cr))
	defer C.free(unsafe.Pointer(cv))
	c := C.ae_open(cs, cr, cv)
	if c == nil {
		return nil, errors.New(CodeUnavailable)
	}
	return &xpcAgentConn{c: c, version: C.CString(XPCVersion)}, nil
}

func (x *xpcAgentConn) Hello(timeout time.Duration) (string, error) {
	var out [32]C.char
	switch C.ae_hello(x.c, x.version, C.int64_t(timeout.Milliseconds()), &out[0], C.size_t(len(out))) {
	case C.AE_MESSAGE:
		return C.GoString(&out[0]), nil
	case C.AE_TIMEOUT:
		return "", errors.New(CodeUnavailable)
	default:
		return "", errors.New(CodePeerUnverified)
	}
}

func (x *xpcAgentConn) Request(fields []xpcField, timeout time.Duration) (xpcRawReply, error) {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return xpcRawReply{}, errors.New(CodeUnavailable)
	}
	C.ae_ref(x.c) // released below; keeps c alive across a concurrent Close
	x.mu.Unlock()
	defer C.ae_unref(x.c)
	types, keys, vals, free := cFields(fields)
	defer free()
	var reply C.xpc_object_t
	switch C.ae_request(x.c, &types[0], &keys[0], &vals[0], C.int(len(fields)), C.int64_t(timeout.Milliseconds()), &reply) {
	case C.AE_MESSAGE:
	case C.AE_TIMEOUT:
		return xpcRawReply{}, errors.New(CodeUnavailable)
	case C.AE_INVALID:
		return xpcRawReply{}, errors.New(CodeProtocol)
	default:
		return xpcRawReply{}, errors.New(CodePeerUnverified)
	}
	defer C.ae_release(reply)
	var out xpcRawReply
	var vbuf *C.uint8_t
	var vlen C.size_t
	switch C.ae_value(reply, &vbuf, &vlen) {
	case 2:
		out.Value, out.HasValue = C.GoBytes(unsafe.Pointer(vbuf), C.int(vlen)), true
		C.ae_wipe_free(vbuf, vlen)
	case 1:
	default:
		return xpcRawReply{}, errors.New(CodeProtocol)
	}
	var n C.size_t
	var overflow C.int
	buf := C.ae_flatten(reply, &n, &overflow)
	if buf == nil || overflow != 0 {
		if buf != nil {
			C.free(unsafe.Pointer(buf))
		}
		wipe(out.Value)
		return xpcRawReply{}, errors.New(CodeProtocol)
	}
	defer C.free(unsafe.Pointer(buf))
	out.Fields = parseFlat(C.GoBytes(unsafe.Pointer(buf), C.int(n)))
	return out, nil
}

func (x *xpcAgentConn) Next(timeout time.Duration) agentEvent {
	var msg C.xpc_object_t
	kind := C.ae_next(x.c, C.int64_t(timeout.Milliseconds()), &msg)
	switch kind {
	case C.AE_TIMEOUT:
		return agentEvent{Kind: evTimeout}
	case C.AE_INTERRUPTED:
		return agentEvent{Kind: evInterrupted}
	case C.AE_INVALID:
		return agentEvent{Kind: evInvalid}
	case C.AE_MESSAGE:
	default:
		return agentEvent{Kind: evPeer}
	}
	var n C.size_t
	var overflow C.int
	buf := C.ae_flatten(msg, &n, &overflow)
	ev := agentEvent{Kind: evMessage, Msg: msg, Overflow: overflow != 0}
	if buf != nil {
		ev.Fields = parseFlat(C.GoBytes(unsafe.Pointer(buf), C.int(n)))
		C.free(unsafe.Pointer(buf))
	}
	return ev
}

// parseFlat decodes ae_flatten's records.
func parseFlat(b []byte) []xpcField {
	var out []xpcField
	for len(b) > 0 {
		t := b[0]
		b = b[1:]
		k := bytes.IndexByte(b, 0)
		if k < 0 {
			return append(out, xpcField{Type: 'X'})
		}
		key := string(b[:k])
		b = b[k+1:]
		v := bytes.IndexByte(b, 0)
		if v < 0 {
			return append(out, xpcField{Type: 'X'})
		}
		out = append(out, xpcField{Type: t, Key: key, Value: string(b[:v])})
		b = b[v+1:]
	}
	return out
}

// cFields copies instructions into C arrays; free releases them.
func cFields(fields []xpcField) (types, keys, vals []*C.char, free func()) {
	n := max(len(fields), 1)
	var frees []unsafe.Pointer
	arr := func() []*C.char {
		p := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
		frees = append(frees, p)
		return unsafe.Slice((**C.char)(p), n)
	}
	types, keys, vals = arr(), arr(), arr()
	for i, f := range fields {
		val := f.Value
		if strings.IndexByte(val, 0) >= 0 {
			val = "" // never sent truncated; JSON responses contain no raw NUL
		}
		for j, s := range []string{string(f.Type), f.Key, val} {
			p := C.CString(s)
			frees = append(frees, unsafe.Pointer(p))
			[][]*C.char{types, keys, vals}[j][i] = p
		}
	}
	return types, keys, vals, func() {
		for _, p := range frees {
			C.free(p)
		}
	}
}

func (x *xpcAgentConn) Reply(msg any, fields []xpcField) {
	m, ok := msg.(C.xpc_object_t)
	if !ok || m == nil {
		return
	}
	types, keys, vals, free := cFields(fields)
	defer free()
	C.ae_reply(m, &types[0], &keys[0], &vals[0], C.int(len(fields)))
}

// buildSelfTest builds instructions into an XPC dictionary and renders it as
// JSON (tests only; sends nothing).
func buildSelfTest(fields []xpcField) string {
	types, keys, vals, free := cFields(fields)
	defer free()
	js := C.ae_selftest_build(&types[0], &keys[0], &vals[0], C.int(len(fields)))
	if js == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(js))
	return C.GoString(js)
}

// flattenSelfTest flattens ae_selftest_message (tests only; sends nothing).
func flattenSelfTest() ([]xpcField, bool) {
	m := C.ae_selftest_message()
	defer C.ae_release(m)
	var n C.size_t
	var overflow C.int
	buf := C.ae_flatten(m, &n, &overflow)
	if buf == nil {
		return nil, overflow != 0
	}
	defer C.free(unsafe.Pointer(buf))
	return parseFlat(C.GoBytes(unsafe.Pointer(buf), C.int(n))), overflow != 0
}

// valueSelfTest runs ae_value on ae_selftest_value(kind) (tests only).
func valueSelfTest(kind int) ([]byte, int) {
	m := C.ae_selftest_value(C.int(kind))
	defer C.ae_release(m)
	var buf *C.uint8_t
	var n C.size_t
	rc := int(C.ae_value(m, &buf, &n))
	var out []byte
	if buf != nil {
		out = C.GoBytes(unsafe.Pointer(buf), C.int(n))
		C.ae_wipe_free(buf, n)
	}
	return out, rc
}

func (x *xpcAgentConn) Close() {
	x.mu.Lock()
	x.closed = true
	x.mu.Unlock()
	x.once.Do(func() {
		C.ae_close(x.c)
		C.free(unsafe.Pointer(x.version))
	})
}
