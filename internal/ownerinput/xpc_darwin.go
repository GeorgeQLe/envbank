//go:build darwin && cgo

package ownerinput

/*
#cgo LDFLAGS: -framework Foundation
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Result codes (fixed).
enum { XR_OK = 0, XR_UNAVAILABLE = 1, XR_PEER = 2, XR_TIMEOUT = 3, XR_PROTOCOL = 4 };

typedef struct {
	char outcome[32];
	char nonce[40];
	char version[48];
	char service_cdhash[80];
	uint8_t *value;   // malloc'd, only when present; caller zeroes and frees
	size_t value_len;
	int has_unknown_keys;
} xr_reply;

static void copy_str(xpc_object_t d, const char *k, char *out, size_t n) {
	out[0] = 0;
	xpc_object_t v = xpc_dictionary_get_value(d, k);
	if (v && xpc_get_type(v) == XPC_TYPE_STRING) {
		const char *s = xpc_string_get_string_ptr(v);
		if (s && strlen(s) < n) strcpy(out, s);
	}
}

// One request on a fresh connection whose peer must satisfy `requirement`
// (checked by libxpc on every message). Fields arrive as parallel arrays.
static int envbank_xpc_request(const char *service, const char *requirement,
		const char **skeys, const char **svals, int ns,
		const char **ikeys, const int64_t *ivals, int ni,
		const char **bkeys, const int *bvals, int nb,
		int64_t timeout_ms, xr_reply *out) {
	memset(out, 0, sizeof(*out));
	xpc_connection_t conn = xpc_connection_create_mach_service(service, NULL, 0);
	if (!conn) return XR_UNAVAILABLE;
	if (xpc_connection_set_peer_code_signing_requirement(conn, requirement) != 0) {
		xpc_connection_cancel(conn);
		xpc_release(conn);
		return XR_PEER;
	}
	xpc_connection_set_event_handler(conn, ^(xpc_object_t e) { (void)e; });
	xpc_connection_resume(conn);
	xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
	for (int i = 0; i < ns; i++) xpc_dictionary_set_string(msg, skeys[i], svals[i]);
	for (int i = 0; i < ni; i++) xpc_dictionary_set_int64(msg, ikeys[i], ivals[i]);
	for (int i = 0; i < nb; i++) xpc_dictionary_set_bool(msg, bkeys[i], bvals[i] != 0);

	__block xpc_object_t reply = NULL;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	xpc_connection_send_message_with_reply(conn, msg, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(xpc_object_t r) {
		reply = xpc_retain(r);
		dispatch_semaphore_signal(done);
	});
	xpc_release(msg);
	long waited = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC));
	int rc = XR_OK;
	if (waited != 0) {
		rc = XR_TIMEOUT;
		xpc_connection_cancel(conn);
		dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
	} else if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
		rc = (reply == XPC_ERROR_CONNECTION_INVALID) ? XR_UNAVAILABLE : XR_PEER;
#ifdef XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT
		if (reply == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) rc = XR_PEER;
#endif
	} else if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
		rc = XR_PROTOCOL;
	} else {
		copy_str(reply, "outcome", out->outcome, sizeof(out->outcome));
		copy_str(reply, "nonce", out->nonce, sizeof(out->nonce));
		copy_str(reply, "v", out->version, sizeof(out->version));
		copy_str(reply, "service_cdhash", out->service_cdhash, sizeof(out->service_cdhash));
		xpc_object_t v = xpc_dictionary_get_value(reply, "value");
		if (v) {
			if (xpc_get_type(v) != XPC_TYPE_DATA || xpc_data_get_length(v) > 4096) {
				rc = XR_PROTOCOL;
			} else {
				out->value_len = xpc_data_get_length(v);
				out->value = malloc(out->value_len ? out->value_len : 1);
				if (out->value) memcpy(out->value, xpc_data_get_bytes_ptr(v), out->value_len);
			}
		}
		__block int unknown = 0;
		xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t val) {
			(void)val;
			if (strcmp(key, "v") && strcmp(key, "nonce") && strcmp(key, "outcome") && strcmp(key, "value") &&
			    strcmp(key, "provider") && strcmp(key, "service_cdhash")) unknown = 1;
			return true;
		});
		out->has_unknown_keys = unknown;
	}
	if (reply) xpc_release(reply);
	xpc_connection_cancel(conn);
	xpc_release(conn);
	dispatch_release(done);
	return rc;
}

static void envbank_xpc_wipe_free(uint8_t *p, size_t n) {
	if (!p) return;
	volatile uint8_t *v = p;
	for (size_t i = 0; i < n; i++) v[i] = 0;
	free(p);
}
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

// xpcRequest sends one dictionary to service (peer must satisfy requirement)
// and returns the parsed reply. The value is copied into Go memory and the C
// copy is zeroed and freed.
func xpcRequest(service, requirement string, msg xpcMessage, timeout time.Duration) (xpcReply, error) {
	cstr := func(s string) *C.char { return C.CString(s) }
	var frees []unsafe.Pointer
	defer func() {
		for _, p := range frees {
			C.free(p)
		}
	}()
	keep := func(p *C.char) *C.char { frees = append(frees, unsafe.Pointer(p)); return p }
	cService, cReq := keep(cstr(service)), keep(cstr(requirement))
	ns, ni, nb := len(msg.strings), len(msg.ints), len(msg.bools)
	alloc := func(n int, size uintptr) unsafe.Pointer {
		p := C.malloc(C.size_t(uintptr(max(n, 1)) * size))
		frees = append(frees, p)
		return p
	}
	sk := (*[1 << 10]*C.char)(alloc(ns, unsafe.Sizeof(uintptr(0))))[:max(ns, 1):max(ns, 1)]
	sv := (*[1 << 10]*C.char)(alloc(ns, unsafe.Sizeof(uintptr(0))))[:max(ns, 1):max(ns, 1)]
	i := 0
	for k, v := range msg.strings {
		sk[i], sv[i] = keep(cstr(k)), keep(cstr(v))
		i++
	}
	ik := (*[1 << 10]*C.char)(alloc(ni, unsafe.Sizeof(uintptr(0))))[:max(ni, 1):max(ni, 1)]
	iv := (*[1 << 10]C.int64_t)(alloc(ni, 8))[:max(ni, 1):max(ni, 1)]
	i = 0
	for k, v := range msg.ints {
		ik[i], iv[i] = keep(cstr(k)), C.int64_t(v)
		i++
	}
	bk := (*[1 << 10]*C.char)(alloc(nb, unsafe.Sizeof(uintptr(0))))[:max(nb, 1):max(nb, 1)]
	bv := (*[1 << 10]C.int)(alloc(nb, 4))[:max(nb, 1):max(nb, 1)]
	i = 0
	for k, v := range msg.bools {
		bk[i] = keep(cstr(k))
		if v {
			bv[i] = 1
		}
		i++
	}
	var out C.xr_reply
	rc := C.envbank_xpc_request(cService, cReq, &sk[0], &sv[0], C.int(ns), &ik[0], &iv[0], C.int(ni), &bk[0], &bv[0], C.int(nb), C.int64_t(timeout.Milliseconds()), &out)
	defer C.envbank_xpc_wipe_free(out.value, out.value_len)
	switch rc {
	case 0:
	case 1:
		return xpcReply{}, errors.New(CodeUnavailable)
	case 2:
		return xpcReply{}, errors.New(CodePeerUnverified)
	case 3:
		return xpcReply{}, errors.New(CodeUnavailable)
	default:
		return xpcReply{}, errors.New(CodeProtocol)
	}
	r := xpcReply{
		Version: C.GoString(&out.version[0]), Nonce: C.GoString(&out.nonce[0]), Outcome: C.GoString(&out.outcome[0]),
		ServiceCDHash: C.GoString(&out.service_cdhash[0]), UnknownKeys: out.has_unknown_keys != 0,
	}
	if out.value != nil {
		r.Value = C.GoBytes(unsafe.Pointer(out.value), C.int(out.value_len))
		r.HasValue = true
	}
	return r, nil
}
