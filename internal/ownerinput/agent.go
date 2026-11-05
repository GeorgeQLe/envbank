package ownerinput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/authz"
)

// Agent-channel message kinds and outcomes (docs/authorized-agents.md).
const (
	KindBrokerHello  = "broker_hello"
	KindAgentRequest = "agent_request"

	OutcomeRegistered = "registered"
)

// agentRequestTimeout bounds the handling of one agent request. The host's
// service gives up after 150 s (agent tool calls after 120 s), so every
// request, including any Touch ID prompt and run, is answered before that.
const agentRequestTimeout = 140 * time.Second

// xpcField is one flattened entry of an XPC dictionary, or one instruction
// for building a reply.
//
// Received (ae_flatten): 'S' string, 'U' uint64, 'I' int64, 'B' bool, 'D' a
// dictionary rendered as JSON (strings, integers, bools, arrays and nested
// dictionaries only), 'X' anything else.
//
// Sent (ae_reply): 'S', 'U', 'I', 'B' set Key (ignored inside an array);
// '{' and '[' open a dictionary or array under Key; '}' closes it.
type xpcField struct {
	Type  byte
	Key   string
	Value string
}

// agentEvent is one event on the long-lived service connection.
type agentEvent struct {
	Kind     int
	Fields   []xpcField
	Overflow bool // the message was too large to flatten
	Msg      any  // opaque handle for Reply
}

// Event kinds.
const (
	evTimeout = iota
	evMessage
	evInterrupted
	evInvalid
	evPeer
)

// agentConn is the long-lived XPC connection to the owner-input service. The
// darwin implementation is thin C glue; tests use a fake.
type agentConn interface {
	// Hello sends broker_hello and returns the reply's outcome.
	Hello(timeout time.Duration) (string, error)
	// Next waits for the next event (evTimeout when none arrived in time).
	Next(timeout time.Duration) agentEvent
	// Reply answers a message received from Next. It is called exactly once
	// per evMessage.
	Reply(msg any, fields []xpcField)
	// Close cancels the connection.
	Close()
}

// agentDial opens the connection; macOS enforces requirement on every message.
var agentDial = dialAgentXPC

// AgentHandler handles one authorized-agent request for a host session and
// returns the value-free response JSON.
type AgentHandler interface {
	HandleAgent(ctx context.Context, s authz.Session, request []byte) []byte
}

// AgentChannel keeps the broker registered with the owner-input service as
// the target for agent requests from host sessions.
type AgentChannel struct {
	Provider    *XPCProvider
	Handler     AgentHandler
	MaxInFlight int          // default 8
	Notify      func(string) // owner terminal status lines (no values)
	Activity    func()       // called on every request (idle lock)
}

func (a *AgentChannel) notify(s string) {
	if a.Notify != nil {
		a.Notify(s)
	}
}

// Run serves agent requests until ctx ends, reconnecting with backoff. It
// requires a paired (cdhash-pinned) provider.
func (a *AgentChannel) Run(ctx context.Context) error {
	if a.Provider == nil || a.Handler == nil || !a.Provider.Pinned() {
		return errors.New(CodeNotPaired)
	}
	limit := a.MaxInFlight
	if limit <= 0 {
		limit = 8
	}
	sem := make(chan struct{}, limit)
	backoff := time.Second
	registered := false
	for ctx.Err() == nil {
		req, err := a.Provider.Requirement()
		if err != nil {
			return err
		}
		conn, err := agentDial(a.Provider.Service, req)
		if err == nil {
			var outcome string
			outcome, err = conn.Hello(10 * time.Second)
			if err == nil && outcome != OutcomeRegistered {
				err = errors.New(CodeProtocol)
			}
			if err != nil {
				conn.Close()
			}
		}
		if err != nil {
			if registered {
				a.notify("Chromux agent channel lost (" + err.Error() + "); retrying")
				registered = false
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		if !registered {
			a.notify("authorized-agent channel registered with the Chromux owner-input service")
			registered = true
		}
		a.serve(ctx, conn, sem)
		conn.Close()
	}
	return nil
}

// serve handles events until the connection fails or ctx ends; it waits for
// in-flight requests (whose contexts it cancels) before returning.
func (a *AgentChannel) serve(ctx context.Context, conn agentConn, sem chan struct{}) {
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for cctx.Err() == nil {
		ev := conn.Next(time.Second)
		switch ev.Kind {
		case evTimeout:
			continue
		case evMessage:
			a.dispatch(cctx, conn, ev, sem, &wg)
		case evInterrupted:
			// The service restarted: register again on the same connection.
			if outcome, err := conn.Hello(10 * time.Second); err != nil || outcome != OutcomeRegistered {
				return
			}
		default: // evInvalid, evPeer
			return
		}
	}
}

func (a *AgentChannel) dispatch(ctx context.Context, conn agentConn, ev agentEvent, sem chan struct{}, wg *sync.WaitGroup) {
	if a.Activity != nil {
		a.Activity()
	}
	sess, request, route, hasRoute, ok := parseAgentRequest(ev)
	if !ok {
		conn.Reply(ev.Msg, agentReply(route, hasRoute, refusal(agentbroker.CodeInvalidRequest)))
		return
	}
	select {
	case sem <- struct{}{}:
	default:
		conn.Reply(ev.Msg, agentReply(route, hasRoute, refusal(agentbroker.CodeBusy)))
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-sem }()
		rctx, cancel := context.WithTimeout(ctx, agentRequestTimeout)
		defer cancel()
		resp := a.Handler.HandleAgent(rctx, sess, request)
		conn.Reply(ev.Msg, agentReply(route, hasRoute, resp))
	}()
}

func refusal(code string) []byte {
	out, _ := json.Marshal(agentbroker.Response{V: agentbroker.ProtocolVersion, Code: code})
	return out
}

// agentReply builds exactly {v, route_id, response}: route_id is echoed when
// the request carried a valid one, and response is the value-free agent
// broker response as a dictionary.
func agentReply(route uint64, hasRoute bool, response []byte) []xpcField {
	f := []xpcField{{'S', "v", XPCVersion}}
	if hasRoute {
		f = append(f, xpcField{'U', "route_id", strconv.FormatUint(route, 10)})
	}
	body, err := jsonToFields("response", response)
	if err != nil {
		body, _ = jsonToFields("response", refusal(agentbroker.CodeInvalidRequest))
	}
	return append(f, body...)
}

// jsonToFields turns one JSON object into reply instructions. Integers become
// int64, nulls are omitted, and keys are emitted in sorted order.
func jsonToFields(key string, raw []byte) ([]xpcField, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("not an object")
	}
	var out []xpcField
	var walk func(key string, v any) error
	walk = func(key string, v any) error {
		switch x := v.(type) {
		case nil:
		case string:
			out = append(out, xpcField{'S', key, x})
		case bool:
			b := "0"
			if x {
				b = "1"
			}
			out = append(out, xpcField{'B', key, b})
		case json.Number:
			n, err := strconv.ParseInt(string(x), 10, 64)
			if err != nil {
				return err
			}
			out = append(out, xpcField{'I', key, strconv.FormatInt(n, 10)})
		case []any:
			out = append(out, xpcField{'[', key, ""})
			for _, e := range x {
				if err := walk("", e); err != nil {
					return err
				}
			}
			out = append(out, xpcField{'}', "", ""})
		case map[string]any:
			out = append(out, xpcField{'{', key, ""})
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := walk(k, x[k]); err != nil {
					return err
				}
			}
			out = append(out, xpcField{'}', "", ""})
		default:
			return errors.New("unsupported JSON value")
		}
		return nil
	}
	return out, walk(key, v)
}

// agentRequestFields is the exact top-level shape of an agent_request.
var agentRequestFields = map[string]byte{"v": 'S', "kind": 'S', "route_id": 'U', "session": 'D', "request": 'D'}

// parseAgentRequest checks the flattened message strictly: exactly the
// fields above, each with its type, the right version and kind, a session of
// exactly four valid strings and a bounded request dictionary. Anything else
// is refused with INVALID_REQUEST.
func parseAgentRequest(ev agentEvent) (s authz.Session, request []byte, route uint64, hasRoute, ok bool) {
	seen := map[string]string{}
	valid := !ev.Overflow
	for _, f := range ev.Fields {
		want, known := agentRequestFields[f.Key]
		if f.Key == "route_id" && f.Type == 'U' {
			if r, err := strconv.ParseUint(f.Value, 10, 64); err == nil && r != 0 {
				route, hasRoute = r, true
			}
		}
		if !known || want != f.Type {
			valid = false
			continue
		}
		if _, dup := seen[f.Key]; dup {
			valid = false
		}
		seen[f.Key] = f.Value
	}
	if !valid || len(seen) != len(agentRequestFields) || !hasRoute {
		return s, nil, route, hasRoute, false
	}
	if seen["v"] != XPCVersion || seen["kind"] != KindAgentRequest {
		return s, nil, route, hasRoute, false
	}
	req := seen["request"]
	if len(req) < 2 || len(req) > agentbroker.Limits.RequestBytes || !utf8.ValidString(req) {
		return s, nil, route, hasRoute, false
	}
	sess, err := parseSession([]byte(seen["session"]))
	if err != nil {
		return authz.Session{}, nil, route, hasRoute, false
	}
	return sess, []byte(req), route, hasRoute, true
}

// parseSession accepts exactly {session_id, workspace, agent_kind, label},
// all strings, all valid.
func parseSession(raw []byte) (authz.Session, error) {
	var m map[string]json.RawMessage
	if len(raw) > 4096 || json.Unmarshal(raw, &m) != nil || len(m) != 4 {
		return authz.Session{}, authz.ErrInvalidSession
	}
	get := func(k string) (string, bool) {
		v, ok := m[k]
		if !ok || len(v) == 0 || v[0] != '"' {
			return "", false
		}
		var s string
		return s, json.Unmarshal(v, &s) == nil
	}
	var s authz.Session
	var ok1, ok2, ok3, ok4 bool
	s.ID, ok1 = get("session_id")
	s.Workspace, ok2 = get("workspace")
	s.AgentKind, ok3 = get("agent_kind")
	s.Label, ok4 = get("label")
	if !ok1 || !ok2 || !ok3 || !ok4 || s.Validate() != nil {
		return authz.Session{}, authz.ErrInvalidSession
	}
	return s, nil
}

// Pinned reports whether pairing pinned the service build (cdhash).
func (p *XPCProvider) Pinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cdhash != ""
}
