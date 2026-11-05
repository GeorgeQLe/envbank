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

// agentRequestTimeout is the end-to-end budget of one agent request. The
// host's agent tool calls give up after 120 s (its service after 150 s), so
// every request, including any wait for the owner channel, Touch ID prompt
// and run, is answered within 110 s: no Touch ID prompt starts with less than
// approval.MinPromptTime left, a run's timeout_seconds is clamped to what is
// left, and a request out of budget is answered at once with
// agentbroker.CodeTimeBudget.
const agentRequestTimeout = 110 * time.Second

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
	// Request sends one message built from instructions and returns the
	// reply (pairing and entry). It may run beside Next/Reply and must fail,
	// not crash, after Close.
	Request(fields []xpcField, timeout time.Duration) (xpcRawReply, error)
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
//
// Registration needs a host-confirmed pairing ON THE SAME CONNECTION:
// broker_hello is sent only on a connection that completed pairing (the
// service's "confirmed", then the owner's Touch ID in the broker terminal).
// A new connection, or a service restart on the same one, pairs again first.
type AgentChannel struct {
	Provider *XPCProvider
	Handler  AgentHandler
	// Confirm asks the owner to confirm the pairing code in the broker
	// terminal with Touch ID, after the service reported "confirmed".
	Confirm     func(id Identity, code string) bool
	MaxInFlight int          // default 8
	Notify      func(string) // owner terminal status lines (no values)
	Activity    func()       // called on every request (idle lock)

	mu     sync.Mutex
	conn   agentConn // the current connection (paired by Open, or by Run)
	paired bool      // conn holds a host-confirmed pairing right now
}

func (a *AgentChannel) setConn(conn agentConn, paired bool) {
	a.mu.Lock()
	a.conn, a.paired = conn, paired && conn != nil
	a.mu.Unlock()
}

// pairedConn returns the connection entries may use: only one that holds a
// host-confirmed pairing.
func (a *AgentChannel) pairedConn() (agentConn, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conn, a.paired && a.conn != nil
}

// maxPairRefusals is how many pairings in a row may be declined (in Chromux
// or the broker terminal) before the channel stops; transport failures only
// back off.
const maxPairRefusals = 3

// Open connects and pairs on the connection Run will register on, pinning the
// service build. It does not register: no agent request reaches the broker
// before Run.
func (a *AgentChannel) Open(ctx context.Context) error {
	if a.Provider == nil || a.Confirm == nil {
		return errors.New(CodeNotPaired)
	}
	conn, err := a.connect(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	old := a.conn
	a.conn, a.paired = conn, true
	a.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// connect dials and pairs; the connection is returned only if paired.
func (a *AgentChannel) connect(ctx context.Context) (agentConn, error) {
	req, err := a.Provider.Requirement()
	if err != nil {
		return nil, err
	}
	conn, err := agentDial(a.Provider.Service, req)
	if err != nil {
		return nil, err
	}
	if err := a.Provider.pairOn(ctx, conn, a.Confirm); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// register says hello on a paired connection.
func register(conn agentConn) error {
	outcome, err := conn.Hello(10 * time.Second)
	if err == nil && outcome != OutcomeRegistered {
		err = errors.New(CodeProtocol)
	}
	return err
}

func (a *AgentChannel) notify(s string) {
	if a.Notify != nil {
		a.Notify(s)
	}
}

// Run serves agent requests until ctx ends, reconnecting (and pairing
// again) with backoff. It requires a pinned provider (Open).
func (a *AgentChannel) Run(ctx context.Context) error {
	if a.Provider == nil || a.Handler == nil || a.Confirm == nil || !a.Provider.Pinned() {
		return errors.New(CodeNotPaired)
	}
	limit := a.MaxInFlight
	if limit <= 0 {
		limit = 8
	}
	sem := make(chan struct{}, limit)
	backoff := time.Second
	refusals := 0
	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	defer func() {
		a.setConn(nil, false)
		if conn != nil {
			conn.Close()
		}
	}()
	for ctx.Err() == nil {
		var err error
		if conn == nil {
			if conn, err = a.connect(ctx); err == nil {
				a.setConn(conn, true)
			}
		}
		if err == nil {
			err = register(conn)
		}
		if err == nil {
			refusals, backoff = 0, time.Second
			a.notify("authorized-agent channel registered with the Chromux owner-input service")
			if a.serve(ctx, conn, sem) && ctx.Err() == nil {
				// The service restarted and lost the pairing: pair again on
				// this connection before saying hello on it.
				a.notify("Chromux owner-input service restarted; pair again to continue")
				a.setConn(conn, false) // no entries until the pairing is confirmed again
				if err = a.Provider.pairOn(ctx, conn, a.Confirm); err == nil {
					a.setConn(conn, true)
					continue
				}
			} else {
				err = errors.New(CodeUnavailable)
			}
		}
		if conn != nil {
			a.setConn(nil, false)
			conn.Close()
			conn = nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && err.Error() == CodeNotPaired {
			if refusals++; refusals >= maxPairRefusals {
				a.notify("Chromux pairing was not confirmed " + strconv.Itoa(refusals) + " times; agent channel stopped (restart the broker to pair again)")
				return errors.New(CodeNotPaired)
			}
		}
		a.notify("Chromux agent channel not registered (" + err.Error() + "); retrying")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
	return nil
}

// serve handles events until the connection fails or ctx ends; it waits for
// in-flight requests (whose contexts it cancels) before returning. It reports
// whether the connection was interrupted (the service restarted).
func (a *AgentChannel) serve(ctx context.Context, conn agentConn, sem chan struct{}) (interrupted bool) {
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
			return true
		default: // evInvalid, evPeer
			return false
		}
	}
	return false
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
