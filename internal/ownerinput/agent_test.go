package ownerinput

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/authz"
)

const validSession = `{"agent_kind":"claude","label":"Deploy preview","session_id":"AbCdEfGhIjKlMnOpQrStUvWx","workspace":"ws-main"}`

// validFields is a flattened agent_request as the host sends it: request is
// a dictionary without `v`.
func validFields() []xpcField {
	return []xpcField{
		{'S', "v", XPCVersion}, {'S', "kind", KindAgentRequest}, {'U', "route_id", "42"},
		{'D', "session", validSession}, {'D', "request", `{"op":"names"}`},
	}
}

func with(fields []xpcField, edit func([]xpcField) []xpcField) []xpcField {
	return edit(append([]xpcField(nil), fields...))
}

func replace(key string, f xpcField) func([]xpcField) []xpcField {
	return func(fs []xpcField) []xpcField {
		for i := range fs {
			if fs[i].Key == key {
				fs[i] = f
			}
		}
		return fs
	}
}

func drop(key string) func([]xpcField) []xpcField {
	return func(fs []xpcField) []xpcField {
		out := fs[:0]
		for _, f := range fs {
			if f.Key != key {
				out = append(out, f)
			}
		}
		return out
	}
}

func add(f xpcField) func([]xpcField) []xpcField {
	return func(fs []xpcField) []xpcField { return append(fs, f) }
}

func session(edit func(map[string]any)) xpcField {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(validSession), &m)
	edit(m)
	raw, _ := json.Marshal(m)
	return xpcField{'D', "session", string(raw)}
}

func TestParseAgentRequestIsStrict(t *testing.T) {
	s, req, route, hasRoute, ok := parseAgentRequest(agentEvent{Kind: evMessage, Fields: validFields()})
	if !ok || !hasRoute || route != 42 || string(req) != `{"op":"names"}` || s.Label != "Deploy preview" || s.AgentKind != "claude" {
		t.Fatalf("valid message refused: %v %v %v %+v", ok, route, string(req), s)
	}
	cases := map[string][]xpcField{
		"wrong version":        with(validFields(), replace("v", xpcField{'S', "v", "envbank.owner-input-xpc/v2"})),
		"wrong kind":           with(validFields(), replace("kind", xpcField{'S', "kind", "entry"})),
		"route as string":      with(validFields(), replace("route_id", xpcField{'S', "route_id", "42"})),
		"route as int64":       with(validFields(), replace("route_id", xpcField{'I', "route_id", "42"})),
		"route zero":           with(validFields(), replace("route_id", xpcField{'U', "route_id", "0"})),
		"route junk":           with(validFields(), replace("route_id", xpcField{'U', "route_id", "x"})),
		"no route":             with(validFields(), drop("route_id")),
		"no request":           with(validFields(), drop("request")),
		"request as string":    with(validFields(), replace("request", xpcField{'S', "request", `{"op":"names"}`})),
		"request not utf8":     with(validFields(), replace("request", xpcField{'D', "request", "{\"op\":\"\xff\"}"})),
		"request too long":     with(validFields(), replace("request", xpcField{'D', "request", `{"op":"` + strings.Repeat("x", agentbroker.Limits.RequestBytes) + `"}`})),
		"request as data":      with(validFields(), replace("request", xpcField{'X', "request", ""})),
		"no session":           with(validFields(), drop("session")),
		"session as string":    with(validFields(), replace("session", xpcField{'S', "session", validSession})),
		"session not json":     with(validFields(), replace("session", xpcField{'D', "session", "{"})),
		"session no label":     with(validFields(), replace("session", session(func(m map[string]any) { delete(m, "label") }))),
		"session extra key":    with(validFields(), replace("session", session(func(m map[string]any) { m["extra"] = "x" }))),
		"session label number": with(validFields(), replace("session", session(func(m map[string]any) { m["label"] = 7 }))),
		"session id array":     with(validFields(), replace("session", session(func(m map[string]any) { m["session_id"] = []string{"a"} }))),
		"short session id":     with(validFields(), replace("session", session(func(m map[string]any) { m["session_id"] = "short" }))),
		"bidi label":           with(validFields(), replace("session", session(func(m map[string]any) { m["label"] = "a\u202eb" }))),
		"control label":        with(validFields(), replace("session", session(func(m map[string]any) { m["label"] = "a\x1b[2Jb" }))),
		"label too long":       with(validFields(), replace("session", session(func(m map[string]any) { m["label"] = strings.Repeat("x", 81) }))),
		"workspace with space": with(validFields(), replace("session", session(func(m map[string]any) { m["workspace"] = "a b" }))),
		"agent kind upper":     with(validFields(), replace("session", session(func(m map[string]any) { m["agent_kind"] = "Claude" }))),
		"unknown top key":      with(validFields(), add(xpcField{'S', "value", "x"})),
		"bool extra":           with(validFields(), add(xpcField{'B', "confirm", "1"})),
		"data extra":           with(validFields(), add(xpcField{'X', "blob", ""})),
		"duplicate key":        with(validFields(), add(xpcField{'D', "request", `{"op":"names"}`})),
	}
	for name, fields := range cases {
		if _, _, _, _, ok := parseAgentRequest(agentEvent{Kind: evMessage, Fields: fields}); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, _, _, ok := parseAgentRequest(agentEvent{Kind: evMessage, Fields: validFields(), Overflow: true}); ok {
		t.Fatal("overflowed message accepted")
	}
}

// Random mutations never panic, and anything accepted has the exact shape.
func TestParseAgentRequestFuzzish(t *testing.T) {
	types := []byte{'S', 'U', 'I', 'B', 'D', 'X'}
	keys := []string{"v", "kind", "route_id", "request", "session", "x", ""}
	vals := []string{"", "0", "42", "{}", "[]", "null", XPCVersion, KindAgentRequest, "\x00", "\xff", validSession, `{"op":"names"}`, strings.Repeat("y", 300),
		`{"session_id":"AbCdEfGhIjKlMnOpQrStUvWx","workspace":"w","agent_kind":"c","label":"l","x":1}`}
	pick := func(n int) int { v, _ := rand.Int(rand.Reader, big.NewInt(int64(n))); return int(v.Int64()) }
	for i := 0; i < 5000; i++ {
		fields := validFields()
		for m := pick(4); m >= 0; m-- {
			j := pick(len(fields))
			switch pick(4) {
			case 0:
				fields[j].Type = types[pick(len(types))]
			case 1:
				fields[j].Key = keys[pick(len(keys))]
			case 2:
				fields[j].Value = vals[pick(len(vals))]
			case 3:
				fields = append(fields[:j], fields[j+1:]...)
				if len(fields) == 0 {
					fields = validFields()
				}
			}
		}
		s, req, _, _, ok := parseAgentRequest(agentEvent{Kind: evMessage, Fields: fields})
		if ok && (s.Validate() != nil || len(req) == 0 || len(fields) != len(agentRequestFields)) {
			t.Fatalf("accepted a malformed message: %+v", fields)
		}
	}
}

// decodeReply rebuilds a reply from its instructions the way ae_reply does.
func decodeReply(t *testing.T, fields []xpcField) map[string]any {
	t.Helper()
	root := map[string]any{}
	type frame struct {
		obj map[string]any
		arr *[]any
	}
	stack := []frame{{obj: root}}
	set := func(k string, v any) {
		top := stack[len(stack)-1]
		if top.arr != nil {
			*top.arr = append(*top.arr, v)
		} else {
			top.obj[k] = v
		}
	}
	for _, f := range fields {
		switch f.Type {
		case 'S':
			set(f.Key, f.Value)
		case 'U':
			n, _ := strconv.ParseUint(f.Value, 10, 64)
			set(f.Key, n)
		case 'I':
			n, _ := strconv.ParseInt(f.Value, 10, 64)
			set(f.Key, n)
		case 'B':
			set(f.Key, f.Value == "1")
		case '{':
			m := map[string]any{}
			set(f.Key, m)
			stack = append(stack, frame{obj: m})
		case '[':
			a := &[]any{}
			top := stack[len(stack)-1]
			if top.arr != nil {
				t.Fatal("nested arrays are not used")
			}
			top.obj[f.Key] = a
			stack = append(stack, frame{arr: a})
		case '}':
			if len(stack) == 1 {
				t.Fatal("unbalanced reply")
			}
			stack = stack[:len(stack)-1]
		default:
			t.Fatalf("unknown instruction %q", f.Type)
		}
	}
	if len(stack) != 1 {
		t.Fatal("unbalanced reply")
	}
	return root
}

func respOf(r map[string]any) map[string]any { m, _ := r["response"].(map[string]any); return m }

// fakeConn is the service side of the long-lived connection.
type fakeConn struct {
	mu      sync.Mutex
	events  chan agentEvent
	replies map[int][]xpcField
	hellos  int
	outcome string
	closed  bool
	done    chan int
}

func newFakeConn() *fakeConn {
	return &fakeConn{events: make(chan agentEvent, 64), replies: map[int][]xpcField{}, outcome: OutcomeRegistered, done: make(chan int, 64)}
}

func (f *fakeConn) Hello(time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hellos++
	return f.outcome, nil
}
func (f *fakeConn) Next(timeout time.Duration) agentEvent {
	select {
	case ev := <-f.events:
		return ev
	case <-time.After(min(timeout, 20*time.Millisecond)):
		return agentEvent{Kind: evTimeout}
	}
}
func (f *fakeConn) Reply(msg any, fields []xpcField) {
	f.mu.Lock()
	id := msg.(int)
	if _, dup := f.replies[id]; dup {
		panic("replied twice")
	}
	f.replies[id] = fields
	f.mu.Unlock()
	f.done <- id
}
func (f *fakeConn) Close() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

func (f *fakeConn) send(id int, fields []xpcField) {
	f.events <- agentEvent{Kind: evMessage, Fields: fields, Msg: id}
}

func (f *fakeConn) wait(t *testing.T, id int) map[string]any {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		f.mu.Lock()
		r, ok := f.replies[id]
		f.mu.Unlock()
		if ok {
			out := decodeReply(t, r)
			for k := range out {
				if k != "v" && k != "route_id" && k != "response" {
					t.Fatalf("reply has extra key %q", k)
				}
			}
			if out["v"] != XPCVersion {
				t.Fatalf("reply version %v", out["v"])
			}
			return out
		}
		select {
		case <-f.done:
		case <-deadline:
			t.Fatalf("no reply to %d", id)
		}
	}
}

func pinnedProvider() *XPCProvider {
	return &XPCProvider{Service: "dev.georgele.envbank.test.fake", TeamID: "NC56VXK48K", Identifier: ServiceIdentifier, cdhash: strings.Repeat("ab", 20)}
}

type dialLog struct {
	mu   sync.Mutex
	n    int
	reqs []string
}

func (d *dialLog) count() int { d.mu.Lock(); defer d.mu.Unlock(); return d.n }
func (d *dialLog) requirements() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.reqs...)
}

func startChannel(t *testing.T, h AgentHandler, max int, conns ...*fakeConn) *dialLog {
	t.Helper()
	log := &dialLog{}
	old := agentDial
	agentDial = func(_ string, req string) (agentConn, error) {
		log.mu.Lock()
		log.n++
		n := log.n
		log.reqs = append(log.reqs, req)
		log.mu.Unlock()
		if n > len(conns) {
			return nil, errors.New(CodeUnavailable)
		}
		return conns[n-1], nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ch := &AgentChannel{Provider: pinnedProvider(), Handler: h, MaxInFlight: max}
	go func() { _ = ch.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; agentDial = old })
	return log
}

type handlerFunc func(ctx context.Context, s authz.Session, req []byte) []byte

func (h handlerFunc) HandleAgent(ctx context.Context, s authz.Session, req []byte) []byte {
	return h(ctx, s, req)
}

func TestAgentChannelRepliesAndRefusesMalformed(t *testing.T) {
	var calls atomic.Int32
	h := handlerFunc(func(ctx context.Context, s authz.Session, req []byte) []byte {
		calls.Add(1)
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > agentRequestTimeout {
			t.Error("request context has no deadline within the host's budget")
		}
		return []byte(`{"v":1,"ok":true,"state":"` + s.AgentKind + `","names":["A","B"],"grants":[{"secrets":[],"scope":"setup"}]}`)
	})
	conn := newFakeConn()
	startChannel(t, h, 4, conn)
	conn.send(1, validFields())
	r := conn.wait(t, 1)
	resp := respOf(r)
	if r["route_id"] != uint64(42) || resp["ok"] != true || resp["state"] != "claude" || resp["v"] != int64(1) {
		t.Fatalf("reply %+v", r)
	}
	if names, _ := resp["names"].(*[]any); names == nil || len(*names) != 2 {
		t.Fatalf("names %+v", resp["names"])
	}
	conn.send(2, with(validFields(), add(xpcField{'S', "value", "x"})))
	r = conn.wait(t, 2)
	if respOf(r)["code"] != agentbroker.CodeInvalidRequest || respOf(r)["ok"] != false || r["route_id"] != uint64(42) {
		t.Fatalf("malformed reply %+v", r)
	}
	conn.send(3, with(validFields(), drop("route_id")))
	if r := conn.wait(t, 3); respOf(r)["code"] != agentbroker.CodeInvalidRequest || r["route_id"] != nil {
		t.Fatalf("no-route reply %+v", r)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler called %d times", calls.Load())
	}
}

func TestAgentChannelBoundsConcurrencyAndReregisters(t *testing.T) {
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	h := handlerFunc(func(ctx context.Context, _ authz.Session, _ []byte) []byte {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		inFlight.Add(-1)
		return []byte(`{"v":1,"ok":true}`)
	})
	conn := newFakeConn()
	second := newFakeConn()
	log := startChannel(t, h, 2, conn, second)
	for i := 1; i <= 2; i++ {
		conn.send(i, validFields())
	}
	time.Sleep(100 * time.Millisecond)
	conn.send(3, validFields())
	if r := conn.wait(t, 3); respOf(r)["code"] != agentbroker.CodeBusy {
		t.Fatalf("over the bound: %+v", r)
	}
	close(release)
	for i := 1; i <= 2; i++ {
		if r := conn.wait(t, i); respOf(r)["ok"] != true {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if peak.Load() > 2 {
		t.Fatalf("peak in flight %d", peak.Load())
	}
	// Service restart: register again on the same connection.
	conn.events <- agentEvent{Kind: evInterrupted}
	time.Sleep(100 * time.Millisecond)
	conn.mu.Lock()
	hellos := conn.hellos
	conn.mu.Unlock()
	if hellos != 2 {
		t.Fatalf("hellos %d", hellos)
	}
	// Connection invalid: dial again with the pinned requirement.
	conn.events <- agentEvent{Kind: evInvalid}
	deadline := time.Now().Add(5 * time.Second)
	for log.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	second.send(9, validFields())
	if r := second.wait(t, 9); respOf(r)["ok"] != true {
		t.Fatalf("after redial: %+v", r)
	}
	for _, req := range log.requirements() {
		if !strings.Contains(req, `cdhash H"`+strings.Repeat("ab", 20)+`"`) {
			t.Fatalf("channel dialled without the pinned cdhash: %s", req)
		}
	}
}

func TestAgentChannelRequiresPairingAndRegistration(t *testing.T) {
	ch := &AgentChannel{Provider: &XPCProvider{Service: "x", TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}, Handler: handlerFunc(nil)}
	if err := ch.Run(context.Background()); err == nil {
		t.Fatal("unpinned provider served agent requests")
	}
	conn := newFakeConn()
	conn.outcome = "declined"
	var called atomic.Int32
	log := startChannel(t, handlerFunc(func(context.Context, authz.Session, []byte) []byte { called.Add(1); return nil }), 2, conn)
	time.Sleep(200 * time.Millisecond)
	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()
	if !closed || log.count() < 1 || called.Load() != 0 {
		t.Fatal("unregistered connection kept or served")
	}
}

// End to end through the channel with the real policy and broker: replies
// are value-free (random sentinels), and ungranted requests never prompt.
func TestAgentChannelRepliesAreValueFree(t *testing.T) {
	value := "sk_sentinel_" + randomToken(t)
	typed := "typed_sentinel_" + randomToken(t)
	own := &testOwner{secret: []byte(typed)}
	b, err := agentbroker.New(agentbroker.Options{Vault: &testVault{values: map[string]string{"API_KEY": value}}, Prompter: own, Approver: own, Runner: agentbroker.ExecRunner{}, Path: "/usr/bin:/bin", BaseEnv: []string{"PATH=/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	gate := authz.NewGate(b, own, nil)
	conn := newFakeConn()
	startChannel(t, gate, 4, conn)
	request := func(id int, req string) map[string]any {
		conn.send(id, with(validFields(), replace("request", xpcField{'D', "request", req})))
		r := conn.wait(t, id)
		raw, _ := json.Marshal(r)
		for _, leak := range []string{value, typed, base64.StdEncoding.EncodeToString([]byte(value))} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("value escaped in reply: %s", raw)
			}
		}
		return respOf(r)
	}
	if r := request(1, `{"op":"names"}`); r["code"] != agentbroker.CodeNotAuthorized || own.approvals() != 0 {
		t.Fatalf("ungranted: %+v", r)
	}
	if r := request(2, `{"op":"grant_request","secrets":["API_KEY"],"scope":"run","duration_s":3600}`); r["state"] != "granted" {
		t.Fatalf("grant: %+v", r)
	}
	if !strings.Contains(own.lastReason(), "Deploy preview") {
		t.Fatalf("reason: %s", own.lastReason())
	}
	st := request(3, `{"op":"grant_status"}`)
	grants, _ := st["grants"].(*[]any)
	if st["ok"] != true || grants == nil || len(*grants) != 1 {
		t.Fatalf("status: %+v", st)
	}
	g0 := (*grants)[0].(map[string]any)
	if secrets, _ := g0["secrets"].(*[]any); secrets == nil || (*secrets)[0] != "API_KEY" || g0["scope"] != "run" || g0["expires_at"] == nil {
		t.Fatalf("grant shape: %+v", g0)
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	tool := filepath.Join(dir, "leak.sh")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho \"$API_KEY\"\nprintf %s \"$API_KEY\" | base64 >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	leak, _ := json.Marshal(map[string]any{"op": "run", "secrets": []string{"API_KEY"}, "argv": []string{tool}, "dir": dir})
	if r := request(4, string(leak)); !strings.Contains(r["stdout"].(string), "[REDACTED:API_KEY]") {
		t.Fatalf("run: %+v", r)
	}
	for i, req := range []string{`{"op":"run","secrets":["API_KEY"],"argv":["/usr/bin/printenv","API_KEY"],"dir":"/"}`, `{"op":"names"}`,
		`{"op":"request","name":"API_KEY","reason":"x"}`, `{"op":"grant_revoke"}`, `{"op":"names"}`} {
		request(10+i, req)
	}
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type testVault struct {
	mu     sync.Mutex
	values map[string]string
}

func (v *testVault) Names(context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for k := range v.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
func (v *testVault) Values(_ context.Context, names []string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	for _, n := range names {
		val, ok := v.values[n]
		if !ok {
			return nil, agentbroker.ErrMissing
		}
		out[n] = val
	}
	return out, nil
}
func (v *testVault) Exists(_ context.Context, n string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.values[n]
	return ok, nil
}
func (v *testVault) Store(_ context.Context, n, val string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[n] = val
	return nil
}

type testOwner struct {
	mu      sync.Mutex
	reasons []string
	secret  []byte
}

func (o *testOwner) ShowRun(agentbroker.Command, string, bool) {}
func (o *testOwner) ShowPlan(string, []string)                 {}
func (o *testOwner) Notify(string)                             {}
func (o *testOwner) ReadSecret(context.Context, agentbroker.Ingest) ([]byte, bool, error) {
	return append([]byte(nil), o.secret...), true, nil
}
func (o *testOwner) Available() bool { return true }
func (o *testOwner) Approve(_ context.Context, reason string) approval.Outcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reasons = append(o.reasons, reason)
	return approval.Approved
}
func (o *testOwner) approvals() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.reasons) }
func (o *testOwner) lastReason() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.reasons) == 0 {
		return ""
	}
	return o.reasons[len(o.reasons)-1]
}

func TestAgentReplyShape(t *testing.T) {
	f := agentReply(7, true, []byte(`{"v":1,"ok":false,"code":"X","exit_code":null}`))
	r := decodeReply(t, f)
	if len(r) != 3 || r["route_id"] != uint64(7) || respOf(r)["code"] != "X" || len(respOf(r)) != 3 {
		t.Fatalf("reply %+v", r)
	}
	if r := decodeReply(t, agentReply(0, false, []byte("not json"))); len(r) != 2 || respOf(r)["code"] != agentbroker.CodeInvalidRequest {
		t.Fatalf("bad response JSON: %+v", r)
	}
}
