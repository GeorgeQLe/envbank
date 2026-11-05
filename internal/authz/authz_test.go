package authz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
)

func sentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sk_sentinel_" + base64.RawURLEncoding.EncodeToString(b)
}

type vault struct {
	mu     sync.Mutex
	values map[string]string
}

func (v *vault) Names(context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var n []string
	for k := range v.values {
		n = append(n, k)
	}
	sort.Strings(n)
	return n, nil
}
func (v *vault) Values(_ context.Context, names []string) (map[string]string, error) {
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
func (v *vault) Exists(_ context.Context, name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.values[name]
	return ok, nil
}
func (v *vault) Store(_ context.Context, name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[name] = value
	return nil
}

// owner records everything shown to the owner and plays the Touch ID role.
type owner struct {
	mu          sync.Mutex
	outcome     approval.Outcome
	unavailable bool
	reasons     []string
	shown       int
	secret      []byte
	during      func()
}

func (o *owner) ShowRun(agentbroker.Command, string, bool) { o.mu.Lock(); o.shown++; o.mu.Unlock() }
func (o *owner) ShowPlan(string, []string)                 { o.mu.Lock(); o.shown++; o.mu.Unlock() }
func (o *owner) Notify(string)                             {}
func (o *owner) ReadSecret(context.Context, agentbroker.Ingest) ([]byte, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.shown++
	return append([]byte(nil), o.secret...), true, nil
}
func (o *owner) Available() bool { return !o.unavailable }
func (o *owner) Approve(_ context.Context, reason string) approval.Outcome {
	o.mu.Lock()
	o.reasons = append(o.reasons, reason)
	during := o.during
	out := o.outcome
	o.mu.Unlock()
	if during != nil {
		during()
	}
	return out
}
func (o *owner) prompts() (shown, approvals int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.shown, len(o.reasons)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func fixture(t *testing.T, values map[string]string) (*Gate, *owner, *clock) {
	t.Helper()
	o := &owner{outcome: approval.Approved, secret: []byte(sentinel(t))}
	b, err := agentbroker.New(agentbroker.Options{Vault: &vault{values: values}, Prompter: o, Approver: o, Runner: agentbroker.ExecRunner{}, Path: "/usr/bin:/bin", BaseEnv: []string{"PATH=/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	return NewGate(b, o, c.now), o, c
}

func session(id string) Session {
	return Session{ID: id + strings.Repeat("x", 24), Workspace: "ws-main", AgentKind: "claude", Label: "Deploy preview"}
}

func raw(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func noValue(t *testing.T, value string, out []byte) {
	t.Helper()
	for _, enc := range []string{value, base64.StdEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value)), hex.EncodeToString([]byte(value))} {
		if strings.Contains(string(out), enc) {
			t.Fatalf("value (or encoding) escaped: %s", out)
		}
	}
}

// The policy matrix: each operation × grant / no grant / expired / another
// session / another workspace / another agent kind / revoked / wrong scope.
// Only the matching grant reaches the broker; every other case is
// NOT_AUTHORIZED and the owner sees nothing.
func TestPolicyMatrix(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	type op struct {
		name    string
		scope   string
		secrets []string
		req     map[string]any
		// reached checks a response that came from the broker (not the policy).
		reached func(agentbroker.Response) bool
	}
	ops := []op{
		{"names", ScopeNames, []string{"API_KEY"}, map[string]any{"v": 1, "op": "names"},
			func(r agentbroker.Response) bool { return r.OK && strings.Join(r.Names, ",") == "API_KEY" }},
		{"run", ScopeRun, []string{"API_KEY"}, map[string]any{"v": 1, "op": "run", "secrets": []string{"API_KEY"}, "argv": []string{"/bin/echo", "hi"}, "dir": dir},
			func(r agentbroker.Response) bool {
				return r.OK && r.ExitCode != nil && strings.TrimSpace(r.Stdout) == "hi"
			}},
		{"request", ScopeRequest, []string{"NEW_KEY"}, map[string]any{"v": 1, "op": "request", "name": "NEW_KEY", "reason": "deploy"},
			func(r agentbroker.Response) bool { return r.OK && r.State == agentbroker.StateStored }},
		{"setup", ScopeSetup, nil, map[string]any{"v": 1, "op": "setup", "setup": map[string]any{"sync": "local_server"}},
			func(r agentbroker.Response) bool { return r.Code == agentbroker.CodeAlreadySetUp }},
		{"relay_request", ScopeRelay, nil, map[string]any{"v": 1, "op": "relay_request"},
			func(r agentbroker.Response) bool { return r.Code == agentbroker.CodeNotSupported }},
	}
	cases := []struct {
		name  string
		grant func(g *Gate, c *clock, o op, s Session)
		as    func(s Session) Session
		ok    bool
	}{
		{"granted", func(g *Gate, _ *clock, o op, s Session) { mustAdd(t, g, s, o.scope, o.secrets, time.Hour) }, nil, true},
		{"no-grant", func(*Gate, *clock, op, Session) {}, nil, false},
		{"expired", func(g *Gate, c *clock, o op, s Session) {
			mustAdd(t, g, s, o.scope, o.secrets, time.Hour)
			c.add(time.Hour)
		}, nil, false},
		{"other-session", func(g *Gate, _ *clock, o op, s Session) { mustAdd(t, g, s, o.scope, o.secrets, time.Hour) },
			func(s Session) Session { s.ID = "other" + s.ID; return s }, false},
		{"other-workspace", func(g *Gate, _ *clock, o op, s Session) { mustAdd(t, g, s, o.scope, o.secrets, time.Hour) },
			func(s Session) Session { s.Workspace = "ws-other"; return s }, false},
		{"other-agent-kind", func(g *Gate, _ *clock, o op, s Session) { mustAdd(t, g, s, o.scope, o.secrets, time.Hour) },
			func(s Session) Session { s.AgentKind = "codex"; return s }, false},
		{"revoked", func(g *Gate, _ *clock, o op, s Session) {
			mustAdd(t, g, s, o.scope, o.secrets, time.Hour)
			if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke"}`)); !r.OK || r.State != agentbroker.StateRevoked {
				t.Fatalf("revoke: %+v", r)
			}
		}, nil, false},
		{"wrong-scope", func(g *Gate, _ *clock, o op, s Session) {
			scope, secrets := ScopeSetup, []string(nil)
			if o.scope == ScopeSetup {
				scope, secrets = ScopeRun, []string{"API_KEY"}
			}
			mustAdd(t, g, s, scope, secrets, time.Hour)
		}, nil, false},
		{"other-secret", func(g *Gate, _ *clock, o op, s Session) {
			if o.secrets == nil {
				mustAdd(t, g, s, ScopeNames, []string{"OTHER"}, time.Hour) // no setup/relay grant at all
				return
			}
			mustAdd(t, g, s, o.scope, []string{"OTHER"}, time.Hour)
		}, nil, false},
	}
	for _, o := range ops {
		for _, c := range cases {
			t.Run(o.name+"/"+c.name, func(t *testing.T) {
				value := sentinel(t)
				g, own, clk := fixture(t, map[string]string{"API_KEY": value, "OTHER": sentinel(t)})
				s := session("matrix")
				c.grant(g, clk, o, s)
				caller := s
				if c.as != nil {
					caller = c.as(s)
				}
				shownBefore, approvalsBefore := own.prompts()
				out := g.HandleAgent(context.Background(), caller, raw(t, o.req))
				var r agentbroker.Response
				if err := json.Unmarshal(out, &r); err != nil {
					t.Fatal(err)
				}
				noValue(t, value, out)
				shown, approvals := own.prompts()
				if c.ok {
					if !o.reached(r) {
						t.Fatalf("granted request did not reach the broker: %s", out)
					}
					return
				}
				if o.name == "names" && c.name == "other-secret" {
					// A names grant for OTHER lists OTHER, never API_KEY.
					if !r.OK || strings.Join(r.Names, ",") != "OTHER" {
						t.Fatalf("names not filtered to the grant: %s", out)
					}
					return
				}
				if r.OK || r.Code != agentbroker.CodeNotAuthorized {
					t.Fatalf("want NOT_AUTHORIZED, got %s", out)
				}
				if shown != shownBefore || approvals != approvalsBefore {
					t.Fatal("the owner was prompted for an ungranted request")
				}
			})
		}
	}
}

func mustAdd(t *testing.T, g *Gate, s Session, scope string, secrets []string, d time.Duration) Grant {
	t.Helper()
	gr, err := g.Grants.Add(s, scope, secrets, d)
	if err != nil {
		t.Fatal(err)
	}
	return gr
}

func TestNamesAreFilteredToGrantedSecrets(t *testing.T) {
	g, _, _ := fixture(t, map[string]string{"A_KEY": sentinel(t), "B_KEY": sentinel(t), "C_KEY": sentinel(t)})
	s := session("names")
	mustAdd(t, g, s, ScopeNames, []string{"A_KEY", "MISSING"}, time.Hour)
	mustAdd(t, g, s, ScopeRun, []string{"C_KEY"}, time.Hour)
	r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"names"}`))
	if !r.OK || strings.Join(r.Names, ",") != "A_KEY,C_KEY" {
		t.Fatalf("names: %+v", r)
	}
	mustAdd(t, g, session("other"), ScopeNames, []string{"B_KEY"}, time.Hour)
	if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"names"}`)); strings.Contains(strings.Join(r.Names, ","), "B_KEY") {
		t.Fatal("another session's grant widened this one")
	}
}

func TestGrantRequestNeedsTouchIDAndValidatesFirst(t *testing.T) {
	g, own, clk := fixture(t, map[string]string{"API_KEY": sentinel(t)})
	s := session("grant")
	s.Label = "Fix “billing” bug"
	req := func(m map[string]any) agentbroker.Response {
		m["v"], m["op"] = 1, "grant_request"
		return g.Handle(context.Background(), s, raw(t, m))
	}
	// Invalid requests are refused before any prompt.
	for _, bad := range []map[string]any{
		{"secrets": []string{"API_KEY"}, "scope": "run"},                                           // no duration
		{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 12*3600 + 1},                // over 12 h
		{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 30},                         // under a minute
		{"secrets": []string{"API_KEY"}, "scope": "admin", "duration_s": 600},                      // unknown scope
		{"secrets": []string{}, "scope": "run", "duration_s": 600},                                 // nothing to grant
		{"secrets": []string{"bad-name"}, "scope": "run", "duration_s": 600},                       // invalid name
		{"secrets": []string{"API_KEY", "API_KEY"}, "scope": "run", "duration_s": 600},             // duplicate
		{"secrets": []string{"API_KEY"}, "scope": "setup", "duration_s": 600},                      // setup takes no secrets
		{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 600, "argv": []string{"x"}}, // stray field
		{"secrets": longNames(16), "scope": "run", "duration_s": 600},                              // cannot be shown in full
	} {
		if r := req(bad); r.OK || r.Code != agentbroker.CodeInvalidRequest {
			t.Fatalf("accepted %v: %+v", bad, r)
		}
	}
	if shown, approvals := own.prompts(); shown != 0 || approvals != 0 {
		t.Fatal("an invalid grant request reached the owner")
	}
	// Denied: no grant.
	own.outcome = approval.Denied
	if r := req(map[string]any{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 7200}); r.OK || r.Code != agentbroker.CodeDenied {
		t.Fatalf("denied: %+v", r)
	}
	// A declined session cannot prompt again at once.
	before := len(own.reasons)
	if r := req(map[string]any{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 7200}); r.Code != agentbroker.CodeBusy || len(own.reasons) != before {
		t.Fatalf("cooldown: %+v", r)
	}
	clk.add(MaxDenialBackoff)
	// Unavailable (no biometry, or the policy cannot be evaluated): refused.
	own.outcome = approval.Unavailable
	if r := req(map[string]any{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 7200}); r.Code != agentbroker.CodeApprovalUnavailable {
		t.Fatalf("unavailable: %+v", r)
	}
	clk.add(MaxDenialBackoff)
	own.outcome, own.unavailable = approval.Approved, true
	if r := req(map[string]any{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 7200}); r.Code != agentbroker.CodeApprovalUnavailable {
		t.Fatalf("canEvaluate false: %+v", r)
	}
	if len(g.Grants.Active(s)) != 0 {
		t.Fatal("a grant exists without Touch ID")
	}
	own.unavailable = false
	clk.add(MaxDenialBackoff)
	r := req(map[string]any{"secrets": []string{"API_KEY"}, "scope": "run", "duration_s": 5400, "reason": "deploy"})
	if !r.OK || r.State != agentbroker.StateGranted || len(r.Grants) != 1 || r.Grants[0].Scope != "run" || r.Grants[0].ExpiresAt != "2026-11-04T14:15:00Z" {
		t.Fatalf("granted: %+v", r)
	}
	last := own.reasons[len(own.reasons)-1]
	want := "grant run access to API_KEY for 1 h 30 min (until 14:15) to claude agent session " + s.Fingerprint() + " in workspace ws-main; session label: Fix billing bug"
	if last != want || len(s.Fingerprint()) != 8 {
		t.Fatalf("Touch ID reason\n got %s\nwant %s", last, want)
	}
	st := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_status"}`))
	if !st.OK || len(st.Grants) != 1 || strings.Join(st.Grants[0].Secrets, ",") != "API_KEY" {
		t.Fatalf("status: %+v", st)
	}
	clk.add(90 * time.Minute)
	if st := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_status"}`)); len(st.Grants) != 0 {
		t.Fatal("expired grant still listed")
	}
	// Revocation needs no Touch ID, and only reduces access.
	own.outcome = approval.Denied
	before = len(own.reasons)
	if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke"}`)); !r.OK || len(own.reasons) != before {
		t.Fatal("revoke prompted")
	}
	if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke","secrets":["X"]}`)); r.OK {
		t.Fatal("revoke with stray fields accepted")
	}
}

func longNames(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("A_VERY_LONG_SECRET_NAME_FOR_TESTING_%02d_%s", i, strings.Repeat("X", 20)))
	}
	return out
}

func TestAlwaysApprovalsEndWithTheGrantAndRevokeStopsInFlight(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	g, own, _ := fixture(t, map[string]string{"API_KEY": sentinel(t)})
	s := session("always")
	run := func(always bool) agentbroker.Response {
		return g.Handle(context.Background(), s, raw(t, map[string]any{"v": 1, "op": "run", "secrets": []string{"API_KEY"}, "argv": []string{"/bin/echo", "ok"}, "dir": dir, "always": always}))
	}
	mustAdd(t, g, s, ScopeRun, []string{"API_KEY"}, time.Hour)
	if r := run(true); !r.OK {
		t.Fatalf("first: %+v", r)
	}
	_, a1 := own.prompts()
	if r := run(false); !r.OK {
		t.Fatalf("second: %+v", r)
	}
	if _, a2 := own.prompts(); a2 != a1 {
		t.Fatal("always approval prompted again within the grant")
	}
	g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke"}`))
	mustAdd(t, g, s, ScopeRun, []string{"API_KEY"}, time.Hour)
	if r := run(false); !r.OK {
		t.Fatalf("after re-grant: %+v", r)
	}
	if _, a3 := own.prompts(); a3 != a1+1 {
		t.Fatal("an always approval survived its grant")
	}
	// Revoked while the owner is deciding: nothing runs.
	marker := filepath.Join(dir, "ran")
	own.during = func() { g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke"}`)) }
	r := g.Handle(context.Background(), s, raw(t, map[string]any{"v": 1, "op": "run", "secrets": []string{"API_KEY"}, "argv": []string{"/usr/bin/touch", marker}, "dir": dir}))
	if r.OK || r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("revoked in flight: %+v", r)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("command ran after revocation")
	}
}

func TestRepliesAreValueFree(t *testing.T) {
	value, other := sentinel(t), sentinel(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	tool := filepath.Join(dir, "leak.sh")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho \"$API_KEY\"\nprintf %s \"$API_KEY\" | base64\necho \"$API_KEY\" >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	g, own, _ := fixture(t, map[string]string{"API_KEY": value, "OTHER": other})
	own.secret = []byte(sentinel(t))
	s := session("leak")
	mustAdd(t, g, s, ScopeRun, []string{"API_KEY"}, time.Hour)
	mustAdd(t, g, s, ScopeRequest, []string{"API_KEY", "NEW_ONE"}, time.Hour)
	for _, req := range []map[string]any{
		{"v": 1, "op": "run", "secrets": []string{"API_KEY"}, "argv": []string{tool}, "dir": dir},
		{"v": 1, "op": "names"},
		{"v": 1, "op": "grant_status"},
		{"v": 1, "op": "request", "name": "NEW_ONE", "reason": value},
		{"v": 1, "op": "request", "name": "API_KEY", "reason": "rotate"},
		{"v": 1, "op": "run", "secrets": []string{"OTHER"}, "argv": []string{tool}, "dir": dir},
		{"v": 1, "op": "get", "name": "API_KEY"},
	} {
		out := g.HandleAgent(context.Background(), s, raw(t, req))
		noValue(t, value, out)
		noValue(t, other, out)
		noValue(t, string(own.secret), out)
	}
}

func TestParseRequestAndSessionValidation(t *testing.T) {
	for _, bad := range []string{``, `null`, `[]`, `{"v":1}`, `{"v":2,"op":"names"}`, `{"op":""}`, `{"v":1,"op":"names","value":"x"}`, `{"v":1,"op":"names"} {}`, "{\"v\":1,\"op\":\"names\xff\"}", `{"v":"1","op":"names"}`} {
		if _, err := ParseRequest([]byte(bad)); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
	if r, err := ParseRequest([]byte(`{"op":"names"}`)); err != nil || r.V != 1 {
		t.Fatal("host request without v refused")
	}
	if _, err := ParseRequest([]byte(`{"v":1,"op":"names","pad":"` + strings.Repeat("x", agentbroker.Limits.RequestBytes) + `"}`)); err == nil {
		t.Fatal("oversized request parsed")
	}
	good := session("valid")
	if good.Validate() != nil {
		t.Fatal("valid session refused")
	}
	for name, mut := range map[string]func(*Session){
		"short id":      func(s *Session) { s.ID = "abc" },
		"id charset":    func(s *Session) { s.ID = strings.Repeat("a", 30) + "!" },
		"empty ws":      func(s *Session) { s.Workspace = "" },
		"ws space":      func(s *Session) { s.Workspace = "a b" },
		"kind upper":    func(s *Session) { s.AgentKind = "Claude" },
		"label long":    func(s *Session) { s.Label = strings.Repeat("x", 81) },
		"label empty":   func(s *Session) { s.Label = "  " },
		"label bidi":    func(s *Session) { s.Label = "abc\u202edef" },
		"label control": func(s *Session) { s.Label = "abc\x1b[2J" },
		"label newline": func(s *Session) { s.Label = "abc\ndef" },
		"label utf8":    func(s *Session) { s.Label = "abc\xff" },
	} {
		s := good
		mut(&s)
		if s.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
		g, own, _ := fixture(t, map[string]string{})
		if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_request","scope":"setup","duration_s":600}`)); r.OK || r.Code != agentbroker.CodeInvalidRequest {
			t.Fatalf("%s: %+v", name, r)
		}
		if _, a := own.prompts(); a != 0 {
			t.Fatalf("%s: prompted", name)
		}
	}
}

func TestStoreCloseEndsEverything(t *testing.T) {
	g, _, _ := fixture(t, map[string]string{})
	s := session("close")
	gr := mustAdd(t, g, s, ScopeSetup, nil, time.Hour)
	g.Close()
	if g.Grants.Valid(gr.id, s) || len(g.Grants.Active(s)) != 0 {
		t.Fatal("grant survived close")
	}
	if _, err := g.Grants.Add(s, ScopeSetup, nil, time.Hour); err == nil {
		t.Fatal("grant added after close")
	}
	for i := 0; i < MaxGrantsPerSession; i++ {
		_, _ = NewStore(nil, nil).Add(s, ScopeSetup, nil, time.Hour)
	}
	st := NewStore(nil, nil)
	for i := 0; i < MaxGrantsPerSession; i++ {
		if _, err := st.Add(s, ScopeSetup, nil, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Add(s, ScopeSetup, nil, time.Hour); !errors.Is(err, ErrFull) {
		t.Fatal("per-session cap not enforced")
	}
}

// The agent-influenced label cannot pose as the grant's terms: those come
// first and whole, the label last without quote characters.
func TestGrantReasonPutsAuthoritativeTermsFirstAndLabelLast(t *testing.T) {
	g, own, _ := fixture(t, map[string]string{"API_KEY": sentinel(t)})
	s := session("spoof")
	s.Label = "” for 1 min only “names” of TEST_KEY ‘ok’ «x» `y`"
	if s.Validate() != nil {
		t.Fatal("label refused")
	}
	r := g.Handle(context.Background(), s, raw(t, map[string]any{"v": 1, "op": "grant_request", "scope": "run", "secrets": []string{"API_KEY"}, "duration_s": 43200}))
	if !r.OK {
		t.Fatalf("grant: %+v", r)
	}
	reason := own.reasons[0]
	auth := "grant run access to API_KEY for 12 h (until 00:00) to claude agent session " + s.Fingerprint() + " in workspace ws-main"
	if !strings.HasPrefix(reason, auth+"; session label: ") {
		t.Fatalf("reason does not start with the authoritative terms: %s", reason)
	}
	if strings.ContainsAny(reason, "“”‘’«»\"'`") {
		t.Fatalf("quote characters survived: %s", reason)
	}
	if !strings.HasSuffix(reason, "for 1 min only names of TEST_KEY ok x y") {
		t.Fatalf("label not last: %s", reason)
	}
	// A fingerprint is a pure function of the session id.
	other := s
	other.ID = "other" + s.ID
	if other.Fingerprint() == s.Fingerprint() || session("spoof").Fingerprint() != s.Fingerprint() {
		t.Fatal("fingerprint not derived from the session id")
	}
	// The authoritative part never shrinks to fit: with a full-length label it
	// still appears whole, and when it alone is too long the request is refused.
	s.Label = strings.Repeat("L", 80)
	names := longNames(6)
	reasonText, ok := grantReason(s, ScopeRun, names, time.Hour, time.Now())
	if !ok || !strings.Contains(reasonText, strings.Join(names, ", ")) || len(reasonText) > approval.MaxReasonBytes {
		t.Fatalf("authoritative part clipped: %v %s", ok, reasonText)
	}
	if _, ok := grantReason(s, ScopeRun, longNames(16), time.Hour, time.Now()); ok {
		t.Fatal("authoritative part that does not fit accepted")
	}
}

func grantReq(t *testing.T, g *Gate, s Session) agentbroker.Response {
	t.Helper()
	return g.Handle(context.Background(), s, raw(t, map[string]any{"v": 1, "op": "grant_request", "scope": "names", "secrets": []string{"API_KEY"}, "duration_s": 600}))
}

// Grant prompts are limited globally: one open at a time, at least 10 s
// apart, and an exponential backoff after consecutive declines from any
// sessions, which new sessions do not reset.
func TestGrantPromptsAreRateLimitedGlobally(t *testing.T) {
	g, own, clk := fixture(t, map[string]string{"API_KEY": sentinel(t)})
	// Spacing: two sessions back to back.
	if r := grantReq(t, g, session("s1")); !r.OK {
		t.Fatalf("first: %+v", r)
	}
	if r := grantReq(t, g, session("s2")); r.Code != agentbroker.CodeBusy {
		t.Fatalf("second within 10 s: %+v", r)
	}
	clk.add(GrantPromptSpacing)
	if r := grantReq(t, g, session("s2")); !r.OK {
		t.Fatalf("after spacing: %+v", r)
	}
	// One open prompt: while the owner decides, every other session is busy.
	clk.add(GrantPromptSpacing)
	var during agentbroker.Response
	own.during = func() { clk.add(time.Hour); during = grantReq(t, g, session("s3")) }
	if r := grantReq(t, g, session("s4")); !r.OK || during.Code != agentbroker.CodeBusy {
		t.Fatalf("concurrent prompt: %+v / %+v", r, during)
	}
	own.during = nil
	// Consecutive declines back off globally: 30 s, 1 min, 2 min, …
	own.outcome = approval.Denied
	clk.add(GrantPromptSpacing)
	for i, wait := range []time.Duration{DeniedCooldown, 2 * DeniedCooldown, 4 * DeniedCooldown, 8 * DeniedCooldown} {
		fresh := session(fmt.Sprintf("churn%d", i))
		before := len(own.reasons)
		if r := grantReq(t, g, fresh); r.Code != agentbroker.CodeDenied || len(own.reasons) != before+1 {
			t.Fatalf("decline %d: %+v", i, r)
		}
		clk.add(wait - time.Second)
		if r := grantReq(t, g, session(fmt.Sprintf("new%d", i))); r.Code != agentbroker.CodeBusy || len(own.reasons) != before+1 {
			t.Fatalf("a new session bypassed backoff %d: %+v", i, r)
		}
		clk.add(time.Second)
	}
	// The cap holds, and an approval resets the backoff.
	for i := 0; i < 20; i++ {
		g.releasePrompt(session("cap"), true, false)
	}
	g.mu.Lock()
	until := g.backoffUntil.Sub(clk.now())
	g.mu.Unlock()
	if until != MaxDenialBackoff {
		t.Fatalf("backoff %v, want the %v cap", until, MaxDenialBackoff)
	}
	clk.add(MaxDenialBackoff)
	own.outcome = approval.Approved
	if r := grantReq(t, g, session("after")); !r.OK {
		t.Fatalf("after backoff: %+v", r)
	}
	clk.add(GrantPromptSpacing)
	if r := grantReq(t, g, session("after2")); !r.OK {
		t.Fatalf("backoff not reset by an approval: %+v", r)
	}
}

// The per-session cooldown map is bounded without being cleared: a full map
// drops expired entries, then the oldest, and keeps the rest.
func TestCooldownMapIsCappedWithoutClearing(t *testing.T) {
	g, _, clk := fixture(t, map[string]string{})
	for i := 0; i < maxCooldowns+50; i++ {
		g.releasePrompt(session(fmt.Sprintf("c%05d", i)), true, false)
		clk.add(time.Millisecond)
	}
	g.mu.Lock()
	n := len(g.denied)
	_, newest := g.denied[session(fmt.Sprintf("c%05d", maxCooldowns+49)).key()]
	_, oldest := g.denied[session("c00000").key()]
	_, recent := g.denied[session(fmt.Sprintf("c%05d", 100)).key()]
	g.mu.Unlock()
	if n != maxCooldowns || !newest || oldest || !recent {
		t.Fatalf("len %d newest %v oldest %v recent %v", n, newest, oldest, recent)
	}
}

// Revoking a grant kills a command still running under it (its whole process
// group), and no output is returned.
func TestRevokeKillsInFlightRuns(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	tool := filepath.Join(dir, "long.sh")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nsleep 60 &\necho $! > \"$0.child\"\necho $$ > \"$0.pid\"\necho \"$API_KEY\"\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	g, _, _ := fixture(t, map[string]string{"API_KEY": sentinel(t)})
	s, other := session("kill"), session("keep")
	mustAdd(t, g, s, ScopeRun, []string{"API_KEY"}, time.Hour)
	mustAdd(t, g, other, ScopeRun, []string{"API_KEY"}, time.Hour)
	done := make(chan []byte, 1)
	go func() {
		done <- g.HandleAgent(context.Background(), s, raw(t, map[string]any{"v": 1, "op": "run", "secrets": []string{"API_KEY"}, "argv": []string{tool}, "dir": dir, "timeout_seconds": 60}))
	}()
	pids := waitPids(t, tool+".pid", tool+".child")
	// Another session's revocation leaves it running.
	g.Handle(context.Background(), other, []byte(`{"v":1,"op":"grant_revoke"}`))
	time.Sleep(100 * time.Millisecond)
	if syscall.Kill(pids[0], 0) != nil {
		t.Fatal("run killed by another session's revoke")
	}
	start := time.Now()
	if r := g.Handle(context.Background(), s, []byte(`{"v":1,"op":"grant_revoke"}`)); !r.OK {
		t.Fatalf("revoke: %+v", r)
	}
	var out []byte
	select {
	case out = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run survived revocation")
	}
	var r agentbroker.Response
	if err := json.Unmarshal(out, &r); err != nil || r.OK || r.Code != agentbroker.CodeNotAuthorized || r.Stdout != "" || time.Since(start) > 3*time.Second {
		t.Fatalf("revoked run: %s after %v", out, time.Since(start))
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, pid := range pids {
		for syscall.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				t.Fatalf("process %d outlived the revoked grant", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func waitPids(t *testing.T, files ...string) []int {
	t.Helper()
	var pids []int
	deadline := time.Now().Add(10 * time.Second)
	for _, f := range files {
		for {
			raw, err := os.ReadFile(f)
			if n, perr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && perr == nil && n > 0 {
				pids = append(pids, n)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no pid in %s", f)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return pids
}
