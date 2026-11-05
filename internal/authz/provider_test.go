package authz

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

type providerFixture struct {
	g      *Gate
	own    *owner
	clk    *clock
	log    *provideractiontest.Log
	vault  *provideractiontest.Vault
	fake   *provideractiontest.Providers
	values []string // every secret value in play
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	f := &providerFixture{log: &provideractiontest.Log{}}
	controls := map[string]string{
		provideraction.ControlNeon:   provideractiontest.Sentinel("napi_"),
		provideraction.ControlVercel: provideractiontest.Sentinel("vcp_"),
		provideraction.ControlStripe: provideractiontest.Sentinel("sk_test_"),
		"STRIPE_WEBHOOK_SECRET":      provideractiontest.Sentinel("whsec_"),
	}
	brokerValues := map[string]string{"API_KEY": sentinel(t)}
	for k, v := range controls {
		brokerValues[k] = v
		f.values = append(f.values, v)
	}
	f.values = append(f.values, brokerValues["API_KEY"])
	f.g, f.own, f.clk = fixture(t, brokerValues)
	f.vault = provideractiontest.NewVault(f.log, controls)
	f.fake = provideractiontest.NewProviders(f.log)
	f.g.Provider = provideraction.New(provideraction.Options{Vault: f.vault, Factory: f.fake, Clock: &provideractiontest.Clock{T: time.Now()}})
	t.Cleanup(f.g.Close)
	return f
}

func (f *providerFixture) secrets() []string {
	return append(append(append([]string{}, f.values...), f.fake.Secret), f.fake.IssuedSecrets()...)
}

func (f *providerFixture) call(t *testing.T, s Session, req map[string]any) (agentbroker.Response, []byte) {
	t.Helper()
	req["v"] = 1
	out := f.g.HandleAgent(context.Background(), s, raw(t, req))
	if leak := provideractiontest.Leak(out, f.secrets()...); leak != "" {
		t.Fatalf("reply leaked a value: %s", out)
	}
	var r agentbroker.Response
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	return r, out
}

func rotateReq(target string) map[string]any {
	v := map[string]any{"team_id": "team_abc123", "project_id": "prj_abc123", "target": target}
	if target == "production" {
		v["production"] = true
	}
	return map[string]any{"op": "provider_action", "action": "neon.rotate", "reason": "monthly rotation", "params": map[string]any{
		"project_id": "calm-sky-123456", "branch_id": "br-main-1", "roles": []string{"app_a", "app_b"}, "database": "appdb",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}, "vercel": v, "health_path": "/api/health",
	}}
}

func (f *providerFixture) waitDone(t *testing.T, s Session, id string) agentbroker.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := f.call(t, s, map[string]any{"op": "provider_status", "operation_id": id})
		if r.State == provideraction.StateSucceeded || r.State == provideraction.StateFailed {
			return r
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("operation did not finish")
	return agentbroker.Response{}
}

func TestProviderActionNeedsAGrantBeforeAnyPrompt(t *testing.T) {
	f := newProviderFixture(t)
	s := session("provider")
	r, _ := f.call(t, s, rotateReq("preview"))
	if r.OK || r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("ungranted: %+v", r)
	}
	// A provider grant for other actions, and grants of other scopes, do not cover it.
	if _, err := f.g.Grants.AddProvider(s, []string{"stripe.webhook.create"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, f.g, s, ScopeRun, []string{"API_KEY"}, time.Hour)
	if r, _ := f.call(t, s, rotateReq("preview")); r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("other action granted: %+v", r)
	}
	// Another session's provider grant does not cover this one.
	if _, err := f.g.Grants.AddProvider(session("other"), []string{"neon.rotate"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.call(t, s, rotateReq("preview")); r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("other session's grant: %+v", r)
	}
	if shown, approvals := f.own.prompts(); shown != 0 || approvals != 0 || len(f.log.Calls()) != 0 {
		t.Fatalf("prompted (%d shown, %d approvals) or acted (%v) for an ungranted action", shown, approvals, f.log.Calls())
	}
}

func TestProviderActionDeclinedTouchIDHasNoSideEffects(t *testing.T) {
	for _, outcome := range []approval.Outcome{approval.Denied, approval.Unavailable} {
		f := newProviderFixture(t)
		f.own.outcome = outcome
		s := session("decline")
		if _, err := f.g.Grants.AddProvider(s, []string{"neon.rotate"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		r, _ := f.call(t, s, rotateReq("preview"))
		if r.OK || r.OperationID != "" || (r.Code != agentbroker.CodeDenied && r.Code != agentbroker.CodeApprovalUnavailable) {
			t.Fatalf("declined: %+v", r)
		}
		if _, approvals := f.own.prompts(); approvals != 1 {
			t.Fatalf("want exactly one Touch ID prompt, got %d", approvals)
		}
		if len(f.log.Calls()) != 0 {
			t.Fatalf("side effects after a declined approval: %v", f.log.Calls())
		}
	}
}

func TestProviderActionApprovalTextAndHappyPath(t *testing.T) {
	f := newProviderFixture(t)
	s := session("approve")
	s.Label = "Rotate “prod” now"
	if _, err := f.g.Grants.AddProvider(s, []string{"neon.rotate"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r, _ := f.call(t, s, rotateReq("production"))
	if !r.OK || r.State != provideraction.StateStarted || r.Action != "neon.rotate" || !provideraction.ValidOperationID(r.OperationID) {
		t.Fatalf("start: %+v", r)
	}
	f.own.mu.Lock()
	reason := f.own.reasons[0]
	f.own.mu.Unlock()
	for _, want := range []string{"perform a provider action: ROTATE Neon role app_b to active in project calm-sky-123456", "DATABASE_URL, DATABASE_URL_UNPOOLED", "Vercel prj_abc123 (team_abc123) PRODUCTION", "then invalidate role app_a", ", for " + s.Ident()} {
		if !strings.Contains(reason, want) {
			t.Errorf("approval text lacks %q: %s", want, reason)
		}
	}
	if !strings.HasSuffix(reason, "; session label: Rotate prod now") || strings.Index(reason, "session label") < strings.Index(reason, "invalidate") {
		t.Errorf("label must come last, unquoted: %s", reason)
	}
	if strings.Contains(reason, "monthly rotation") || strings.Contains(reason, "always") {
		t.Errorf("agent reason or always in the Touch ID text: %s", reason)
	}
	st := f.waitDone(t, s, r.OperationID)
	if !st.OK || st.State != provideraction.StateSucceeded || st.Step != provideraction.StepNeonInvalidateOld || len(st.Result) == 0 {
		t.Fatalf("status: %+v", st)
	}
	var res provideraction.Result
	if err := json.Unmarshal(st.Result, &res); err != nil || res.ActiveRole != "app_b" || res.Records["DATABASE_URL"] < 1 {
		t.Fatalf("result %s", st.Result)
	}
	// Every action needs its own Touch ID: a second identical call prompts again.
	f.call(t, s, rotateReq("production"))
	if _, approvals := f.own.prompts(); approvals != 2 {
		t.Fatalf("want a Touch ID per action, got %d", approvals)
	}
}

func TestProviderStatusIsOwnedBySession(t *testing.T) {
	f := newProviderFixture(t)
	s := session("owner")
	if _, err := f.g.Grants.AddProvider(s, []string{"neon.rotate"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r, _ := f.call(t, s, rotateReq("preview"))
	f.waitDone(t, s, r.OperationID)
	for _, other := range []Session{session("intruder"), func() Session { x := s; x.Workspace = "ws-other"; return x }(), func() Session { x := s; x.AgentKind = "codex"; return x }()} {
		if st, _ := f.call(t, other, map[string]any{"op": "provider_status", "operation_id": r.OperationID}); st.OK || st.Code != provideraction.CodeUnknownOperation || st.State != "" {
			t.Fatalf("another session read the status: %+v", st)
		}
	}
	if st, _ := f.call(t, s, map[string]any{"op": "provider_status", "operation_id": strings.Repeat("a", 32)}); st.Code != provideraction.CodeUnknownOperation {
		t.Fatalf("unknown id: %+v", st)
	}
	for _, bad := range []map[string]any{
		{"op": "provider_status", "operation_id": "short"},
		{"op": "provider_status", "operation_id": r.OperationID, "action": "neon.rotate"},
		{"op": "provider_status"},
	} {
		if st, _ := f.call(t, s, bad); st.Code != agentbroker.CodeInvalidRequest {
			t.Fatalf("%v: %+v", bad, st)
		}
	}
}

func TestProviderActionRefusalsBeforePrompt(t *testing.T) {
	f := newProviderFixture(t)
	s := session("refuse")
	if _, err := f.g.Grants.AddProvider(s, provideraction.Actions(), time.Hour); err != nil {
		t.Fatal(err)
	}
	bad := rotateReq("preview")
	bad["params"].(map[string]any)["roles"] = []string{"app_a"}
	unknownField := rotateReq("preview")
	unknownField["params"].(map[string]any)["extra"] = true
	withSecrets := rotateReq("preview")
	withSecrets["secrets"] = []string{"API_KEY"}
	for _, req := range []map[string]any{bad, unknownField, withSecrets,
		{"op": "provider_action", "action": "neon.rotate"},
		{"op": "provider_action", "action": "aws.iam.create", "params": map[string]any{}},
	} {
		r, _ := f.call(t, s, req)
		if r.OK || (r.Code != agentbroker.CodeInvalidRequest && r.Code != agentbroker.CodeNotAuthorized) {
			t.Fatalf("%v: %+v", req, r)
		}
	}
	// Provider fields on other ops are refused.
	if r, _ := f.call(t, s, map[string]any{"op": "names", "action": "neon.rotate"}); r.Code != agentbroker.CodeInvalidRequest {
		t.Fatalf("names with provider fields: %+v", r)
	}
	if shown, approvals := f.own.prompts(); shown != 0 || approvals != 0 {
		t.Fatal("prompted for an invalid provider action")
	}
	// With no factory: PROVIDER_UNAVAILABLE, but only after the grant check.
	f.g.Provider = provideraction.New(provideraction.Options{Vault: f.vault})
	if r, _ := f.call(t, s, rotateReq("preview")); r.Code != provideraction.CodeUnavailable {
		t.Fatalf("no factory: %+v", r)
	}
	f.g.Provider = nil
	if r, _ := f.call(t, s, rotateReq("preview")); r.Code != provideraction.CodeUnavailable {
		t.Fatalf("no service: %+v", r)
	}
	if r, _ := f.call(t, session("nogrant"), rotateReq("preview")); r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("no grant, no factory: %+v", r)
	}
}

func TestProviderGrantRequest(t *testing.T) {
	f := newProviderFixture(t)
	s := session("granting")
	for _, bad := range []map[string]any{
		{"op": "grant_request", "scope": "provider", "duration_s": 3600},                                                    // no actions
		{"op": "grant_request", "scope": "provider", "actions": []string{"neon.nope"}, "duration_s": 3600},                  // unknown
		{"op": "grant_request", "scope": "provider", "actions": []string{"neon.rotate", "neon.rotate"}, "duration_s": 3600}, // duplicate
		{"op": "grant_request", "scope": "provider", "actions": []string{"neon.rotate"}, "secrets": []string{"API_KEY"}, "duration_s": 3600},
		{"op": "grant_request", "scope": "run", "actions": []string{"neon.rotate"}, "secrets": []string{"API_KEY"}, "duration_s": 3600},
		{"op": "grant_request", "scope": "provider", "actions": []string{"neon.rotate"}, "action": "neon.rotate", "duration_s": 3600},
	} {
		if r, _ := f.call(t, s, bad); r.OK || r.Code != agentbroker.CodeInvalidRequest {
			t.Fatalf("%v: %+v", bad, r)
		}
	}
	if _, approvals := f.own.prompts(); approvals != 0 {
		t.Fatal("prompted for an invalid grant request")
	}
	r, _ := f.call(t, s, map[string]any{"op": "grant_request", "scope": "provider", "actions": []string{"stripe.webhook.rotate", "neon.rotate"}, "duration_s": 3600})
	if !r.OK || r.State != agentbroker.StateGranted || len(r.Grants) != 1 || r.Grants[0].Scope != "provider" || strings.Join(r.Grants[0].Actions, ",") != "neon.rotate,stripe.webhook.rotate" || len(r.Grants[0].Secrets) != 0 {
		t.Fatalf("grant: %+v", r)
	}
	f.own.mu.Lock()
	reason := f.own.reasons[0]
	f.own.mu.Unlock()
	if !strings.HasPrefix(reason, "grant permission to request provider actions neon.rotate, stripe.webhook.rotate (each needs Touch ID) for 1 h") {
		t.Fatalf("grant reason: %s", reason)
	}
	// A provider grant covers no secrets.
	if r, _ := f.call(t, s, map[string]any{"op": "names"}); r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("provider grant listed names: %+v", r)
	}
}

// CONTROL_* records: never listed, never injected, never grantable for
// names or run; owner entry through request still seeds them.
func TestControlRecordsAreReserved(t *testing.T) {
	f := newProviderFixture(t)
	f.clk.add(time.Minute)
	s := session("control")
	for _, scope := range []string{"names", "run"} {
		r, _ := f.call(t, s, map[string]any{"op": "grant_request", "scope": scope, "secrets": []string{"CONTROL_VERCEL_TOKEN"}, "duration_s": 3600})
		if r.OK || r.Code != agentbroker.CodeReserved {
			t.Fatalf("%s grant of a control record: %+v", scope, r)
		}
		r, _ = f.call(t, s, map[string]any{"op": "grant_request", "scope": scope, "secrets": []string{"control_vercel_token"}, "duration_s": 3600})
		if r.Code != agentbroker.CodeReserved {
			t.Fatalf("%s grant, lower case: %+v", scope, r)
		}
	}
	if _, approvals := f.own.prompts(); approvals != 0 {
		t.Fatal("prompted for a reserved grant")
	}
	// Even a grant forced into the store (not reachable by agents) does not
	// list or inject a control record.
	mustAdd(t, f.g, s, ScopeNames, []string{"CONTROL_VERCEL_TOKEN", "API_KEY"}, time.Hour)
	if r, _ := f.call(t, s, map[string]any{"op": "names"}); !r.OK || strings.Join(r.Names, ",") != "API_KEY" {
		t.Fatalf("names listed a control record: %+v", r)
	}
	mustAdd(t, f.g, s, ScopeRun, []string{"CONTROL_VERCEL_TOKEN"}, time.Hour)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	if r, _ := f.call(t, s, map[string]any{"op": "run", "secrets": []string{"CONTROL_VERCEL_TOKEN"}, "argv": []string{"/bin/echo", "x"}, "dir": dir}); r.OK || r.Code != agentbroker.CodeReserved {
		t.Fatalf("run injected a control record: %+v", r)
	}
	// Legacy socket (no grants at all): names hides them, run refuses them,
	// provider ops are refused.
	if r := f.g.Broker.Handle(context.Background(), agentbroker.Request{V: 1, Op: "names"}); !r.OK || strings.Contains(strings.Join(r.Names, ","), "CONTROL_") {
		t.Fatalf("legacy names: %+v", r)
	}
	if r := f.g.Broker.Handle(context.Background(), agentbroker.Request{V: 1, Op: "run", Secrets: []string{"CONTROL_STRIPE_KEY"}, Argv: []string{"/bin/echo"}, Dir: dir}); r.Code != agentbroker.CodeReserved {
		t.Fatalf("legacy run: %+v", r)
	}
	for _, op := range []string{"provider_action", "provider_status"} {
		if r := f.g.Broker.Handle(context.Background(), agentbroker.Request{V: 1, Op: op}); r.OK || r.Code != agentbroker.CodeNotAuthorized {
			t.Fatalf("legacy %s: %+v", op, r)
		}
	}
	// Seeding through request (owner-typed entry) still works.
	f.clk.add(time.Hour)
	r, _ := f.call(t, s, map[string]any{"op": "grant_request", "scope": "request", "secrets": []string{"CONTROL_NEON_API_KEY"}, "duration_s": 3600})
	if !r.OK {
		t.Fatalf("request grant for a control record: %+v", r)
	}
	r, _ = f.call(t, s, map[string]any{"op": "request", "name": "CONTROL_NEON_API_KEY", "reason": "seed the Neon control key"})
	if !r.OK || r.State != agentbroker.StateStored {
		t.Fatalf("seeding a control record: %+v", r)
	}
	if r := f.g.Broker.Handle(context.Background(), agentbroker.Request{V: 1, Op: "request", Name: "CONTROL_NEW_KEY", Reason: "seed"}); !r.OK || r.State != agentbroker.StateStored {
		t.Fatalf("legacy seeding: %+v", r)
	}
}

func TestRevokeAndCloseStopProviderOperations(t *testing.T) {
	f := newProviderFixture(t)
	f.fake.Block = make(chan struct{})
	s := session("revoke")
	if _, err := f.g.Grants.AddProvider(s, []string{"neon.rotate"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r, _ := f.call(t, s, rotateReq("preview"))
	if !r.OK {
		t.Fatalf("start: %+v", r)
	}
	f.call(t, s, map[string]any{"op": "grant_revoke"})
	st := f.waitDone(t, s, r.OperationID)
	if st.State != provideraction.StateFailed || st.Code != agentbroker.CodeNotAuthorized || f.log.Index("neon.invalidate app_a") >= 0 {
		t.Fatalf("revoked: %+v", st)
	}
	if _, err := f.g.Grants.AddProvider(s, []string{"neon.rotate"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r, _ = f.call(t, s, rotateReq("preview"))
	f.g.Close()
	st, _ = f.call(t, s, map[string]any{"op": "provider_status", "operation_id": r.OperationID})
	if st.State != provideraction.StateFailed || st.Code != agentbroker.CodeBrokerClosed {
		t.Fatalf("closed: %+v", st)
	}
}
