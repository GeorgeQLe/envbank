package authz

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

func pushReq(project string, vars map[string]string) map[string]any {
	return map[string]any{"op": "provider_action", "action": "vercel.env.push", "params": map[string]any{
		"team_id": "team_abc123", "project_id": project, "target": "preview", "variables": vars}}
}

func allowReq(project string, records ...string) map[string]any {
	return map[string]any{"op": "provider_action", "action": "binding.allow", "params": map[string]any{
		"records": records, "team_id": "team_abc123", "project_id": project}}
}

// Pushes of unbound records, or to destinations not allowed, are refused
// before any Touch ID prompt.
func TestProviderPushBindingRefusalsBeforePrompt(t *testing.T) {
	f := newProviderFixture(t)
	s := session("push")
	if _, err := f.g.Grants.AddProvider(s, []string{"vercel.env.push"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.call(t, s, pushReq("prj_abc123", map[string]string{"STRIPE_WEBHOOK_SECRET": "STRIPE_WEBHOOK_SECRET"})); r.Code != provideraction.CodeRecordNotBound {
		t.Fatalf("unbound: %+v", r)
	}
	if r, _ := f.call(t, s, pushReq("prj_agentowned", map[string]string{"DATABASE_URL": "DATABASE_URL"})); r.Code != provideraction.CodeDestinationNotAllowed {
		t.Fatalf("not allowed: %+v", r)
	}
	if shown, approvals := f.own.prompts(); shown != 0 || approvals != 0 || len(f.log.Calls()) != 0 {
		t.Fatalf("prompted (%d, %d) or acted (%v)", shown, approvals, f.log.Calls())
	}
}

func TestBindingAllowNeedsItsOwnTouchID(t *testing.T) {
	f := newProviderFixture(t)
	s := session("allow")
	// No grant for binding.allow: a push grant does not cover it.
	if _, err := f.g.Grants.AddProvider(s, []string{"vercel.env.push"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.call(t, s, allowReq("prj_new1", "DATABASE_URL")); r.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("ungranted: %+v", r)
	}
	if _, err := f.g.Grants.AddProvider(s, []string{"binding.allow", "vercel.env.push"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Declined: nothing changes.
	f.own.outcome = approval.Denied
	if r, _ := f.call(t, s, allowReq("prj_new1", "DATABASE_URL", "DATABASE_URL_UNPOOLED")); r.OK || r.Code != agentbroker.CodeDenied {
		t.Fatalf("declined: %+v", r)
	}
	if b, _ := f.vault.Binding("DATABASE_URL"); len(b.AllowedDestinations) != 1 {
		t.Fatalf("declined allow changed the binding: %+v", b)
	}
	f.own.mu.Lock()
	reason := f.own.reasons[0]
	f.own.mu.Unlock()
	for _, want := range []string{"perform a provider action: ALLOW records DATABASE_URL, DATABASE_URL_UNPOOLED to be deployed to Vercel project prj_new1 (team_abc123)", "PRODUCTION", "can read their values", ", for " + s.Ident()} {
		if !strings.Contains(reason, want) {
			t.Errorf("approval text lacks %q: %s", want, reason)
		}
	}
	// Approved: the destination is added, and the push then runs (with its own prompt).
	f.own.outcome = approval.Approved
	r, _ := f.call(t, s, allowReq("prj_new1", "DATABASE_URL"))
	if st := f.waitDone(t, s, r.OperationID); st.State != provideraction.StateSucceeded {
		t.Fatalf("allow: %+v", st)
	}
	r, _ = f.call(t, s, pushReq("prj_new1", map[string]string{"DATABASE_URL": "DATABASE_URL"}))
	if st := f.waitDone(t, s, r.OperationID); st.State != provideraction.StateSucceeded {
		t.Fatalf("push: %+v", st)
	}
	if _, approvals := f.own.prompts(); approvals != 3 {
		t.Fatalf("want 3 Touch ID prompts, got %d", approvals)
	}
	// A plan too long to show in full is refused, never clipped or prompted.
	var many []string
	for i := 0; i < 16; i++ {
		rec := "LONG_RECORD_NAME_" + strings.Repeat("X", 40) + string(rune('A'+i))
		many = append(many, rec)
		f.vault.Set(rec, provideractiontest.Sentinel("x_"))
		f.vault.Bind(provideraction.Binding{Record: rec, Provider: provideraction.ProviderNeon, Kind: provideraction.KindNeonPooled,
			Resource: provideraction.BindingResource{ProjectID: "calm-sky-123456", BranchID: "br-main-1"}})
	}
	if r, _ := f.call(t, s, allowReq("prj_new1", many...)); r.Code != provideraction.CodePlanTooLong {
		t.Fatalf("over-long: %+v", r)
	}
	if _, approvals := f.own.prompts(); approvals != 3 {
		t.Fatal("prompted for an over-long plan")
	}
}

// Bindings are vault objects only the provider service writes: names, run
// and request reach records, never bindings. An owner-entered value under a
// bound name is not bound (the binding pins the broker's revision), so it
// cannot be pushed.
func TestBindingsAreNotReachableByAgentOps(t *testing.T) {
	log := &provideractiontest.Log{}
	shared := provideractiontest.NewVault(log, map[string]string{
		provideraction.ControlVercel: provideractiontest.Sentinel("vcp_"),
		"DATABASE_URL":               provideractiontest.Sentinel("postgresql://app_a:"),
		"DATABASE_URL_UNPOOLED":      provideractiontest.Sentinel("postgresql://app_a:"),
	})
	bindNeonRecords(shared)
	o := &owner{outcome: approval.Approved, secret: []byte(sentinel(t))}
	b, err := agentbroker.New(agentbroker.Options{Vault: shared, Prompter: o, Approver: o, Runner: agentbroker.ExecRunner{}, Path: "/usr/bin:/bin", BaseEnv: []string{"PATH=/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	g := NewGate(b, o, c.now)
	g.Provider = provideraction.New(provideraction.Options{Vault: shared, Factory: provideractiontest.NewProviders(log), Clock: &provideractiontest.Clock{T: time.Now()}})
	t.Cleanup(g.Close)
	s := session("reserve")
	call := func(req map[string]any) agentbroker.Response {
		req["v"] = 1
		out := g.HandleAgent(context.Background(), s, raw(t, req))
		var r agentbroker.Response
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	mustAdd(t, g, s, ScopeNames, []string{"DATABASE_URL"}, time.Hour)
	if r := call(map[string]any{"op": "names"}); !r.OK || strings.Join(r.Names, ",") != "DATABASE_URL" {
		t.Fatalf("names: %+v", r)
	}
	before, _ := shared.Binding("DATABASE_URL")
	// The owner types a new value into the bound name (request).
	c.add(time.Minute)
	mustAdd(t, g, s, ScopeRequest, []string{"DATABASE_URL"}, time.Hour)
	if r := call(map[string]any{"op": "request", "name": "DATABASE_URL", "reason": "replace"}); !r.OK || r.State != agentbroker.StateStored {
		t.Fatalf("request: %+v", r)
	}
	after, _ := shared.Binding("DATABASE_URL")
	if after.RecordRevision != before.RecordRevision || len(after.AllowedDestinations) != 1 {
		t.Fatalf("request changed the binding: %+v", after)
	}
	if _, err := g.Grants.AddProvider(s, []string{"vercel.env.push"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	prompts := func() int { _, n := o.prompts(); return n }
	n := prompts()
	if r := call(pushReq("prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL"})); r.Code != provideraction.CodeRecordNotBound {
		t.Fatalf("push of an owner-entered value under a bound name: %+v", r)
	}
	if prompts() != n {
		t.Fatal("prompted for an unbound push")
	}
	// Request on a fresh name creates a record, never a binding.
	mustAdd(t, g, s, ScopeRequest, []string{"NEW_THING"}, time.Hour)
	call(map[string]any{"op": "request", "name": "NEW_THING", "reason": "x"})
	if _, ok := shared.Binding("NEW_THING"); ok {
		t.Fatal("request created a binding")
	}
}
