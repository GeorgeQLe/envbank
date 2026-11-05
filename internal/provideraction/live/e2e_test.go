package live

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/authz"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// owner is the broker terminal and the Touch ID approver: it approves
// everything and records every text shown.
type owner struct {
	mu      sync.Mutex
	reasons []string // Touch ID texts
	shown   []string // broker terminal plan lines and notices
}

func (o *owner) ShowRun(agentbroker.Command, string, bool) {}
func (o *owner) ShowPlan(title string, lines []string) {
	o.mu.Lock()
	o.shown = append(o.shown, title)
	o.shown = append(o.shown, lines...)
	o.mu.Unlock()
}
func (o *owner) Notify(line string) { o.mu.Lock(); o.shown = append(o.shown, line); o.mu.Unlock() }
func (o *owner) ReadSecret(context.Context, agentbroker.Ingest) ([]byte, bool, error) {
	return nil, false, nil
}
func (o *owner) Available() bool { return true }
func (o *owner) Approve(_ context.Context, reason string) approval.Outcome {
	o.mu.Lock()
	o.reasons = append(o.reasons, reason)
	o.mu.Unlock()
	return approval.Approved
}
func (o *owner) approvals() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.reasons...)
}
func (o *owner) texts() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Join(o.reasons, "\n") + "\n" + strings.Join(o.shown, "\n")
}

type harness struct {
	t     *testing.T
	fx    *fakes
	own   *owner
	vault *provideractiontest.Vault
	gate  *authz.Gate
	s     authz.Session
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, fx: newFakes(t), own: &owner{}}
	// Seed the CONTROL_ records as the owner would (request flow), plus an
	// owner-entered secret no provider action created.
	values := map[string]string{"CLERK_SECRET_KEY": provideractiontest.Sentinel("sk_clerk_")}
	for k, v := range h.fx.keys {
		values[k] = v
	}
	h.fx.sec.mu.Lock()
	h.fx.sec.all = append(h.fx.sec.all, values["CLERK_SECRET_KEY"])
	h.fx.sec.mu.Unlock()
	h.vault = provideractiontest.NewVault(nil, values)
	b, err := agentbroker.New(agentbroker.Options{Vault: h.vault, Prompter: h.own, Approver: h.own, Runner: agentbroker.ExecRunner{},
		Path: "/usr/bin:/bin", BaseEnv: []string{"PATH=/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	h.gate = authz.NewGate(b, h.own, nil)
	h.gate.Provider = provideraction.New(provideraction.Options{Vault: h.vault, Factory: h.fx.factory(cfg),
		Clock: &provideractiontest.Clock{T: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}})
	t.Cleanup(h.gate.Close)
	t.Cleanup(b.Close)
	h.s = authz.Session{ID: "e2e" + strings.Repeat("x", 24), Workspace: "ws-main", AgentKind: "claude", Label: "E2E provider actions"}
	return h
}

func (h *harness) secrets() []string {
	return h.fx.allSecrets()
}

// call sends one agent request through the gate exactly as the host
// channel does and scans the raw reply for every secret in play.
func (h *harness) call(req map[string]any) agentbroker.Response {
	h.t.Helper()
	req["v"] = 1
	raw, err := json.Marshal(req)
	if err != nil {
		h.t.Fatal(err)
	}
	out := h.gate.HandleAgent(context.Background(), h.s, raw)
	if leak := provideractiontest.Leak(out, h.secrets()...); leak != "" {
		h.t.Fatalf("reply leaked a secret value: %s", out)
	}
	var r agentbroker.Response
	if err := json.Unmarshal(out, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

type result struct {
	resp agentbroker.Response
	res  provideraction.Result
}

// act runs one provider action to completion and returns its final status.
func (h *harness) act(action string, params map[string]any) result {
	h.t.Helper()
	before := len(h.own.approvals())
	r := h.call(map[string]any{"op": "provider_action", "action": action, "params": params, "reason": "e2e"})
	if !r.OK || r.OperationID == "" {
		h.t.Fatalf("%s refused: %+v", action, r)
	}
	if n := len(h.own.approvals()); n != before+1 {
		h.t.Fatalf("%s: %d approvals, want exactly one", action, n-before)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st := h.call(map[string]any{"op": "provider_status", "operation_id": r.OperationID})
		if st.State == provideraction.StateSucceeded || st.State == provideraction.StateFailed {
			var res provideraction.Result
			if len(st.Result) > 0 {
				if err := json.Unmarshal(st.Result, &res); err != nil {
					h.t.Fatal(err)
				}
			}
			return result{resp: st, res: res}
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("%s did not finish", action)
	return result{}
}

func (h *harness) mustSucceed(action string, params map[string]any) provideraction.Result {
	h.t.Helper()
	r := h.act(action, params)
	if r.resp.State != provideraction.StateSucceeded {
		h.t.Fatalf("%s: %+v\nevents: %v", action, r.resp, h.fx.ev.list())
	}
	return r.res
}

// refusedWithoutPrompt checks a provider_action is refused with code and
// nobody was asked.
func (h *harness) refusedWithoutPrompt(code, action string, params map[string]any) {
	h.t.Helper()
	before, events := len(h.own.approvals()), len(h.fx.ev.list())
	r := h.call(map[string]any{"op": "provider_action", "action": action, "params": params})
	if r.OK || r.Code != code {
		h.t.Fatalf("%s: got %+v, want %s", action, r, code)
	}
	if len(h.own.approvals()) != before || len(h.fx.ev.list()) != events {
		h.t.Fatalf("%s: refusal %s prompted or reached a provider", action, code)
	}
}

func (h *harness) grant(actions ...string) {
	h.t.Helper()
	r := h.call(map[string]any{"op": "grant_request", "scope": "provider", "actions": actions, "duration_s": 3600})
	if !r.OK {
		h.t.Fatalf("grant: %+v", r)
	}
}

func (h *harness) binding(record string) provideraction.Binding {
	b, ok := h.vault.Binding(record)
	if !ok {
		h.t.Fatalf("no binding for %s", record)
	}
	return b
}

func value(v *provideractiontest.Vault, name string) string { s, _ := v.Value(name); return s }

// TestSyntheticEndToEnd drives every v1 action through authz.Gate against
// stateful Neon, Vercel and Stripe fakes using the real adapters.
func TestSyntheticEndToEnd(t *testing.T) {
	h := newHarness(t, Config{NeonOrgID: "org-e2e-test"})
	team := h.fx.team
	preview := func(project string) map[string]any {
		return map[string]any{"team_id": team, "project_id": project, "target": "preview"}
	}

	// Ungranted: refused before any prompt or provider call.
	h.refusedWithoutPrompt(agentbroker.CodeNotAuthorized, provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-app"})
	h.grant(provideraction.Actions()...)
	if a := h.own.approvals(); len(a) != 1 {
		t.Fatalf("grant approvals: %v", a)
	}

	// Vercel project and Neon project.
	vp := h.mustSucceed(provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-app", "git_repo": "georgeqle/e2e-app"})
	project := vp.ProjectID
	np := h.mustSucceed(provideraction.ActionNeonProjectCreate, map[string]any{"name": "envbank-e2e-db",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}})
	if h.fx.ev.index("neon.create_project "+np.ProjectID+" org=org-e2e-test") < 0 {
		t.Fatalf("project not created in the configured org: %v", h.fx.ev.list())
	}
	if np.ActiveRole != "app_a" || np.Role != "neondb_owner" || len(np.PreparedRoles) != 2 {
		t.Fatalf("neon create result %+v", np)
	}
	appA := value(h.vault, "DATABASE_URL")
	if !strings.Contains(appA, "app_a:"+h.fx.neon.password(np.ProjectID, "app_a")+"@") || !strings.Contains(appA, "-pooler.") || !h.fx.neon.validURI(appA) {
		t.Fatal("DATABASE_URL does not hold app_a's pooled URI")
	}
	if strings.Contains(value(h.vault, "DATABASE_URL")+value(h.vault, "DATABASE_URL_UNPOOLED"), h.fx.neon.password(np.ProjectID, "neondb_owner")) {
		t.Fatal("an owner credential was stored")
	}

	// Unbound and not-yet-allowed pushes are refused before any prompt.
	push := func(vars map[string]string) map[string]any {
		p := preview(project)
		p["variables"] = vars
		return p
	}
	dbVars := map[string]string{"DATABASE_URL": "DATABASE_URL", "DATABASE_URL_UNPOOLED": "DATABASE_URL_UNPOOLED"}
	h.refusedWithoutPrompt(provideraction.CodeDestinationNotAllowed, provideraction.ActionVercelEnvPush, push(dbVars))
	h.refusedWithoutPrompt(provideraction.CodeRecordNotBound, provideraction.ActionVercelEnvPush, push(map[string]string{"CLERK_SECRET_KEY": "CLERK_SECRET_KEY"}))

	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"}, "team_id": team, "project_id": project})
	if a := h.own.approvals(); !strings.Contains(a[len(a)-1], "Project created by this broker") {
		t.Fatalf("binding.allow text: %s", a[len(a)-1])
	}
	h.refusedWithoutPrompt(provideraction.CodeRecordNotBound, provideraction.ActionVercelEnvPush, push(map[string]string{"CLERK_SECRET_KEY": "CLERK_SECRET_KEY"}))

	h.mustSucceed(provideraction.ActionVercelEnvPush, push(dbVars))
	if h.fx.vercel.envValue(project, "DATABASE_URL") != appA {
		t.Fatal("Vercel did not receive DATABASE_URL")
	}
	rp := preview(project)
	rp["health_path"] = "/api/health"
	rd := h.mustSucceed(provideraction.ActionVercelRedeploy, rp)
	if rd.Health == nil || rd.Health.Checks < provideraction.MinHealthChecks || rd.Health.WindowSeconds < 30 {
		t.Fatalf("redeploy health %+v", rd.Health)
	}

	// Rotation: app_b becomes active; app_a is invalidated only after the
	// new deployment, built with app_b's URI, passed its health checks.
	oldA := h.fx.neon.password(np.ProjectID, "app_a")
	rot := h.mustSucceed(provideraction.ActionNeonRotate, map[string]any{"project_id": np.ProjectID, "branch_id": np.BranchID,
		"roles": []string{"app_a", "app_b"}, "owner_role": np.Role, "database": np.Database,
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"},
		"vercel":  preview(project), "health_path": "/api/health"})
	if rot.ActiveRole != "app_b" || rot.InvalidatedRole != "app_a" {
		t.Fatalf("rotate result %+v", rot)
	}
	appB := value(h.vault, "DATABASE_URL")
	if !strings.Contains(appB, "app_b:"+h.fx.neon.password(np.ProjectID, "app_b")+"@") || !h.fx.neon.validURI(appB) || !h.fx.neon.validURI(value(h.vault, "DATABASE_URL_UNPOOLED")) {
		t.Fatal("rotated records do not hold app_b's current URIs")
	}
	if h.fx.vercel.envValue(project, "DATABASE_URL") != appB || h.fx.vercel.envValue(project, "DATABASE_URL_UNPOOLED") != value(h.vault, "DATABASE_URL_UNPOOLED") {
		t.Fatal("Vercel did not receive the new Neon URIs")
	}
	if h.fx.neon.password(np.ProjectID, "app_a") == oldA || h.fx.neon.validURI(appA) {
		t.Fatal("the old role's password is still valid")
	}
	resetB, deploy := h.fx.ev.last("neon.reset app_b"), h.fx.ev.index("vercel.deploy "+rot.DeploymentID)
	health, invalidate := h.fx.ev.last("health "+rot.DeploymentID+" 200"), h.fx.ev.last("neon.reset app_a")
	if !(resetB < h.fx.ev.last("vercel.env DATABASE_URL") && h.fx.ev.last("vercel.env DATABASE_URL") < deploy && deploy < health && health < invalidate) {
		t.Fatalf("rotation order wrong: %v", h.fx.ev.list())
	}
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		b := h.binding(rec)
		if _, rev := h.vault.Value(rec); b.RecordRevision != rev || b.Revoked || len(b.AllowedDestinations) != 1 || b.Resource.ProjectID != np.ProjectID {
			t.Fatalf("binding %s after rotation: %+v (record rev %d)", rec, b, rev)
		}
	}

	// Stripe: create, allow, rotate.
	wc := h.mustSucceed(provideraction.ActionStripeWebhookCreate, map[string]any{"url": "https://envbank-e2e-app.vercel.app/api/stripe",
		"events": []string{"checkout.session.completed", "invoice.paid"}, "record": "STRIPE_WEBHOOK_SECRET"})
	first := wc.EndpointID
	if ep := h.fx.stripe.endpoint(first); ep == nil || ep.secret != value(h.vault, "STRIPE_WEBHOOK_SECRET") || len(ep.events) != 2 {
		t.Fatal("webhook secret not stored from the create response")
	}
	h.refusedWithoutPrompt(provideraction.CodeDestinationNotAllowed, provideraction.ActionStripeWebhookRotate, map[string]any{"endpoint_id": first,
		"record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS", "vercel": preview(project), "health_path": "/api/health"})
	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"STRIPE_WEBHOOK_SECRET"}, "team_id": team, "project_id": project})
	oldSecret := value(h.vault, "STRIPE_WEBHOOK_SECRET")
	sr := h.mustSucceed(provideraction.ActionStripeWebhookRotate, map[string]any{"endpoint_id": first,
		"record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS", "vercel": preview(project), "health_path": "/api/health"})
	second := sr.EndpointID
	if second == first || sr.DeletedEndpointID != first || !h.fx.stripe.endpoint(first).deleted {
		t.Fatalf("stripe rotate result %+v", sr)
	}
	newSecret := value(h.vault, "STRIPE_WEBHOOK_SECRET")
	if newSecret != h.fx.stripe.endpoint(second).secret || value(h.vault, "STRIPE_WEBHOOK_SECRET_PREVIOUS") != oldSecret ||
		h.fx.vercel.envValue(project, "STRIPE_WEBHOOK_SECRET") != newSecret || h.fx.vercel.envValue(project, "STRIPE_WEBHOOK_SECRET_PREVIOUS") != oldSecret {
		t.Fatal("webhook secrets not moved and pushed as planned")
	}
	if h.fx.ev.last("health "+sr.DeploymentID+" 200") > h.fx.ev.index("stripe.delete "+first) {
		t.Fatalf("old endpoint deleted before health passed: %v", h.fx.ev.list())
	}
	if b := h.binding("STRIPE_WEBHOOK_SECRET"); b.Resource.EndpointID != second || b.Resource.Lineage != first {
		t.Fatalf("webhook binding after rotation %+v", b)
	}
	if b := h.binding("STRIPE_WEBHOOK_SECRET_PREVIOUS"); b.Kind != provideraction.KindStripeWebhookSecretPrevious || b.Resource.Lineage != first || len(b.AllowedDestinations) != 1 {
		t.Fatalf("previous binding %+v", b)
	}

	// Cleanup: deletes revoke the bindings; the records stay.
	sd := h.mustSucceed(provideraction.ActionStripeWebhookDelete, map[string]any{"endpoint_id": second})
	nd := h.mustSucceed(provideraction.ActionNeonProjectDelete, map[string]any{"project_id": np.ProjectID})
	h.mustSucceed(provideraction.ActionVercelProjectDelete, map[string]any{"team_id": team, "project_id": project})
	if len(sd.RevokedBindings) != 2 || len(nd.RevokedBindings) != 2 {
		t.Fatalf("revoked %v and %v", sd.RevokedBindings, nd.RevokedBindings)
	}
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED", "STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET_PREVIOUS"} {
		if !h.binding(rec).Revoked || value(h.vault, rec) == "" {
			t.Fatalf("%s: binding not revoked or record removed", rec)
		}
	}
	if h.fx.ev.index("stripe.delete "+second) < 0 || h.fx.ev.index("neon.delete_project "+np.ProjectID) < 0 || h.fx.ev.index("vercel.delete_project "+project) < 0 {
		t.Fatalf("provider deletes missing: %v", h.fx.ev.list())
	}
	h.refusedWithoutPrompt(provideraction.CodeRecordNotBound, provideraction.ActionVercelEnvPush, push(dbVars))

	// Nothing the owner saw, or any reply, carried a value; the health
	// checks never carried credentials or cookies.
	if leak := provideractiontest.Leak([]byte(h.own.texts()), h.secrets()...); leak != "" {
		t.Fatalf("owner-facing text leaked a value")
	}
	for _, r := range h.fx.vercel.healthReqs {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("x-vercel-protection-bypass") != "" || !strings.HasSuffix(r.URL.Host, ".vercel.app") {
			t.Fatalf("health request carried credentials or left vercel.app: %v %v", r.URL, r.Header)
		}
	}
	if n := len(h.own.approvals()); n != 13 { // grant + 12 actions
		t.Fatalf("%d approvals", n)
	}
}

// Vercel deployment protection (401) fails the health step with
// HEALTH_PROTECTED and is never bypassed: a rotation stops before it
// invalidates the old role.
func TestDeploymentProtectionStopsRotationBeforeInvalidation(t *testing.T) {
	h := newHarness(t, Config{})
	team := h.fx.team
	h.grant(provideraction.Actions()...)
	project := h.mustSucceed(provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-protected"}).ProjectID
	np := h.mustSucceed(provideraction.ActionNeonProjectCreate, map[string]any{"name": "envbank-e2e-db",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}})
	if h.fx.ev.index("neon.create_project "+np.ProjectID+" org=") < 0 {
		t.Fatal("org_id sent without --neon-org-id")
	}
	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"}, "team_id": team, "project_id": project})
	h.fx.vercel.mu.Lock()
	h.fx.vercel.protect = true
	h.fx.vercel.mu.Unlock()
	appA := value(h.vault, "DATABASE_URL")
	mark := len(h.fx.ev.list())
	r := h.act(provideraction.ActionNeonRotate, map[string]any{"project_id": np.ProjectID, "branch_id": np.BranchID,
		"roles": []string{"app_a", "app_b"}, "owner_role": np.Role, "database": np.Database,
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"},
		"vercel":  map[string]any{"team_id": team, "project_id": project, "target": "preview"}, "health_path": "/api/health"})
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepHealth || r.resp.Code != provideraction.CodeHealthProtected {
		t.Fatalf("status %+v", r.resp)
	}
	for _, e := range h.fx.ev.list()[mark:] {
		if e == "neon.reset app_a" {
			t.Fatal("the old role was invalidated although health did not pass")
		}
	}
	if !h.fx.neon.validURI(appA) || h.fx.ev.last("neon.reset app_b") < mark {
		t.Fatal("expected the new role reset and the old URI still valid")
	}
	for _, r := range h.fx.vercel.healthReqs {
		if r.Header.Get("Authorization") != "" || r.Header.Get("x-vercel-protection-bypass") != "" {
			t.Fatal("protection bypass attempted")
		}
	}
}
