package provideraction_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// Tests for the security-review findings (November 5, 2026).

func neonRotate(t *testing.T, scopes ...map[string]any) json.RawMessage {
	var p map[string]any
	_ = json.Unmarshal(rotateParams(t), &p)
	list := []any{}
	for _, s := range scopes {
		list = append(list, s)
	}
	p["vercel"] = list
	return js(t, p)
}

func stripeRotate(t *testing.T, endpoint string, scopes ...map[string]any) json.RawMessage {
	var p map[string]any
	_ = json.Unmarshal(stripeRotateParams(t), &p)
	list := []any{}
	for _, s := range scopes {
		list = append(list, s)
	}
	p["vercel"], p["endpoint_id"] = list, endpoint
	return js(t, p)
}

func pushTo(t *testing.T, target string, vars map[string]string) json.RawMessage {
	p := vercelRef(target)
	p["variables"] = vars
	return js(t, p)
}

func (e *env) noCallsSince(t *testing.T, mark int, what string) {
	t.Helper()
	if calls := e.log.Calls()[mark:]; len(calls) != 0 {
		t.Fatalf("%s: side effects %v", what, calls)
	}
}

// Finding 1: a rotation must rewrite and redeploy every scope the records
// were deployed to (production last), or be refused before the prompt.
func TestRotationCoversEveryDeployedScope(t *testing.T) {
	e := newEnv(t, nil)
	db := map[string]string{"DATABASE_URL": "DATABASE_URL", "DATABASE_URL_UNPOOLED": "DATABASE_URL_UNPOOLED"}
	if st := e.run(t, pa.ActionVercelEnvPush, pushTo(t, "preview", db)); st.State != pa.StateSucceeded {
		t.Fatalf("preview push %+v", st)
	}
	// Production under another env name for the pooled URI.
	if st := e.run(t, pa.ActionVercelEnvPush, pushTo(t, "production", map[string]string{"POSTGRES_URL": "DATABASE_URL", "DATABASE_URL_UNPOOLED": "DATABASE_URL_UNPOOLED"})); st.State != pa.StateSucceeded {
		t.Fatalf("production push %+v", st)
	}
	b, _ := e.vault.Binding("DATABASE_URL")
	if len(b.DeployedTo) != 2 || b.DeployedTo[0].Target != "preview" || b.DeployedTo[1].Target != "production" || b.DeployedTo[1].Env != "POSTGRES_URL" {
		t.Fatalf("deployed_to %+v", b.DeployedTo)
	}
	// A preview-only rotation would break production: refused, nothing called.
	mark := len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, vercelRef("preview"))); code != pa.CodeRotationScopeIncomplete {
		t.Fatalf("preview-only rotation: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, vercelRef("production"))); code != pa.CodeRotationScopeIncomplete {
		t.Fatalf("production-only rotation: %q", code)
	}
	// A scope the records may not go to is still refused.
	other := map[string]any{"team_id": "team_abc123", "project_id": "prj_other", "target": "preview", "git_branch": "main"}
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, vercelRef("production"), vercelRef("preview"), other)); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("not allowed scope: %q", code)
	}
	e.noCallsSince(t, mark, "refused rotations")

	params := neonRotate(t, vercelRef("production"), vercelRef("preview"))
	text := e.summary(t, pa.ActionNeonRotate, params)
	for _, want := range []string{"on Vercel team_abc123: prj_abc123 preview@main+PRODUCTION; PRODUCTION last: STAGED, PROMOTE", "then INVALIDATE old role app_a"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q: %s", want, text)
		}
	}
	mark = len(e.log.Calls())
	st := e.run(t, pa.ActionNeonRotate, params)
	if st.State != pa.StateSucceeded {
		t.Fatalf("rotation %+v", st)
	}
	calls := e.log.Calls()[mark:]
	idx := func(c string) int {
		for i, x := range calls {
			if x == c {
				return i
			}
		}
		return -1
	}
	// Preview pushed, redeployed and healthy before production is touched;
	// production through the release; the old role only at the end.
	if !(idx("vercel.upsert DATABASE_URL preview") < idx("vercel.redeploy dpl_current") && idx("vercel.redeploy dpl_current") < idx("vercel.upsert POSTGRES_URL production") &&
		idx("vercel.upsert POSTGRES_URL production") < idx("vercel.promote dpl_new0002") && idx("vercel.promote dpl_new0002") < idx("neon.invalidate app_a")) || idx("vercel.upsert DATABASE_URL production") >= 0 {
		t.Fatalf("rotation order:\n%s", strings.Join(calls, "\n"))
	}
	if e.fake.Pushed["POSTGRES_URL"] == "" || e.fake.Pushed["POSTGRES_URL"] != e.fake.Pushed["DATABASE_URL"] || !strings.Contains(e.fake.Pushed["POSTGRES_URL"], "app_b") {
		t.Fatal("production env var not rewritten under its deployed name")
	}
	if r := st.Result.Redeployed; len(r) != 2 || r[0].Target != "preview" || r[1].Target != "production" || r[1].Health == nil || !st.Result.ProductionVerified {
		t.Fatalf("redeployed %+v", r)
	}
	e.noLeak(t, "status", st)
}

// Deployments are recorded before the write; deleting the project forgets
// them (its env vars are gone).
func TestDeployedToRecordedBeforePushAndForgottenOnDelete(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.Fail = "vercel.upsert DATABASE_URL preview"
	if st := e.run(t, pa.ActionVercelEnvPush, pushTo(t, "preview", map[string]string{"DATABASE_URL": "DATABASE_URL"})); st.State != pa.StateFailed {
		t.Fatalf("push %+v", st)
	}
	if b, _ := e.vault.Binding("DATABASE_URL"); len(b.DeployedTo) != 1 {
		t.Fatalf("a failed push must still be recorded (fail closed): %+v", b.DeployedTo)
	}
	e.fake.Fail = ""
	e.vault.CreatedVercelProject("team_abc123", "prj_abc123")
	st := e.run(t, pa.ActionVercelProjectDelete, js(t, map[string]any{"team_id": "team_abc123", "project_id": "prj_abc123"}))
	if st.State != pa.StateSucceeded || strings.Join(st.Result.ForgottenDeployments, ",") != "DATABASE_URL" {
		t.Fatalf("delete %+v", st)
	}
	if b, _ := e.vault.Binding("DATABASE_URL"); len(b.DeployedTo) != 0 || len(b.AllowedDestinations) != 1 {
		t.Fatalf("binding after project delete %+v", b)
	}
}

// Finding 2: the broker derives the active role from the bindings and
// refuses an asserted order that disagrees; an interrupted rotation is
// completed, never reset over a role in use.
func TestNeonActiveRoleIsDerived(t *testing.T) {
	e := newEnv(t, nil)
	withRoles := func(roles ...string) json.RawMessage {
		var p map[string]any
		_ = json.Unmarshal(rotateParams(t), &p)
		p["roles"] = roles
		return js(t, p)
	}
	if code := e.prepareCode(t, pa.ActionNeonRotate, withRoles("app_b", "app_a")); code != pa.CodeNeonActiveRoleMismatch {
		t.Fatalf("reversed order: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionNeonRotate, withRoles("app_a", "app_b")); code != "" {
		t.Fatalf("matching order: %q", code)
	}
	if len(e.log.Calls()) != 2 { // the owner and fresh-name live checks of the accepted one only
		t.Fatalf("calls %v", e.log.Calls())
	}
	// Inconsistent or missing role state: refused.
	b, _ := e.vault.Binding("DATABASE_URL_UNPOOLED")
	b.ActiveRole = "app_b"
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeNeonActiveRoleMismatch {
		t.Fatalf("pooled and direct disagree: %q", code)
	}
	b.Roles, b.ActiveRole = nil, ""
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeNeonActiveRoleMismatch {
		t.Fatalf("no role state: %q", code)
	}

	// Interrupted: health fails after app_b's URIs were stored and pushed.
	e = newEnv(t, nil)
	e.fake.Fail = "vercel.health /api/health"
	if st := e.run(t, pa.ActionNeonRotate, rotateParams(t)); st.State != pa.StateFailed || st.Step != pa.StepHealth {
		t.Fatalf("interrupted %+v", st)
	}
	b, _ = e.vault.Binding("DATABASE_URL")
	if b.ActiveRole != "app_b" || b.RetiringRole != "app_a" {
		t.Fatalf("binding after the interruption %+v", b)
	}
	stored, _ := e.vault.Value("DATABASE_URL")
	// The next rotation completes it: app_a (maybe still in use) is not
	// reset first, app_b's stored URIs are deployed, then app_a goes.
	if code := e.prepareCode(t, pa.ActionNeonRotate, withRoles("app_b", "app_a")); code != pa.CodeNeonActiveRoleMismatch {
		t.Fatalf("reset of the retiring role asserted: %q", code)
	}
	text := e.summary(t, pa.ActionNeonRotate, rotateParams(t))
	if !strings.Contains(text, "COMPLETE Neon calm-sky-123456/br-main-1/appdb rotation to role app_b") || !strings.Contains(text, "then INVALIDATE old role app_a") {
		t.Fatalf("resume text: %s", text)
	}
	e.fake.Fail = ""
	mark := len(e.log.Calls())
	st := e.run(t, pa.ActionNeonRotate, withRoles("app_a", "app_b"))
	if st.State != pa.StateSucceeded || !st.Result.Resumed || st.Result.InvalidatedRole != "app_a" {
		t.Fatalf("resume %+v", st)
	}
	for _, c := range e.log.Calls()[mark:] {
		if strings.HasPrefix(c, "neon.reset ") {
			t.Fatalf("a password was reset while resuming: %v", e.log.Calls()[mark:])
		}
	}
	if v, _ := e.vault.Value("DATABASE_URL"); v != stored || e.fake.Pushed["DATABASE_URL"] != stored {
		t.Fatal("resume did not deploy the stored URIs")
	}
	if b, _ := e.vault.Binding("DATABASE_URL"); b.ActiveRole != "app_b" || b.RetiringRole != "" {
		t.Fatalf("binding after resume %+v", b)
	}
	// The one after that rotates normally, back to app_a.
	if text := e.summary(t, pa.ActionNeonRotate, rotateParams(t)); !strings.Contains(text, "reset role app_a into") || !strings.Contains(text, "INVALIDATE old role app_b") {
		t.Fatalf("next text: %s", text)
	}
}

// Finding 3: a branch-scoped preview redeploy reads the branch's current
// deployment.
func TestBranchScopedRedeployReadsThatBranch(t *testing.T) {
	e := newEnv(t, nil)
	p := vercelRef("preview")
	p["git_branch"] = "feat/x"
	st := e.run(t, pa.ActionVercelRedeploy, js(t, p))
	if st.State != pa.StateSucceeded || e.log.Index("vercel.current branch=feat/x") < 0 {
		t.Fatalf("redeploy %+v calls %v", st, e.log.Calls())
	}
	if r := st.Result.Redeployed; len(r) != 1 || r[0].GitBranch != "feat/x" {
		t.Fatalf("redeployed %+v", r)
	}
}

// Finding 4: deletes are refused unless this broker created the resource,
// and the text names it.
func TestDeletesNeedProvenance(t *testing.T) {
	e := newEnv(t, nil)
	for action, params := range map[string]json.RawMessage{
		pa.ActionNeonProjectDelete:   js(t, map[string]any{"project_id": "calm-sky-123456"}),
		pa.ActionVercelProjectDelete: js(t, map[string]any{"team_id": "team_abc123", "project_id": "prj_abc123"}),
		pa.ActionStripeWebhookDelete: js(t, map[string]any{"endpoint_id": "we_foreign1"}),
	} {
		if code := e.prepareCode(t, action, params); code != pa.CodeNotCreatedByBroker {
			t.Errorf("%s of a foreign resource: %q", action, code)
		}
	}
	if len(e.log.Calls()) != 0 {
		t.Fatalf("calls %v", e.log.Calls())
	}
	// Created here: allowed, and the texts say what and that.
	st := e.run(t, pa.ActionNeonProjectCreate, js(t, map[string]any{"name": "throwaway-db", "records": map[string]string{"pooled": "P", "direct": "D"}}))
	if st.State != pa.StateSucceeded {
		t.Fatalf("create %+v", st)
	}
	if text := e.summary(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": st.Result.ProjectID})); !strings.Contains(text, "DELETE Neon project throwaway-db (calm-sky-123456), created by this broker,") {
		t.Errorf("neon text: %s", text)
	}
	vp := e.run(t, pa.ActionVercelProjectCreate, js(t, map[string]any{"team_id": "team_abc123", "name": "throwaway-app"}))
	if text := e.summary(t, pa.ActionVercelProjectDelete, js(t, map[string]any{"team_id": "team_abc123", "project_id": vp.Result.ProjectID})); !strings.Contains(text, "DELETE Vercel project throwaway-app ("+vp.Result.ProjectID+") in team_abc123, created by this broker,") {
		t.Errorf("vercel text: %s", text)
	}
	wh := e.run(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "WHSEC"}))
	if text := e.summary(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": wh.Result.EndpointID})); !strings.Contains(text, "DELETE Stripe webhook endpoint "+wh.Result.EndpointID+" for https://shop.example.com/api/stripe, created by this broker") {
		t.Errorf("stripe text: %s", text)
	}
}

// Finding 5: neon.roles.prepare refuses existing roles it did not create,
// unless adopt_existing_roles (then named in the text), and owner_role must
// be the database's owner.
func TestRolesPrepareRefusesExistingRoles(t *testing.T) {
	params := map[string]any{"project_id": "foreign-proj-1", "branch_id": "br-main-1", "database": "appdb", "owner_role": "neondb_owner", "adopt": false}
	e := newEnv(t, nil)
	e.fake.ExistingRoles["app_a"] = true
	if code := e.prepareCode(t, pa.ActionNeonRolesPrepare, js(t, params)); code != pa.CodeNeonRoleExists {
		t.Fatalf("existing role: %q", code)
	}
	params["adopt_existing_roles"] = true
	text := e.summary(t, pa.ActionNeonRolesPrepare, js(t, params))
	if !strings.Contains(text, "EXISTING role app_a (not created by this broker) will act as the schema owner") || strings.Contains(text, "EXISTING role app_b") {
		t.Fatalf("adopt text: %s", text)
	}
	for _, c := range e.log.Calls() {
		if strings.HasPrefix(c, "neon.prepare_roles") {
			t.Fatal("prepared before approval")
		}
	}
	// A role created between the prompt and the run is refused.
	prep, code := e.svc.Prepare(context.Background(), pa.ActionNeonRolesPrepare, js(t, params))
	if code != "" {
		t.Fatal(code)
	}
	e.fake.ExistingRoles["app_b"] = true
	id, _ := e.svc.Start(prep, owner, scope, nil)
	if st := e.wait(t, id); st.State != pa.StateFailed || st.Step != pa.StepNeonCheckRoleState || st.Code != pa.CodeNeonRoleExists || e.log.Index("neon.prepare_roles neondb_owner app_a,app_b adopt=false") >= 0 {
		t.Fatalf("changed role state %+v", st)
	}
	// Roles this broker created (project provenance) are its own.
	e = newEnv(t, nil)
	e.vault.CreatedNeonProject("calm-sky-123456", "br-main-1")
	e.fake.ExistingRoles["app_a"], e.fake.ExistingRoles["app_b"] = true, true
	own := map[string]any{"project_id": "calm-sky-123456", "branch_id": "br-main-1", "database": "appdb", "owner_role": "neondb_owner", "adopt": false}
	if st := e.run(t, pa.ActionNeonRolesPrepare, js(t, own)); st.State != pa.StateSucceeded {
		t.Fatalf("own roles %+v", st)
	}
	// owner_role must be the database's actual owner.
	e.fake.DBOwner = "someone_else"
	if code := e.prepareCode(t, pa.ActionNeonRolesPrepare, js(t, own)); code != pa.CodeNeonOwnerRoleMismatch {
		t.Fatalf("owner mismatch: %q", code)
	}
}

// Finding 7: neon.rotate checks the database's owner and never makes it a
// rotation role.
func TestNeonRotateChecksTheOwner(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.DBOwner = "real_owner"
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeNeonOwnerRoleMismatch {
		t.Fatalf("owner mismatch: %q", code)
	}
	e = newEnv(t, nil)
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		b, _ := e.vault.Binding(rec)
		b.Roles, b.ActiveRole = []string{"NeonDB_Owner", "app_b"}, "app_b"
		e.vault.Bind(b)
	}
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeNeonOwnerRoleMismatch {
		t.Fatalf("owner as a rotation role: %q", code)
	}
	if len(e.log.Calls()) != 0 {
		t.Fatalf("calls %v", e.log.Calls())
	}
}

// Finding 6: re-running a Stripe rotation whose previous endpoint still
// exists is refused (the endpoint is reported); once that endpoint is
// deleted, the dead previous secret is overwritten.
func TestStripeRotationRefusesOrphanEndpoint(t *testing.T) {
	old := provideractiontest.Sentinel("whsec_")
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": old})
	e.fake.Fail = "vercel.health /api/health"
	st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	if st.State != pa.StateFailed || st.Result.EndpointID == "" {
		t.Fatalf("interrupted %+v", st)
	}
	e.fake.Fail = ""
	second := st.Result.EndpointID
	mark := len(e.log.Calls())
	prep, code, detail := e.svc.PrepareDetail(context.Background(), pa.ActionStripeWebhookRotate, stripeRotate(t, second, vercelRef("preview")))
	prep.Release()
	if code != pa.CodeStripeOrphanEndpoint || detail == nil || detail.OrphanEndpointID != "we_old1" {
		t.Fatalf("orphan: %q %+v", code, detail)
	}
	if calls := e.log.Calls()[mark:]; strings.Join(calls, ",") != "stripe.webhook "+second+",stripe.webhook we_old1" {
		t.Fatalf("only the read-only endpoint reads may run: %v", calls)
	}
	if prev, _ := e.vault.Value("STRIPE_WEBHOOK_SECRET_PREVIOUS"); prev != old {
		t.Fatal("the secret in use was lost")
	}
	// Cleanup: delete the orphan (created by this broker), then rotate.
	if st := e.run(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_old1"})); st.State != pa.StateSucceeded ||
		strings.Join(st.Result.RevokedBindings, ",") != "STRIPE_WEBHOOK_SECRET_PREVIOUS" {
		t.Fatalf("orphan delete %+v", st)
	}
	st = e.run(t, pa.ActionStripeWebhookRotate, stripeRotate(t, second, vercelRef("preview")))
	if st.State != pa.StateSucceeded || st.Result.DeletedEndpointID != second {
		t.Fatalf("rotation after cleanup %+v", st)
	}
	if b, _ := e.vault.Binding("STRIPE_WEBHOOK_SECRET_PREVIOUS"); b.Revoked || b.Resource.EndpointID != second {
		t.Fatalf("previous binding %+v", b)
	}
	e.noLeak(t, "status", st)
}

// Finding 8: prechecks never read a value (revision only).
func TestPrechecksReadNoValues(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	for action, params := range map[string]json.RawMessage{
		pa.ActionVercelEnvPush:       pushTo(t, "preview", map[string]string{"DATABASE_URL": "DATABASE_URL"}),
		pa.ActionBindingAllow:        js(t, map[string]any{"records": []string{"DATABASE_URL"}, "team_id": "team_abc123", "project_id": "prj_new1"}),
		pa.ActionStripeWebhookRotate: stripeRotateParams(t),
	} {
		if code := e.prepareCode(t, action, params); code != "" {
			t.Fatalf("%s: %q", action, code)
		}
	}
	for _, r := range e.vault.ValueReads() {
		if !strings.HasPrefix(r, "CONTROL_") { // a live precheck's control credential only
			t.Fatalf("a precheck read the value of %s", r)
		}
	}
}
