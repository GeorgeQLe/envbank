package provideraction_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// Tests for the second security review of provider actions (November 5,
// 2026).

func branchRef(branch string) map[string]any {
	m := vercelRef("preview")
	if branch == "" {
		delete(m, "git_branch")
	} else {
		m["git_branch"] = branch
	}
	return m
}

func pushAt(t *testing.T, ref map[string]any, vars map[string]string, replace bool) json.RawMessage {
	m := map[string]any{"variables": vars}
	for k, v := range ref {
		m[k] = v
	}
	if replace {
		m["replace_existing"] = true
	}
	return js(t, m)
}

func deployedTo(b pa.Binding) []string {
	var out []string
	for _, d := range b.DeployedTo {
		s := d.Target + "@" + d.GitBranch + ":" + d.Env
		out = append(out, s)
	}
	return out
}

// M1: a rotation never rewrites an all-branches preview env var, named in
// its params or recorded in deployed_to. The way out: remove that env var
// (vercel.env.remove), push per branch, rotate.
func TestRotationRefusesUnscopedPreview(t *testing.T) {
	e := newEnv(t, nil)
	mark := len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, branchRef(""))); code != pa.CodeRotationUnscopedPreview {
		t.Fatalf("unscoped preview in params: %q", code)
	}
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, branchRef(""), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("all-branches push %+v", st)
	}
	mark = len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, branchRef("main"))); code != pa.CodeRotationUnscopedPreview {
		t.Fatalf("unscoped preview in deployed_to: %q", code)
	}
	e.noCallsSince(t, mark, "refused rotation")
	if st := e.run(t, pa.ActionVercelEnvRemove, envRemove(t, "DATABASE_URL", "DATABASE_URL", branchRef(""))); st.State != pa.StateSucceeded {
		t.Fatalf("remove %+v", st)
	}
	if st := e.run(t, pa.ActionNeonRotate, neonRotate(t, branchRef("main"))); st.State != pa.StateSucceeded {
		t.Fatalf("rotation after the workaround %+v", st)
	}
}

// M2: every vault write names the revision it expects; a record changed
// meanwhile (by the owner or another broker) is never overwritten.
func TestRecordChangedMeanwhileIsNotOverwritten(t *testing.T) {
	change := func(e *env, record string) {
		var once sync.Once
		e.vault.BeforeStore = func(name string) {
			if name == record {
				once.Do(func() { e.vault.Set(record, "changed-by-owner") })
			}
		}
	}
	cases := []struct {
		name, record, action string
		params               func(t *testing.T) json.RawMessage
	}{
		{"neon rotate", "DATABASE_URL", pa.ActionNeonRotate, rotateParams},
		{"stripe rotate previous", "STRIPE_WEBHOOK_SECRET_PREVIOUS", pa.ActionStripeWebhookRotate, stripeRotateParams},
		{"stripe rotate current", "STRIPE_WEBHOOK_SECRET", pa.ActionStripeWebhookRotate, stripeRotateParams},
		{"neon create", "NEW_DB_URL", pa.ActionNeonProjectCreate, func(t *testing.T) json.RawMessage {
			return js(t, map[string]any{"name": "throwaway-1", "region_id": "aws-us-east-2", "pg_version": 17,
				"records": map[string]string{"pooled": "NEW_DB_URL", "direct": "NEW_DB_URL_UNPOOLED"}})
		}},
		{"stripe create", "NEW_WHSEC", pa.ActionStripeWebhookCreate, func(t *testing.T) json.RawMessage {
			return js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "NEW_WHSEC"})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
			change(e, c.record)
			st := e.run(t, c.action, c.params(t))
			if st.State != pa.StateFailed || st.Code != pa.CodeRecordChanged {
				t.Fatalf("status %+v", st)
			}
			if v, _ := e.vault.Value(c.record); v != "changed-by-owner" {
				t.Fatal("the changed record was overwritten")
			}
			if e.log.Index("vault.store_refused "+c.record) < 0 || len(e.fake.Pushed) != 0 ||
				e.log.Index("neon.invalidate app_a") >= 0 || e.log.Index("stripe.delete we_old1") >= 0 {
				t.Fatalf("calls %v", e.log.Calls())
			}
			e.noLeak(t, "status", st)
		})
	}
}

// M3: one owner per (scope, env name). A push over another record's env
// var needs replace_existing, names the replaced record in the approval,
// and drops that record's claim; a rotation never writes there.
func TestEnvNameHasOneOwner(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	main := branchRef("main")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	mark := len(e.log.Calls())
	other := pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, false)
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, other); code != pa.CodeEnvNameTaken {
		t.Fatalf("push over another record's env var: %q", code)
	}
	e.noCallsSince(t, mark, "refused push")
	replace := pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, true)
	if s := e.summary(t, pa.ActionVercelEnvPush, replace); !strings.Contains(s, "; REPLACES record DATABASE_URL's value in DB_URL") {
		t.Fatalf("replace text: %s", s)
	}
	st := e.run(t, pa.ActionVercelEnvPush, replace)
	if st.State != pa.StateSucceeded || strings.Join(st.Result.ReplacedRecords, ",") != "DATABASE_URL" || !contains(st.Steps, pa.StepBindingRelease) {
		t.Fatalf("replace %+v", st)
	}
	a, _ := e.vault.Binding("DATABASE_URL")
	b, _ := e.vault.Binding("DATABASE_URL_UNPOOLED")
	if len(a.DeployedTo) != 0 || strings.Join(deployedTo(b), ",") != "preview@main:DB_URL" {
		t.Fatalf("claims: %v and %v", deployedTo(a), deployedTo(b))
	}
	// A rotation refuses to write over another record's env var: here the
	// Stripe secret was pushed as DATABASE_URL.
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("feat/x"), map[string]string{"DATABASE_URL": "STRIPE_WEBHOOK_SECRET"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	mark = len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, branchRef("feat/x"), main)); code != pa.CodeEnvNameTaken {
		t.Fatalf("rotation over another record's env var: %q", code)
	}
	e.noCallsSince(t, mark, "refused rotation")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// L1: env.push locks its records and the records whose env vars it
// replaces, so it cannot interleave with a rotation of either.
func TestEnvPushLocksItsRecords(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	main := branchRef("main")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"WH": "STRIPE_WEBHOOK_SECRET"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	ctx := context.Background()
	rot, code := e.svc.Prepare(ctx, pa.ActionNeonRotate, rotateParams(t))
	if code != "" {
		t.Fatal(code)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("feat/y"), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); code != pa.CodeResourceBusy {
		t.Fatalf("push of a record being rotated: %q", code)
	}
	rot.Release()
	srot, code := e.svc.Prepare(ctx, pa.ActionStripeWebhookRotate, stripeRotate(t, "we_old1", main))
	if code != "" {
		t.Fatal(code)
	}
	// Replacing the Stripe secret's env var locks the Stripe record too.
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"WH": "DATABASE_URL"}, true)); code != pa.CodeResourceBusy {
		t.Fatalf("push replacing a record being rotated: %q", code)
	}
	srot.Release()
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"WH": "DATABASE_URL"}, true)); code != "" {
		t.Fatalf("after release: %q", code)
	}
}

// 1(c): vercel.env.remove deletes one bound record's env var from one
// scope and drops that deployed_to entry; the record stays.
func TestVercelEnvRemove(t *testing.T) {
	e := newEnv(t, map[string]string{"CLERK_SECRET_KEY": provideractiontest.Sentinel("sk_")})
	prod := vercelRef("production")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, prod, map[string]string{"POSTGRES_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	before, _ := e.vault.Value("DATABASE_URL")
	params := envRemove(t, "DATABASE_URL", "POSTGRES_URL", prod)
	if s := e.summary(t, pa.ActionVercelEnvRemove, params); s != "REMOVE env var POSTGRES_URL (record DATABASE_URL's value) from Vercel prj_abc123 (team_abc123) PRODUCTION; "+
		"deployments built with it keep it until redeployed; the record stays in the vault" {
		t.Fatalf("text: %s", s)
	}
	mark, reads := len(e.log.Calls()), len(e.vault.ValueReads())
	st := e.run(t, pa.ActionVercelEnvRemove, params)
	if st.State != pa.StateSucceeded || st.Result.Variables["POSTGRES_URL"] != "removed" || strings.Join(st.Result.ForgottenDeployments, ",") != "DATABASE_URL" {
		t.Fatalf("remove %+v", st)
	}
	if calls := e.log.Calls()[mark:]; strings.Join(calls, ",") != "vercel.delete_env POSTGRES_URL production" {
		t.Fatalf("calls %v", calls)
	}
	b, _ := e.vault.Binding("DATABASE_URL")
	if after, _ := e.vault.Value("DATABASE_URL"); len(b.DeployedTo) != 0 || after != before || contains(e.vault.ValueReads()[reads:], "DATABASE_URL") {
		t.Fatalf("binding %+v, record kept %v, value reads %v", b.DeployedTo, after == before, e.vault.ValueReads()[reads:])
	}
	mark = len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionVercelEnvRemove, params); code != pa.CodeNotDeployed {
		t.Fatalf("second remove: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvRemove, envRemove(t, "CLERK_SECRET_KEY", "CLERK_SECRET_KEY", prod)); code != pa.CodeRecordNotBound {
		t.Fatalf("owner-entered record: %q", code)
	}
	e.noCallsSince(t, mark, "refused removes")
	e.noLeak(t, "status", st)
}

// One record spreads over at most as many scopes as one rotation names.
func TestPushRefusesMoreScopesThanARotation(t *testing.T) {
	e := newEnv(t, nil)
	for _, br := range []string{"main", "staging", "feat/a"} {
		if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, branchRef(br), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
			t.Fatalf("push %s %+v", br, st)
		}
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("feat/b"), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); code != pa.CodeRotationScopeLimit {
		t.Fatalf("fourth scope: %q", code)
	}
	// Another env name in a scope already listed is fine.
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("main"), map[string]string{"PG_URL": "DATABASE_URL"}, false)); code != "" {
		t.Fatalf("same scope: %q", code)
	}
}

// L2: the binding records the role about to be reset before the reset, so
// a rotation interrupted between the reset and the binding save is retried
// (the same role reset again), never refused as a mismatch.
func TestInterruptedResetIsRetried(t *testing.T) {
	for _, fail := range []string{"neon.reset app_b", "store"} {
		t.Run(fail, func(t *testing.T) {
			e := newEnv(t, nil)
			if fail == "store" {
				e.vault.FailStore["DATABASE_URL_UNPOOLED"] = true // after the reset and the first store
			} else {
				e.fake.Fail = fail
			}
			st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
			if st.State != pa.StateFailed || st.Step != pa.StepNeonResetNewRole || !contains(st.Steps, pa.StepBindingPending) || len(e.fake.Pushed) != 0 {
				t.Fatalf("interrupted %+v", st)
			}
			for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
				if b, _ := e.vault.Binding(rec); b.PendingRole != "app_b" || b.ActiveRole != "app_a" {
					t.Fatalf("%s after the interruption %+v", rec, b)
				}
			}
			e.fake.Fail = ""
			e.vault.FailStore["DATABASE_URL_UNPOOLED"] = false
			if s := e.summary(t, pa.ActionNeonRotate, rotateParams(t)); !strings.Contains(s, "reset role app_b into") || !strings.Contains(s, "INVALIDATE old role app_a") {
				t.Fatalf("retry text: %s", s)
			}
			st = e.run(t, pa.ActionNeonRotate, rotateParams(t))
			if st.State != pa.StateSucceeded || st.Result.InvalidatedRole != "app_a" {
				t.Fatalf("retry %+v", st)
			}
			for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
				if b, _ := e.vault.Binding(rec); b.PendingRole != "" || b.ActiveRole != "app_b" || b.RetiringRole != "" {
					t.Fatalf("%s after the retry %+v", rec, b)
				}
			}
			e.noLeak(t, "status", st)
		})
	}
}

// L3: a Stripe rotation copies the endpoint the broker created: a live
// endpoint whose URL or events drifted from the provenance is refused
// before the prompt and again when running; the URL is in the approval.
func TestStripeRotationRefusesDrift(t *testing.T) {
	drifts := map[string]pa.StripeWebhook{
		"url":    {URL: "https://attacker.example.net/hook", Events: []string{"checkout.session.completed", "invoice.paid"}},
		"events": {URL: "https://shop.example.com/api/stripe/webhook", Events: []string{"invoice.paid"}},
	}
	for name, live := range drifts {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
			e.fake.Endpoints["we_old1"] = live
			if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != pa.CodeStripeEndpointDrift {
				t.Fatalf("drift before the prompt: %q", code)
			}
			// Drift after the approval: refused at execute, nothing created.
			delete(e.fake.Endpoints, "we_old1")
			prep, code := e.svc.Prepare(context.Background(), pa.ActionStripeWebhookRotate, stripeRotateParams(t))
			if code != "" {
				t.Fatal(code)
			}
			e.fake.Endpoints["we_old1"] = live
			id, code := e.svc.Start(prep, owner, scope, nil)
			if code != "" {
				t.Fatal(code)
			}
			st := e.wait(t, id)
			if st.State != pa.StateFailed || st.Code != pa.CodeStripeEndpointDrift || e.log.Index("stripe.create") >= 0 || len(e.fake.Pushed) != 0 {
				t.Fatalf("drift at execute %+v %v", st, e.log.Calls())
			}
		})
	}
	// Provenance from before events were recorded cannot be compared.
	e := newEnv(t, nil)
	e.vault.Set("STRIPE_WEBHOOK_SECRET", provideractiontest.Sentinel("whsec_"))
	e.vault.Bind(pa.Binding{Record: "STRIPE_WEBHOOK_SECRET", Provider: pa.ProviderStripe, Kind: pa.KindStripeWebhookSecret,
		Resource: pa.BindingResource{EndpointID: "we_old1", Lineage: "we_old1"}, AllowedDestinations: []pa.Destination{{TeamID: "team_abc123", ProjectID: "prj_abc123"}}})
	if err := e.vault.SaveStripeEndpoint(context.Background(), pa.StripeEndpointProvenance{V: pa.BindingVersion, EndpointID: "we_old1",
		URL: "https://shop.example.com/api/stripe/webhook", Lineage: "we_old1"}); err != nil {
		t.Fatal(err)
	}
	if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != pa.CodeStripeEndpointDrift {
		t.Fatalf("legacy provenance: %q", code)
	}
}

// L4: a Neon project or Stripe endpoint whose credentials are still
// deployed is not deleted; vercel.env.remove first.
func TestDeleteRefusedWhileDeployed(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	e.vault.CreatedNeonProject("calm-sky-123456", "br-main-1")
	main := branchRef("main")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DATABASE_URL": "DATABASE_URL", "STRIPE_WEBHOOK_SECRET": "STRIPE_WEBHOOK_SECRET"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	mark := len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "calm-sky-123456"})); code != pa.CodeResourceStillDeployed {
		t.Fatalf("neon delete: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_old1"})); code != pa.CodeResourceStillDeployed {
		t.Fatalf("stripe delete: %q", code)
	}
	e.noCallsSince(t, mark, "refused deletes")
	for _, rec := range []string{"DATABASE_URL", "STRIPE_WEBHOOK_SECRET"} {
		if st := e.run(t, pa.ActionVercelEnvRemove, envRemove(t, rec, rec, main)); st.State != pa.StateSucceeded {
			t.Fatalf("remove %s %+v", rec, st)
		}
	}
	if st := e.run(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "calm-sky-123456"})); st.State != pa.StateSucceeded {
		t.Fatalf("neon delete %+v", st)
	}
	if st := e.run(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_old1"})); st.State != pa.StateSucceeded {
		t.Fatalf("stripe delete %+v", st)
	}
}

// L5: a production redeploy's explicit source must be the deployment
// serving production now (the rollback target); otherwise nothing changes.
func TestProductionRedeploySourceMustBeCurrent(t *testing.T) {
	e := newEnv(t, nil)
	p := vercelRef("production")
	p["deployment"], p["health_path"] = "dpl_older", "/api/health"
	if s := e.summary(t, pa.ActionVercelRedeploy, js(t, p)); !strings.Contains(s, "from the deployment serving production now (must be dpl_older) as STAGED") {
		t.Fatalf("text: %s", s)
	}
	st := e.run(t, pa.ActionVercelRedeploy, js(t, p))
	if st.State != pa.StateFailed || st.Code != pa.CodeProductionSourceNotCurrent || e.log.Index("vercel.redeploy dpl_older") >= 0 || e.fake.Production() != "dpl_current" {
		t.Fatalf("status %+v calls %v", st, e.log.Calls())
	}
	p["deployment"] = "dpl_current"
	if st := e.run(t, pa.ActionVercelRedeploy, js(t, p)); st.State != pa.StateSucceeded || !st.Result.Promoted || st.Result.PreviousDeploymentID != "dpl_current" {
		t.Fatalf("redeploy of the current deployment %+v", st)
	}
}
