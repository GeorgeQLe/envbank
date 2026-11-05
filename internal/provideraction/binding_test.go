package provideraction_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

func envRemove(t *testing.T, record, envName string, ref map[string]any) json.RawMessage {
	m := map[string]any{"record": record, "env": envName}
	for k, v := range ref {
		m[k] = v
	}
	return js(t, m)
}

func pushParams(t *testing.T, project string, vars map[string]string) json.RawMessage {
	return js(t, map[string]any{"team_id": "team_abc123", "project_id": project, "target": "preview", "git_branch": "main", "variables": vars})
}

// prepareCode prepares and releases, returning the refusal code ("" ok).
func (e *env) prepareCode(t *testing.T, action string, params json.RawMessage) string {
	t.Helper()
	prep, code := e.svc.Prepare(context.Background(), action, params)
	prep.Release()
	return code
}

func TestPushRefusesUnboundRecordsBeforeAnyCall(t *testing.T) {
	clerk := provideractiontest.Sentinel("sk_live_clerk_")
	e := newEnv(t, map[string]string{"CLERK_SECRET_KEY": clerk})
	// Owner-entered: no binding at all.
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"CLERK_SECRET_KEY": "CLERK_SECRET_KEY"})); code != pa.CodeRecordNotBound {
		t.Fatalf("unbound push: %q", code)
	}
	// One unbound record refuses the whole push.
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL", "X": "CLERK_SECRET_KEY"})); code != pa.CodeRecordNotBound {
		t.Fatalf("mixed push: %q", code)
	}
	// A bound record rewritten by something else (owner entry, import)
	// is no longer bound: the binding pins the revision the broker stored.
	e.vault.Set("DATABASE_URL", clerk)
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL"})); code != pa.CodeRecordNotBound {
		t.Fatalf("stale binding push: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeRecordNotBound {
		t.Fatalf("rotation over a foreign value: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionBindingAllow, js(t, map[string]any{"records": []string{"CLERK_SECRET_KEY"}, "team_id": "team_abc123", "project_id": "prj_abc123"})); code != pa.CodeRecordNotBound {
		t.Fatalf("binding.allow of an owner-entered record: %q", code)
	}
	if len(e.log.Calls()) != 0 || len(e.fake.Pushed) != 0 {
		t.Fatalf("side effects: %v", e.log.Calls())
	}
}

func TestPushRefusesDestinationsNotAllowed(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_attacker", map[string]string{"DATABASE_URL": "DATABASE_URL"})); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("push to another project: %q", code)
	}
	// Same project ID under another team is another destination.
	other := js(t, map[string]any{"team_id": "team_other", "project_id": "prj_abc123", "target": "preview", "variables": map[string]string{"DATABASE_URL": "DATABASE_URL"}})
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, other); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("push to another team: %q", code)
	}
	for _, action := range []string{pa.ActionNeonRotate, pa.ActionStripeWebhookRotate} {
		var p map[string]any
		params := rotateParams(t)
		if action == pa.ActionStripeWebhookRotate {
			params = stripeRotateParams(t)
		}
		_ = json.Unmarshal(params, &p)
		p["vercel"].([]any)[0].(map[string]any)["project_id"] = "prj_attacker"
		if code := e.prepareCode(t, action, js(t, p)); code != pa.CodeDestinationNotAllowed {
			t.Fatalf("%s to another project: %q", action, code)
		}
	}
	if len(e.log.Calls()) != 0 {
		t.Fatalf("side effects: %v", e.log.Calls())
	}
	// Allowed: preview and production of the allowed project.
	st := e.run(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL"}))
	if st.State != pa.StateSucceeded {
		t.Fatalf("allowed push: %+v", st)
	}
	e.noLeak(t, "push", st)
}

// A record changed between the prompt and the run is refused by the
// operation's first step: no destination is written.
func TestPushBindingRecheckedWhenRunning(t *testing.T) {
	e := newEnv(t, nil)
	prep, code := e.svc.Prepare(context.Background(), pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL"}))
	if code != "" {
		t.Fatal(code)
	}
	e.vault.Set("DATABASE_URL", provideractiontest.Sentinel("foreign_"))
	id, _ := e.svc.Start(prep, owner, scope, nil)
	st := e.wait(t, id)
	if st.State != pa.StateFailed || st.Step != pa.StepVaultReadRevisions || st.Code != pa.CodeRecordNotBound || len(e.fake.Pushed) != 0 {
		t.Fatalf("status %+v, pushed %d", st, len(e.fake.Pushed))
	}
}

func TestBindingAllowAddsOneDestination(t *testing.T) {
	e := newEnv(t, nil)
	allow := js(t, map[string]any{"records": []string{"DATABASE_URL_UNPOOLED", "DATABASE_URL"}, "team_id": "team_abc123", "project_id": "prj_new1"})
	prep, code := e.svc.Prepare(context.Background(), pa.ActionBindingAllow, allow)
	if code != "" {
		t.Fatal(code)
	}
	text := prep.Summary()
	for _, want := range []string{"ALLOW records DATABASE_URL, DATABASE_URL_UNPOOLED to be deployed to Vercel project prj_new1 (team_abc123)", "PRODUCTION", "can read their values", "NOT created by this broker"} {
		if !strings.Contains(text, want) {
			t.Errorf("binding.allow text lacks %q: %s", want, text)
		}
	}
	id, _ := e.svc.Start(prep, owner, scope, nil)
	if st := e.wait(t, id); st.State != pa.StateSucceeded || st.Result.ProjectID != "prj_new1" || len(st.Result.Records) != 2 {
		t.Fatalf("allow %+v", st)
	}
	b, _ := e.vault.Binding("DATABASE_URL")
	if len(b.AllowedDestinations) != 2 || b.AllowedDestinations[1] != (pa.Destination{TeamID: "team_abc123", ProjectID: "prj_new1"}) {
		t.Fatalf("binding %+v", b)
	}
	// A project this broker created is said so (provenance only).
	st := e.run(t, pa.ActionVercelProjectCreate, js(t, map[string]any{"team_id": "team_abc123", "name": "throwaway-app"}))
	if st.State != pa.StateSucceeded || st.Result.TeamID != "team_abc123" {
		t.Fatalf("create %+v", st)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, st.Result.ProjectID, map[string]string{"DATABASE_URL": "DATABASE_URL"})); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("project creation allowed a record: %q", code)
	}
	prep, _ = e.svc.Prepare(context.Background(), pa.ActionBindingAllow, js(t, map[string]any{"records": []string{"DATABASE_URL"}, "team_id": "team_abc123", "project_id": st.Result.ProjectID}))
	if !strings.Contains(prep.Summary(), "Project created by this broker") {
		t.Fatalf("provenance not shown: %s", prep.Summary())
	}
	prep.Release()
	// Bounded.
	b, _ = e.vault.Binding("DATABASE_URL")
	for i := len(b.AllowedDestinations); i < pa.MaxAllowedDestinations; i++ {
		b.AllowedDestinations = append(b.AllowedDestinations, pa.Destination{TeamID: "team_abc123", ProjectID: "prj_fill" + strings.Repeat("x", i)})
	}
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionBindingAllow, js(t, map[string]any{"records": []string{"DATABASE_URL"}, "team_id": "team_abc123", "project_id": "prj_onemore"})); code != pa.CodeBindingLimit {
		t.Fatalf("limit: %q", code)
	}
}

func TestRotationsRefuseUnboundAndForeignRecords(t *testing.T) {
	neonVariant := func(t *testing.T, mutate func(p map[string]any)) json.RawMessage {
		var p map[string]any
		_ = json.Unmarshal(rotateParams(t), &p)
		mutate(p)
		return js(t, p)
	}
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_"), "OTHER_SECRET": provideractiontest.Sentinel("x_")})
	cases := []struct {
		name   string
		action string
		params json.RawMessage
		code   string
	}{
		{"neon other project", pa.ActionNeonRotate, neonVariant(t, func(p map[string]any) { p["project_id"] = "other-project-1" }), pa.CodeBindingMismatch},
		{"neon other branch", pa.ActionNeonRotate, neonVariant(t, func(p map[string]any) { p["branch_id"] = "br-other-1" }), pa.CodeBindingMismatch},
		{"neon kinds swapped", pa.ActionNeonRotate, neonVariant(t, func(p map[string]any) {
			p["records"] = map[string]string{"pooled": "DATABASE_URL_UNPOOLED", "direct": "DATABASE_URL"}
		}), pa.CodeBindingMismatch},
		{"neon unbound record", pa.ActionNeonRotate, neonVariant(t, func(p map[string]any) {
			p["records"] = map[string]string{"pooled": "DATABASE_URL", "direct": "OTHER_SECRET"}
		}), pa.CodeRecordNotBound},
		{"neon stripe record", pa.ActionNeonRotate, neonVariant(t, func(p map[string]any) {
			p["records"] = map[string]string{"pooled": "STRIPE_WEBHOOK_SECRET", "direct": "DATABASE_URL_UNPOOLED"}
		}), pa.CodeBindingMismatch},
		{"stripe other endpoint", pa.ActionStripeWebhookRotate, []byte(strings.Replace(string(stripeRotateParams(t)), "we_old1", "we_other", 1)), pa.CodeBindingMismatch},
		{"stripe neon record", pa.ActionStripeWebhookRotate, []byte(strings.Replace(string(stripeRotateParams(t)), `"record":"STRIPE_WEBHOOK_SECRET"`, `"record":"DATABASE_URL"`, 1)), pa.CodeBindingMismatch},
		{"stripe unbound record", pa.ActionStripeWebhookRotate, []byte(strings.Replace(string(stripeRotateParams(t)), `"record":"STRIPE_WEBHOOK_SECRET"`, `"record":"OTHER_SECRET"`, 1)), pa.CodeRecordNotBound},
		{"stripe previous unbound", pa.ActionStripeWebhookRotate, []byte(strings.Replace(string(stripeRotateParams(t)), "STRIPE_WEBHOOK_SECRET_PREVIOUS", "OTHER_SECRET", 1)), pa.CodeRecordNotBound},
		{"stripe previous is a neon record", pa.ActionStripeWebhookRotate, []byte(strings.Replace(string(stripeRotateParams(t)), "STRIPE_WEBHOOK_SECRET_PREVIOUS", "DATABASE_URL", 1)), pa.CodeBindingMismatch},
	}
	for _, c := range cases {
		if code := e.prepareCode(t, c.action, c.params); code != c.code {
			t.Errorf("%s: got %q, want %q", c.name, code, c.code)
		}
	}
	// previous_record bound to another lineage.
	e.vault.Set("STRIPE_WEBHOOK_SECRET_PREVIOUS", provideractiontest.Sentinel("whsec_"))
	e.vault.Bind(pa.Binding{Record: "STRIPE_WEBHOOK_SECRET_PREVIOUS", Provider: pa.ProviderStripe, Kind: pa.KindStripeWebhookSecretPrevious,
		Resource: pa.BindingResource{EndpointID: "we_x", Lineage: "we_x"}})
	if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != pa.CodeBindingMismatch {
		t.Fatalf("previous of another lineage: %q", code)
	}
	// A revoked binding is not bound.
	b, _ := e.vault.Binding("DATABASE_URL")
	b.Revoked = true
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionNeonRotate, rotateParams(t)); code != pa.CodeRecordNotBound {
		t.Fatalf("revoked: %q", code)
	}
	if len(e.log.Calls()) != 0 {
		t.Fatalf("side effects: %v", e.log.Calls())
	}
	if v, _ := e.vault.Value("OTHER_SECRET"); !strings.Contains(v, "SENTINEL") {
		t.Fatal("unrelated record changed")
	}
}

func TestCreateActionsBindNewRecords(t *testing.T) {
	e := newEnv(t, nil)
	st := e.run(t, pa.ActionNeonProjectCreate, js(t, map[string]any{"name": "throwaway", "records": map[string]string{"pooled": "NEW_POOLED", "direct": "NEW_DIRECT"}}))
	if st.State != pa.StateSucceeded || st.Steps[len(st.Steps)-1] != pa.StepBindingSave {
		t.Fatalf("create %+v", st)
	}
	for rec, kind := range map[string]string{"NEW_POOLED": pa.KindNeonPooled, "NEW_DIRECT": pa.KindNeonDirect} {
		b, ok := e.vault.Binding(rec)
		_, rev := e.vault.Value(rec)
		if !ok || b.Kind != kind || b.Provider != pa.ProviderNeon || b.Resource.ProjectID != "calm-sky-123456" || b.Resource.BranchID != "br-main-1" ||
			b.RecordRevision != rev || len(b.AllowedDestinations) != 0 || b.Revoked {
			t.Fatalf("%s binding %+v", rec, b)
		}
	}
	st = e.run(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "WHSEC"}))
	b, _ := e.vault.Binding("WHSEC")
	if st.State != pa.StateSucceeded || b.Kind != pa.KindStripeWebhookSecret || b.Resource.EndpointID != st.Result.EndpointID || b.Resource.Lineage != st.Result.EndpointID {
		t.Fatalf("stripe create %+v, binding %+v", st, b)
	}
	// Create actions still refuse existing records, bound or not.
	if code := e.prepareCode(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/x", "events": []string{"invoice.paid"}, "record": "DATABASE_URL"})); code != pa.CodeRecordExists {
		t.Fatalf("create over a bound record: %q", code)
	}
	// A binding save failure fails the create (the records stay, unbound).
	e = newEnv(t, nil)
	e.vault.FailBinding["P2"] = true
	st = e.run(t, pa.ActionNeonProjectCreate, js(t, map[string]any{"name": "throwaway", "records": map[string]string{"pooled": "P2", "direct": "D2"}}))
	if st.State != pa.StateFailed || st.Step != pa.StepBindingSave || st.Result.ProjectID == "" {
		t.Fatalf("failed binding %+v", st)
	}
	e.noLeak(t, "failed binding", st)
}

func TestStripeRotationMovesBindingAlongLineage(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	if st.State != pa.StateSucceeded {
		t.Fatalf("rotate %+v", st)
	}
	cur, _ := e.vault.Binding("STRIPE_WEBHOOK_SECRET")
	prev, ok := e.vault.Binding("STRIPE_WEBHOOK_SECRET_PREVIOUS")
	_, curRev := e.vault.Value("STRIPE_WEBHOOK_SECRET")
	_, prevRev := e.vault.Value("STRIPE_WEBHOOK_SECRET_PREVIOUS")
	if cur.Resource.EndpointID != st.Result.EndpointID || cur.Resource.Lineage != "we_old1" || cur.RecordRevision != curRev {
		t.Fatalf("record binding %+v", cur)
	}
	if !ok || prev.Kind != pa.KindStripeWebhookSecretPrevious || prev.Resource.Lineage != "we_old1" || prev.RecordRevision != prevRev || len(prev.AllowedDestinations) != 1 {
		t.Fatalf("previous binding %+v", prev)
	}
	// The next rotation names the new endpoint; the old one is refused.
	if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != pa.CodeBindingMismatch {
		t.Fatalf("rotation of the deleted endpoint: %q", code)
	}
	next := []byte(strings.Replace(string(stripeRotateParams(t)), "we_old1", st.Result.EndpointID, 1))
	if st2 := e.run(t, pa.ActionStripeWebhookRotate, next); st2.State != pa.StateSucceeded {
		t.Fatalf("second rotation %+v", st2)
	}
	e.noLeak(t, "rotate", st)
}

func TestDeletesRevokeBindingsButKeepRecords(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	e.vault.CreatedNeonProject("calm-sky-123456", "br-main-1")
	st := e.run(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "calm-sky-123456"}))
	if st.State != pa.StateSucceeded || strings.Join(st.Result.RevokedBindings, ",") != "DATABASE_URL,DATABASE_URL_UNPOOLED" {
		t.Fatalf("neon delete %+v", st)
	}
	if ok, _ := e.vault.Exists(context.Background(), "DATABASE_URL"); !ok {
		t.Fatal("delete removed the record")
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"DATABASE_URL": "DATABASE_URL"})); code != pa.CodeRecordNotBound {
		t.Fatalf("push after delete: %q", code)
	}
	if b, _ := e.vault.Binding("STRIPE_WEBHOOK_SECRET"); b.Revoked {
		t.Fatal("unrelated binding revoked")
	}
	// Stripe: rotate, then delete the current endpoint: the whole lineage ends.
	st = e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	endpoint := st.Result.EndpointID
	// Still deployed: refused until the env var is removed from Vercel.
	if code := e.prepareCode(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": endpoint})); code != pa.CodeResourceStillDeployed {
		t.Fatalf("delete of a deployed endpoint: %q", code)
	}
	if st := e.run(t, pa.ActionVercelEnvRemove, envRemove(t, "STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET", vercelRef("preview"))); st.State != pa.StateSucceeded {
		t.Fatalf("env remove %+v", st)
	}
	st = e.run(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": endpoint}))
	if st.State != pa.StateSucceeded || strings.Join(st.Result.RevokedBindings, ",") != "STRIPE_WEBHOOK_SECRET,STRIPE_WEBHOOK_SECRET_PREVIOUS" {
		t.Fatalf("stripe delete %+v", st)
	}
	// A failed provider delete revokes nothing.
	e = newEnv(t, nil)
	e.vault.CreatedNeonProject("calm-sky-123456", "br-main-1")
	e.fake.Fail = "neon.delete_project calm-sky-123456"
	st = e.run(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "calm-sky-123456"}))
	if b, _ := e.vault.Binding("DATABASE_URL"); st.State != pa.StateFailed || b.Revoked {
		t.Fatalf("failed delete revoked bindings: %+v", st)
	}
}

func TestBindingSaveFailureStopsRotationBeforePush(t *testing.T) {
	e := newEnv(t, nil)
	e.vault.FailBinding["DATABASE_URL"] = true
	st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
	if st.State != pa.StateFailed || st.Step != pa.StepBindingPending || len(e.fake.Pushed) != 0 || e.log.Index("neon.reset app_b") >= 0 || e.log.Index("neon.invalidate app_a") >= 0 {
		t.Fatalf("status %+v", st)
	}
	e.noLeak(t, "failed status", st)
}

// Bindings live in the vault, not in the service: a new service over the
// same vault (a broker restart) sees them.
func TestBindingsSurviveServiceRestart(t *testing.T) {
	e := newEnv(t, nil)
	st := e.run(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "WHSEC"}))
	if st.State != pa.StateSucceeded {
		t.Fatal(st)
	}
	e.run(t, pa.ActionBindingAllow, js(t, map[string]any{"records": []string{"WHSEC"}, "team_id": "team_abc123", "project_id": "prj_abc123"}))
	e.svc.Close()
	e.svc = pa.New(pa.Options{Vault: e.vault, Factory: e.fake, Clock: e.clock})
	t.Cleanup(e.svc.Close)
	if st := e.run(t, pa.ActionVercelEnvPush, pushParams(t, "prj_abc123", map[string]string{"STRIPE_WEBHOOK_SECRET": "WHSEC"})); st.State != pa.StateSucceeded {
		t.Fatalf("push after restart %+v", st)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushParams(t, "prj_other", map[string]string{"STRIPE_WEBHOOK_SECRET": "WHSEC"})); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("after restart: %q", code)
	}
}

func TestStoredBindingsAreValidatedStrictly(t *testing.T) {
	good := `{"v":1,"record":"DATABASE_URL","provider":"neon","kind":"neon.pooled","resource":{"project_id":"calm-sky-1","branch_id":"br-main-1"},"record_revision":3,"allowed_destinations":[{"team_id":"team_a","project_id":"prj_a"}]}`
	if _, err := pa.DecodeBinding([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"v":1`, `"v":2`, 1),
		strings.Replace(good, `"neon.pooled"`, `"stripe.webhook_secret"`, 1),
		strings.Replace(good, `"record":"DATABASE_URL"`, `"record":"CONTROL_NEON_API_KEY"`, 1),
		strings.Replace(good, `"record_revision":3`, `"record_revision":0`, 1),
		strings.Replace(good, `"prj_a"`, `"prj_a/../b"`, 1),
		strings.Replace(good, `]}`, `,{"team_id":"team_a","project_id":"prj_a"}]}`, 1),
		strings.Replace(good, `"allowed_destinations":[{"team_id":"team_a","project_id":"prj_a"}]`, `"allowed_destinations":null`, 1),
		strings.Replace(good, `}]}`, `}],"extra":1}`, 1),
		good + ` {}`,
	} {
		if _, err := pa.DecodeBinding([]byte(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}
