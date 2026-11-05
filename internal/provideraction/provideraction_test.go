package provideraction_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

const (
	owner = "session-a"
	scope = "grant:1"
)

type env struct {
	log      *provideractiontest.Log
	vault    *provideractiontest.Vault
	fake     *provideractiontest.Providers
	clock    *provideractiontest.Clock
	svc      *pa.Service
	controls []string // control-credential sentinels
}

func newEnv(t *testing.T, values map[string]string, opts ...func(*pa.Options)) *env {
	t.Helper()
	e := &env{log: &provideractiontest.Log{}, clock: &provideractiontest.Clock{T: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}}
	all := map[string]string{
		pa.ControlNeon:   provideractiontest.Sentinel("napi_"),
		pa.ControlVercel: provideractiontest.Sentinel("vcp_"),
		pa.ControlStripe: provideractiontest.Sentinel("rk_test_"),
	}
	for k, v := range all {
		e.controls = append(e.controls, v)
		_ = k
	}
	// The Neon rotation records exist, created by the broker (bound to the
	// project) and allowed to the default Vercel destination.
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		all[rec] = provideractiontest.Sentinel("postgresql://app_a:")
		e.controls = append(e.controls, all[rec])
	}
	for k, v := range values {
		all[k] = v
		e.controls = append(e.controls, v)
	}
	e.vault = provideractiontest.NewVault(e.log, all)
	dest := []pa.Destination{{TeamID: "team_abc123", ProjectID: "prj_abc123"}}
	neonRes := pa.BindingResource{ProjectID: "calm-sky-123456", BranchID: "br-main-1"}
	e.vault.Bind(pa.Binding{Record: "DATABASE_URL", Provider: pa.ProviderNeon, Kind: pa.KindNeonPooled, Resource: neonRes, AllowedDestinations: dest})
	e.vault.Bind(pa.Binding{Record: "DATABASE_URL_UNPOOLED", Provider: pa.ProviderNeon, Kind: pa.KindNeonDirect, Resource: neonRes, AllowedDestinations: dest})
	if _, ok := all["STRIPE_WEBHOOK_SECRET"]; ok {
		e.vault.Bind(pa.Binding{Record: "STRIPE_WEBHOOK_SECRET", Provider: pa.ProviderStripe, Kind: pa.KindStripeWebhookSecret,
			Resource: pa.BindingResource{EndpointID: "we_old1", Lineage: "we_old1"}, AllowedDestinations: dest})
	}
	e.fake = provideractiontest.NewProviders(e.log)
	o := pa.Options{Vault: e.vault, Factory: e.fake, Clock: e.clock}
	for _, f := range opts {
		f(&o)
	}
	e.svc = pa.New(o)
	t.Cleanup(e.svc.Close)
	return e
}

func js(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vercelRef(target string) map[string]any {
	m := map[string]any{"team_id": "team_abc123", "project_id": "prj_abc123", "target": target}
	if target == "production" {
		m["production"] = true
	}
	return m
}

func rotateParams(t *testing.T) json.RawMessage {
	return js(t, map[string]any{
		"project_id": "calm-sky-123456", "branch_id": "br-main-1", "roles": []string{"app_a", "app_b"}, "owner_role": "neondb_owner", "database": "appdb",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"},
		"vercel":  vercelRef("preview"), "health_path": "/api/health",
	})
}

func stripeRotateParams(t *testing.T) json.RawMessage {
	return js(t, map[string]any{
		"endpoint_id": "we_old1", "record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS",
		"vercel": vercelRef("preview"), "health_path": "/api/health",
	})
}

// run prepares and starts an action and waits for it to finish.
func (e *env) run(t *testing.T, action string, params json.RawMessage) pa.Status {
	t.Helper()
	prep, code := e.svc.Prepare(context.Background(), action, params)
	if code != "" {
		t.Fatalf("prepare %s: %s", action, code)
	}
	id, code := e.svc.Start(prep, owner, scope, nil)
	if code != "" {
		t.Fatalf("start: %s", code)
	}
	return e.wait(t, id)
}

func (e *env) wait(t *testing.T, id string) pa.Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, ok := e.svc.Status(owner, id)
		if !ok {
			t.Fatal("status not found")
		}
		if st.State == pa.StateSucceeded || st.State == pa.StateFailed {
			return st
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("operation did not finish")
	return pa.Status{}
}

// secrets returns every value an output must never contain.
func (e *env) secrets() []string {
	out := append([]string{e.fake.Secret}, e.controls...)
	return append(out, e.fake.IssuedSecrets()...)
}

func (e *env) noLeak(t *testing.T, what string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if leak := provideractiontest.Leak(b, e.secrets()...); leak != "" {
		t.Fatalf("%s leaked a value: %s", what, b)
	}
}

func TestParamValidationIsStrict(t *testing.T) {
	good := map[string]json.RawMessage{
		pa.ActionNeonProjectCreate:   js(t, map[string]any{"name": "throwaway-1", "region_id": "aws-us-east-2", "pg_version": 17, "records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}}),
		pa.ActionNeonProjectDelete:   js(t, map[string]any{"project_id": "calm-sky-123456"}),
		pa.ActionNeonRotate:          rotateParams(t),
		pa.ActionNeonRolesPrepare:    js(t, map[string]any{"project_id": "calm-sky-123456", "branch_id": "br-main-1", "database": "appdb", "owner_role": "neondb_owner", "adopt": true}),
		pa.ActionVercelProjectCreate: js(t, map[string]any{"team_id": "team_abc", "name": "throwaway-app", "git_repo": "owner/repo", "framework": "nextjs"}),
		pa.ActionVercelProjectDelete: js(t, map[string]any{"team_id": "team_abc", "project_id": "prj_abc"}),
		pa.ActionVercelEnvPush:       js(t, map[string]any{"team_id": "team_abc", "project_id": "prj_abc", "target": "preview", "git_branch": "feat/x", "variables": map[string]string{"DATABASE_URL": "DATABASE_URL"}}),
		pa.ActionVercelRedeploy:      js(t, map[string]any{"team_id": "team_abc", "project_id": "prj_abc", "target": "production", "production": true, "deployment": "dpl_abc"}),
		pa.ActionStripeWebhookCreate: js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "STRIPE_WEBHOOK_SECRET"}),
		pa.ActionStripeWebhookRotate: stripeRotateParams(t),
		pa.ActionStripeWebhookDelete: js(t, map[string]any{"endpoint_id": "we_abc"}),
		pa.ActionBindingAllow:        js(t, map[string]any{"records": []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"}, "team_id": "team_abc", "project_id": "prj_abc"}),
	}
	if len(good) != len(pa.Actions()) {
		t.Fatalf("every action needs a good case: %v", pa.Actions())
	}
	for action, params := range good {
		if _, ok := pa.Parse(action, params); !ok {
			t.Errorf("%s: valid params refused: %s", action, params)
		}
	}
	bad := []struct {
		action string
		params string
	}{
		{"neon.unknown", `{}`},
		{pa.ActionNeonProjectDelete, `{"project_id":"calm-sky-1","extra":1}`},                                               // unknown field
		{pa.ActionNeonProjectDelete, `{"project_id":"Calm_Sky"}`},                                                           // pattern
		{pa.ActionNeonProjectDelete, `{"project_id":"calm"} {"project_id":"x"}`},                                            // trailing data
		{pa.ActionNeonProjectDelete, `["calm"]`},                                                                            // not an object
		{pa.ActionNeonProjectDelete, ``},                                                                                    // empty
		{pa.ActionVercelProjectDelete, `{"team_id":"abc","project_id":"prj_abc"}`},                                          // team_ prefix
		{pa.ActionVercelProjectDelete, `{"team_id":"team_abc","project_id":"prj_a/../b"}`},                                  // pattern
		{pa.ActionVercelRedeploy, `{"team_id":"team_abc","project_id":"prj_abc","target":"production"}`},                    // production flag missing
		{pa.ActionVercelRedeploy, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","production":true}`},     // flag on preview
		{pa.ActionVercelRedeploy, `{"team_id":"team_abc","project_id":"prj_abc","target":"development"}`},                   // target
		{pa.ActionVercelRedeploy, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","deployment":"abc"}`},    // dpl_
		{pa.ActionVercelRedeploy, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","health_path":"/../x"}`}, // path
		{pa.ActionVercelEnvPush, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","variables":{"X":"CONTROL_VERCEL_TOKEN"}}`},
		{pa.ActionVercelEnvPush, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","variables":{"control_x":"DB"}}`},
		{pa.ActionVercelEnvPush, `{"team_id":"team_abc","project_id":"prj_abc","target":"preview","variables":{}}`},
		{pa.ActionVercelEnvPush, `{"team_id":"team_abc","project_id":"prj_abc","target":"production","production":true,"git_branch":"main","variables":{"A":"B"}}`},
		{pa.ActionStripeWebhookCreate, `{"url":"http://shop.example.com/x","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://user:pw@shop.example.com/x","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://127.0.0.1/x","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com:8443/x","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/x'y","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/` + strings.Repeat("a", 300) + `","events":["invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/x","events":[],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/x","events":["invoice.paid","invoice.paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/x","events":["Invoice Paid"],"record":"W"}`},
		{pa.ActionStripeWebhookCreate, `{"url":"https://shop.example.com/x","events":["invoice.paid"],"record":"CONTROL_STRIPE_KEY"}`},
		{pa.ActionStripeWebhookRotate, `{"endpoint_id":"we_a","record":"W","previous_record":"W","vercel":{"team_id":"team_a","project_id":"prj_a","target":"preview"},"health_path":"/"}`},
		{pa.ActionStripeWebhookDelete, `{"endpoint_id":"acct_abc"}`},
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"app_b"`, `"app_a"`, 1)},            // same role twice
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"br-main-1"`, `"main"`, 1)},         // br-
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"/api/health"`, `"api/health"`, 1)}, // path
		{pa.ActionNeonProjectCreate, `{"name":"x","pg_version":9,"records":{"pooled":"A","direct":"B"}}`},
		{pa.ActionNeonProjectCreate, `{"name":"x","roles":["app_a"],"records":{"pooled":"A","direct":"B"}}`},
		{pa.ActionNeonProjectCreate, `{"name":"x","roles":["app_a","envbank_app_owner"],"records":{"pooled":"A","direct":"B"}}`},
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"owner_role":"neondb_owner",`, ``, 1)},
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"neondb_owner"`, `"app_a"`, 1)},
		{pa.ActionNeonRotate, strings.Replace(string(rotateParams(t)), `"neondb_owner"`, `"envbank_app_owner"`, 1)},
		{pa.ActionNeonRolesPrepare, `{"project_id":"calm","branch_id":"br-x","database":"d","owner_role":"o","roles":["a","b","c"],"adopt":false}`},
		{pa.ActionNeonRolesPrepare, `{"project_id":"calm","branch_id":"br-x","database":"d","owner_role":"o","roles":["a","A"],"adopt":false}`},
		{pa.ActionNeonRolesPrepare, `{"project_id":"calm","branch_id":"br-x","database":"d","adopt":false}`},
		{pa.ActionNeonProjectCreate, `{"name":"x","records":{"pooled":"A","direct":"A"}}`},
		{pa.ActionVercelProjectCreate, `{"team_id":"team_abc","name":"UPPER"}`},
		{pa.ActionBindingAllow, `{"records":[],"team_id":"team_abc","project_id":"prj_abc"}`},
		{pa.ActionBindingAllow, `{"records":["A","A"],"team_id":"team_abc","project_id":"prj_abc"}`},
		{pa.ActionBindingAllow, `{"records":["CONTROL_VERCEL_TOKEN"],"team_id":"team_abc","project_id":"prj_abc"}`},
		{pa.ActionBindingAllow, `{"records":["A"],"team_id":"team_abc"}`},
		{pa.ActionBindingAllow, `{"records":["A"],"team_id":"team_abc","project_id":"prj_abc","target":"production"}`},
		{pa.ActionBindingAllow, `{"records":["A"],"team_id":"team_abc","project_id":"prj_abc","brokerCreated":true}`},
		{pa.ActionVercelProjectCreate, `{"team_id":"team_abc","name":"` + strings.Repeat("a", 101) + `"}`},
	}
	for _, c := range bad {
		if _, ok := pa.Parse(c.action, json.RawMessage(c.params)); ok {
			t.Errorf("%s: invalid params accepted: %s", c.action, c.params)
		}
	}
}

func TestPlanTextIsDeterministicAndNamesEverything(t *testing.T) {
	a, _ := pa.Parse(pa.ActionNeonRotate, rotateParams(t))
	b, _ := pa.Parse(pa.ActionNeonRotate, rotateParams(t))
	if a != b || a == "" {
		t.Fatalf("plan text not deterministic: %q %q", a, b)
	}
	for _, want := range []string{"ROTATE Neon role app_b to active", "calm-sky-123456", "br-main-1", "DATABASE_URL, DATABASE_URL_UNPOOLED", "Vercel prj_abc123 (team_abc123) preview", "redeploy from the current deployment", "/api/health", "then invalidate role app_a"} {
		if !strings.Contains(a, want) {
			t.Errorf("neon.rotate plan lacks %q: %s", want, a)
		}
	}
	if strings.Contains(a, "PRODUCTION") {
		t.Errorf("preview plan says PRODUCTION: %s", a)
	}
	var p map[string]any
	_ = json.Unmarshal(rotateParams(t), &p)
	p["vercel"] = vercelRef("production")
	prod, ok := pa.Parse(pa.ActionNeonRotate, js(t, p))
	if !ok || !strings.Contains(prod, "Vercel prj_abc123 (team_abc123) PRODUCTION") {
		t.Fatalf("production plan must say PRODUCTION: %s", prod)
	}
	s, _ := pa.Parse(pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	for _, want := range []string{"ROTATE Stripe webhook we_old1", "copy bound record STRIPE_WEBHOOK_SECRET to STRIPE_WEBHOOK_SECRET_PREVIOUS (bound as previous)", "push both to Vercel prj_abc123", "then delete we_old1"} {
		if !strings.Contains(s, want) {
			t.Errorf("stripe.webhook.rotate plan lacks %q: %s", want, s)
		}
	}
}

func TestNeonRotateHappyPathOrder(t *testing.T) {
	e := newEnv(t, nil)
	st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
	if st.State != pa.StateSucceeded || st.Code != "" {
		t.Fatalf("status %+v", st)
	}
	want := []string{
		"neon.roles_ready neondb_owner app_a,app_b",
		"neon.reset app_b",
		"vault.store DATABASE_URL",
		"vault.store DATABASE_URL_UNPOOLED",
		"vercel.upsert DATABASE_URL preview",
		"vercel.upsert DATABASE_URL_UNPOOLED preview",
		"vercel.current",
		"vercel.redeploy dpl_current",
		"vercel.wait_ready",
		"vercel.health /api/health",
		"vercel.health /api/health",
		"vercel.health /api/health",
		"neon.invalidate app_a",
	}
	if got := e.log.Calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("call order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	wantSteps := []string{pa.StepControl, pa.StepBindingCheck, pa.StepNeonCheckRoles, pa.StepNeonResetNewRole, pa.StepBindingSave, pa.StepVercelEnvPush, pa.StepVercelCurrent, pa.StepVercelRedeploy, pa.StepVercelWaitReady, pa.StepHealth, pa.StepNeonInvalidateOld}
	if strings.Join(st.Steps, ",") != strings.Join(wantSteps, ",") {
		t.Fatalf("steps %v", st.Steps)
	}
	// What was pushed is exactly what the vault durably holds.
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		v, rev := e.vault.Value(rec)
		if e.fake.Pushed[rec] != v || !strings.Contains(v, "app_b") || st.Result.Records[rec] != rev {
			t.Fatalf("%s: pushed value or revision does not match the vault", rec)
		}
	}
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		b, _ := e.vault.Binding(rec)
		if _, rev := e.vault.Value(rec); b.RecordRevision != rev || len(b.AllowedDestinations) != 1 || b.Resource.ProjectID != "calm-sky-123456" {
			t.Fatalf("%s binding not moved to the new value: %+v", rec, b)
		}
	}
	r := st.Result
	if r.ActiveRole != "app_b" || r.InvalidatedRole != "app_a" || r.DeploymentID == "" || r.Health == nil || r.Health.Checks < 3 || r.Health.WindowSeconds < 30 {
		t.Fatalf("result %+v", r)
	}
	e.noLeak(t, "status", st)
	// The control credentials were wiped after the action.
	for _, c := range e.fake.Creds {
		for _, b := range c {
			if b != 0 {
				t.Fatal("control credential buffer not wiped")
			}
		}
	}
}

// Failing at any step before health passed must never invalidate the old
// role, and must report the step; nothing is ever value-bearing.
func TestNeonRotateFailureAtEachStepKeepsOldRole(t *testing.T) {
	steps := map[string]string{
		"neon.roles_ready neondb_owner app_a,app_b":   pa.StepNeonCheckRoles,
		"neon.reset app_b":                            pa.StepNeonResetNewRole,
		"vercel.upsert DATABASE_URL preview":          pa.StepVercelEnvPush,
		"vercel.upsert DATABASE_URL_UNPOOLED preview": pa.StepVercelEnvPush,
		"vercel.current":                              pa.StepVercelCurrent,
		"vercel.redeploy dpl_current":                 pa.StepVercelRedeploy,
		"vercel.wait_ready":                           pa.StepVercelWaitReady,
		"vercel.health /api/health":                   pa.StepHealth,
	}
	for call, step := range steps {
		t.Run(call, func(t *testing.T) {
			e := newEnv(t, nil)
			e.fake.Fail = call
			st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
			if st.State != pa.StateFailed || st.Step != step || st.Code == "" {
				t.Fatalf("status %+v", st)
			}
			if e.log.Index("neon.invalidate app_a") >= 0 {
				t.Fatal("old role invalidated after a failure")
			}
			e.noLeak(t, "failed status", st)
		})
	}
	t.Run("roles not prepared", func(t *testing.T) {
		e := newEnv(t, nil)
		e.fake.RolesNotPrepared = true
		st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
		if st.State != pa.StateFailed || st.Step != pa.StepNeonCheckRoles || st.Code != pa.CodeRolesNotPrepared {
			t.Fatalf("status %+v", st)
		}
		if got := e.log.Calls(); len(got) != 1 || got[0] != "neon.roles_ready neondb_owner app_a,app_b" {
			t.Fatalf("side effects with unprepared roles: %v", got)
		}
	})
	t.Run("vault store fails", func(t *testing.T) {
		e := newEnv(t, nil)
		e.vault.FailStore["DATABASE_URL_UNPOOLED"] = true
		st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
		if st.State != pa.StateFailed || st.Step != pa.StepNeonResetNewRole {
			t.Fatalf("status %+v", st)
		}
		for _, c := range e.log.Calls() {
			if strings.HasPrefix(c, "vercel.") || strings.HasPrefix(c, "neon.invalidate") {
				t.Fatalf("destination written or old role invalidated before the value was stored: %v", e.log.Calls())
			}
		}
	})
	t.Run("invalidation fails after health", func(t *testing.T) {
		e := newEnv(t, nil)
		e.fake.Fail = "neon.invalidate app_a"
		st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
		if st.State != pa.StateFailed || st.Step != pa.StepNeonInvalidateOld || st.Code != pa.CodeProviderFailed || st.Result.ActiveRole != "app_b" {
			t.Fatalf("status %+v", st)
		}
		e.noLeak(t, "failed status", st)
	})
}

func TestStripeWebhookRotateOrder(t *testing.T) {
	old := provideractiontest.Sentinel("whsec_")
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": old})
	st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	if st.State != pa.StateSucceeded {
		t.Fatalf("status %+v", st)
	}
	want := []string{
		"stripe.webhook we_old1",
		"vault.store STRIPE_WEBHOOK_SECRET_PREVIOUS",
		"stripe.create",
		"vault.store STRIPE_WEBHOOK_SECRET",
		"vercel.upsert STRIPE_WEBHOOK_SECRET preview",
		"vercel.upsert STRIPE_WEBHOOK_SECRET_PREVIOUS preview",
		"vercel.current",
		"vercel.redeploy dpl_current",
		"vercel.wait_ready",
		"vercel.health /api/health",
		"vercel.health /api/health",
		"vercel.health /api/health",
		"stripe.delete we_old1",
	}
	if got := e.log.Calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("call order:\n%s", strings.Join(got, "\n"))
	}
	prev, _ := e.vault.Value("STRIPE_WEBHOOK_SECRET_PREVIOUS")
	cur, _ := e.vault.Value("STRIPE_WEBHOOK_SECRET")
	if prev != old || cur == old || !strings.HasPrefix(cur, "whsec_") || e.fake.Pushed["STRIPE_WEBHOOK_SECRET"] != cur || e.fake.Pushed["STRIPE_WEBHOOK_SECRET_PREVIOUS"] != old {
		t.Fatal("secrets not moved and pushed as planned")
	}
	if !strings.HasPrefix(st.Result.EndpointID, "we_new") || st.Result.DeletedEndpointID != "we_old1" {
		t.Fatalf("result %+v", st.Result)
	}
	e.noLeak(t, "status", st)
	b, _ := json.Marshal(st)
	if provideractiontest.Leak(b, old) != "" {
		t.Fatal("old webhook secret leaked")
	}
}

func TestStripeWebhookRotateFailureNeverDeletesOld(t *testing.T) {
	for _, call := range []string{"stripe.webhook we_old1", "stripe.create", "vercel.upsert STRIPE_WEBHOOK_SECRET preview", "vercel.redeploy dpl_current", "vercel.wait_ready", "vercel.health /api/health"} {
		t.Run(call, func(t *testing.T) {
			old := provideractiontest.Sentinel("whsec_")
			e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": old})
			e.fake.Fail = call
			st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
			if st.State != pa.StateFailed || st.Step == "" || st.Code == "" {
				t.Fatalf("status %+v", st)
			}
			if e.log.Index("stripe.delete we_old1") >= 0 {
				t.Fatal("old endpoint deleted after a failure")
			}
			if prev, _ := e.vault.Value("STRIPE_WEBHOOK_SECRET_PREVIOUS"); call != "stripe.webhook we_old1" && prev != old {
				t.Fatal("the secret in use was not kept in previous_record")
			}
			e.noLeak(t, "failed status", st)
		})
	}
}

func TestNeonProjectCreatePreparesRolesAndNeverStoresOwner(t *testing.T) {
	e := newEnv(t, nil)
	params := js(t, map[string]any{"name": "throwaway", "records": map[string]string{"pooled": "NEW_POOLED", "direct": "NEW_DIRECT"}})
	st := e.run(t, pa.ActionNeonProjectCreate, params)
	if st.State != pa.StateSucceeded || st.Result.ProjectID != "calm-sky-123456" || st.Result.ActiveRole != "app_a" || st.Result.Role != "neondb_owner" ||
		st.Result.Records["NEW_POOLED"] != 1 || strings.Join(st.Result.PreparedRoles, ",") != "app_a,app_b" {
		t.Fatalf("create %+v", st)
	}
	want := []string{"neon.create_project throwaway", "neon.prepare_roles neondb_owner app_a,app_b adopt=false", "neon.reset app_a", "vault.store NEW_POOLED", "vault.store NEW_DIRECT"}
	if got := e.log.Calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("call order:\n%s", strings.Join(got, "\n"))
	}
	for _, rec := range []string{"NEW_POOLED", "NEW_DIRECT"} {
		if v, _ := e.vault.Value(rec); !strings.HasPrefix(v, "postgresql://app_a:") || strings.Contains(v, "neondb_owner") {
			t.Fatalf("%s does not hold app_a's credentials only", rec)
		}
	}
	// The owner's password (the first issued secret) is in no record.
	owner := e.fake.IssuedSecrets()[0]
	for _, rec := range []string{"NEW_POOLED", "NEW_DIRECT", "discarded"} {
		if v, _ := e.vault.Value(rec); strings.Contains(v, owner) {
			t.Fatal("owner credentials persisted")
		}
	}
	e.noLeak(t, "create", st)

	// Custom roles; a failure after create still reports project_id.
	e = newEnv(t, nil)
	e.fake.Fail = "neon.prepare_roles neondb_owner app_x,app_y adopt=false"
	st = e.run(t, pa.ActionNeonProjectCreate, js(t, map[string]any{"name": "throwaway", "roles": []string{"app_x", "app_y"}, "records": map[string]string{"pooled": "P", "direct": "D"}}))
	if st.State != pa.StateFailed || st.Step != pa.StepNeonPrepareRoles || st.Result.ProjectID != "calm-sky-123456" {
		t.Fatalf("failed create %+v", st)
	}
	if ok, _ := e.vault.Exists(context.Background(), "P"); ok {
		t.Fatal("record written after a failed role preparation")
	}
	e.noLeak(t, "failed create", st)
}

func TestNeonRolesPrepare(t *testing.T) {
	params := map[string]any{"project_id": "calm-sky-123456", "branch_id": "br-main-1", "database": "appdb", "owner_role": "neondb_owner", "adopt": true}
	text, ok := pa.Parse(pa.ActionNeonRolesPrepare, js(t, params))
	if !ok || !strings.Contains(text, "CHANGE OWNERSHIP of all existing public-schema objects to envbank_app_owner") || !strings.Contains(text, "owner role neondb_owner") || !strings.Contains(text, "app_a, app_b") {
		t.Fatalf("adopt text: %s", text)
	}
	params["adopt"] = false
	text, _ = pa.Parse(pa.ActionNeonRolesPrepare, js(t, params))
	if strings.Contains(text, "CHANGE OWNERSHIP") || !strings.Contains(text, "existing public-schema objects keep their owners") {
		t.Fatalf("no-adopt text: %s", text)
	}
	e := newEnv(t, nil)
	params["adopt"], params["roles"] = true, []string{"web_a", "web_b"}
	st := e.run(t, pa.ActionNeonRolesPrepare, js(t, params))
	if st.State != pa.StateSucceeded || strings.Join(st.Result.PreparedRoles, ",") != "web_a,web_b" {
		t.Fatalf("prepare %+v", st)
	}
	if got := e.log.Calls(); len(got) != 1 || got[0] != "neon.prepare_roles neondb_owner web_a,web_b adopt=true" {
		t.Fatalf("calls %v", got)
	}
	e.noLeak(t, "prepare", st)
}

func TestOtherActionsAndPrechecks(t *testing.T) {
	e := newEnv(t, map[string]string{"EXISTING": provideractiontest.Sentinel("x_")})
	st := e.run(t, pa.ActionNeonProjectCreate, js(t, map[string]any{"name": "throwaway", "records": map[string]string{"pooled": "NEW_POOLED", "direct": "NEW_DIRECT"}}))
	if st.State != pa.StateSucceeded {
		t.Fatalf("create %+v", st)
	}
	st = e.run(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "WHSEC"}))
	if st.State != pa.StateSucceeded || !strings.HasPrefix(st.Result.EndpointID, "we_") {
		t.Fatalf("stripe create %+v", st)
	}
	e.noLeak(t, "stripe create", st)
	ctx := context.Background()
	push := js(t, map[string]any{"team_id": "team_a", "project_id": "prj_a", "target": "preview", "variables": map[string]string{"APP_KEY": "NEW_POOLED"}})
	if _, code := e.svc.Prepare(ctx, pa.ActionVercelEnvPush, push); code != pa.CodeDestinationNotAllowed {
		t.Fatalf("push before binding.allow: %q", code)
	}
	st = e.run(t, pa.ActionBindingAllow, js(t, map[string]any{"records": []string{"NEW_POOLED"}, "team_id": "team_a", "project_id": "prj_a"}))
	if st.State != pa.StateSucceeded {
		t.Fatalf("binding.allow %+v", st)
	}
	st = e.run(t, pa.ActionVercelEnvPush, push)
	if st.State != pa.StateSucceeded || st.Result.Variables["APP_KEY"] != "upserted" {
		t.Fatalf("env push %+v", st)
	}
	e.noLeak(t, "env push", st)
	// Prechecks refuse before anything happens.
	if _, code := e.svc.Prepare(ctx, pa.ActionVercelEnvPush, js(t, map[string]any{"team_id": "team_a", "project_id": "prj_a", "target": "preview", "variables": map[string]string{"APP_KEY": "EXISTING"}})); code != pa.CodeRecordNotBound {
		t.Fatalf("push of an owner-entered record: %q", code)
	}
	if _, code := e.svc.Prepare(ctx, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/x", "events": []string{"invoice.paid"}, "record": "EXISTING"})); code != pa.CodeRecordExists {
		t.Fatalf("overwrite by create: %q", code)
	}
	if _, code := e.svc.Prepare(ctx, pa.ActionVercelEnvPush, js(t, map[string]any{"team_id": "team_a", "project_id": "prj_a", "target": "preview", "variables": map[string]string{"A": "MISSING"}})); code != agentbroker.CodeUnknownSecret {
		t.Fatalf("push of a missing record: %q", code)
	}
	if _, code := e.svc.Prepare(ctx, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != agentbroker.CodeUnknownSecret {
		t.Fatalf("rotate of a missing record: %q", code)
	}
	bare := pa.New(pa.Options{Vault: provideractiontest.NewVault(nil, nil), Factory: e.fake})
	defer bare.Close()
	if _, code := bare.Prepare(ctx, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "abc"})); code != pa.CodeControlMissing {
		t.Fatalf("missing control credential: %q", code)
	}
	if _, code := pa.New(pa.Options{Vault: e.vault}).Prepare(ctx, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "abc"})); code != pa.CodeUnavailable {
		t.Fatalf("no factory: %q", code)
	}
}

func TestLiveStripeKeyRefused(t *testing.T) {
	e := newEnv(t, nil)
	live := provideractiontest.Sentinel("sk_live_")
	e.vault.Set(pa.ControlStripe, live)
	e.controls = append(e.controls, live)
	st := e.run(t, pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_abc"}))
	if st.State != pa.StateFailed || st.Step != pa.StepControl || st.Code != pa.CodeControlRefused || len(e.log.Calls()) != 0 {
		t.Fatalf("live key: %+v %v", st, e.log.Calls())
	}
	e.noLeak(t, "status", st)
}

func TestHealthNeedsThreeChecksOverThirtySeconds(t *testing.T) {
	e := newEnv(t, nil, func(o *pa.Options) { o.HealthInterval = 7 * time.Second })
	st := e.run(t, pa.ActionVercelRedeploy, js(t, map[string]any{"team_id": "team_a", "project_id": "prj_a", "target": "preview"}))
	if st.State != pa.StateSucceeded || st.Result.Health.Checks != 6 || st.Result.Health.WindowSeconds != 35 {
		t.Fatalf("health %+v", st.Result.Health)
	}
	e = newEnv(t, nil, func(o *pa.Options) { o.HealthInterval = time.Minute })
	st = e.run(t, pa.ActionVercelRedeploy, js(t, map[string]any{"team_id": "team_a", "project_id": "prj_a", "target": "preview"}))
	if st.Result.Health.Checks != 3 {
		t.Fatalf("at least 3 checks even when the window is passed: %+v", st.Result.Health)
	}
}

func TestSessionOwnershipOfStatus(t *testing.T) {
	e := newEnv(t, nil)
	prep, _ := e.svc.Prepare(context.Background(), pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "abc"}))
	id, _ := e.svc.Start(prep, owner, scope, nil)
	if len(id) != 32 || !pa.ValidOperationID(id) {
		t.Fatalf("operation id %q", id)
	}
	if _, ok := e.svc.Status("session-b", id); ok {
		t.Fatal("another session read the status")
	}
	if _, ok := e.svc.Status(owner, strings.Repeat("0", 32)); ok {
		t.Fatal("unknown id found")
	}
	e.wait(t, id)
}

func TestConcurrencyAndJournalBounds(t *testing.T) {
	e := newEnv(t, nil, func(o *pa.Options) { o.MaxRunning = 2; o.MaxJournal = 3 })
	e.fake.Block = make(chan struct{})
	params := js(t, map[string]any{"project_id": "abc"})
	ctx := context.Background()
	var ids []string
	for i := 0; i < 2; i++ {
		prep, code := e.svc.Prepare(ctx, pa.ActionNeonProjectDelete, params)
		if code != "" {
			t.Fatal(code)
		}
		id, _ := e.svc.Start(prep, owner, scope, nil)
		ids = append(ids, id)
	}
	if _, code := e.svc.Prepare(ctx, pa.ActionNeonProjectDelete, params); code != agentbroker.CodeBusy {
		t.Fatalf("third concurrent action: %q", code)
	}
	close(e.fake.Block)
	for _, id := range ids {
		e.wait(t, id)
	}
	e.fake.Block = nil
	// A released preparation frees its slot.
	prep, _ := e.svc.Prepare(ctx, pa.ActionNeonProjectDelete, params)
	prep.Release()
	prep.Release()
	for i := 0; i < 3; i++ {
		ids = append(ids, e.run(t, pa.ActionNeonProjectDelete, params).OperationID)
	}
	if _, ok := e.svc.Status(owner, ids[0]); ok {
		t.Fatal("journal not bounded: the oldest finished operation was kept")
	}
	if _, ok := e.svc.Status(owner, ids[len(ids)-1]); !ok {
		t.Fatal("newest operation evicted")
	}
}

func TestCloseAndEndScopeStopOperations(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.Block = make(chan struct{})
	ctx := context.Background()
	start := func(sc string) string {
		prep, code := e.svc.Prepare(ctx, pa.ActionNeonRotate, rotateParams(t))
		if code != "" {
			t.Fatal(code)
		}
		id, _ := e.svc.Start(prep, owner, sc, nil)
		return id
	}
	a := start("grant:a")
	e.svc.EndScope("grant:a")
	st := e.wait(t, a)
	if st.State != pa.StateFailed || st.Code != agentbroker.CodeNotAuthorized {
		t.Fatalf("ended scope: %+v", st)
	}
	b := start("grant:b")
	e.svc.Close()
	st, _ = e.svc.Status(owner, b)
	if st.State != pa.StateFailed || st.Code != agentbroker.CodeBrokerClosed {
		t.Fatalf("closed: %+v", st)
	}
	if e.log.Index("neon.invalidate app_a") >= 0 {
		t.Fatal("old role invalidated by a cancelled rotation")
	}
	if _, code := e.svc.Prepare(ctx, pa.ActionNeonRotate, rotateParams(t)); code != agentbroker.CodeBrokerClosed {
		t.Fatalf("after close: %q", code)
	}
}

func TestRevokedGrantStopsBeforeNextStep(t *testing.T) {
	e := newEnv(t, nil)
	valid := true
	e.fake.Fail = ""
	prep, _ := e.svc.Prepare(context.Background(), pa.ActionNeonRotate, rotateParams(t))
	calls := 0
	id, _ := e.svc.Start(prep, owner, scope, func() bool { calls++; return valid && calls < 3 })
	st := e.wait(t, id)
	if st.State != pa.StateFailed || st.Code != agentbroker.CodeNotAuthorized || e.log.Index("neon.invalidate app_a") >= 0 {
		t.Fatalf("status %+v", st)
	}
}
