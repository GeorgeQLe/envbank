package provideraction_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/approval"
	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
)

func prodRotateParams(t *testing.T) json.RawMessage {
	var p map[string]any
	_ = json.Unmarshal(rotateParams(t), &p)
	p["vercel"] = []any{vercelRef("production")}
	return js(t, p)
}

// Production approval texts say PRODUCTION, the staged redeploy, the
// promote and the automatic rollback, and fit the Touch ID prompt with
// realistic IDs and room for the session label.
func TestProductionApprovalTexts(t *testing.T) {
	long := map[string]any{"team_id": "team_" + strings.Repeat("a", 24), "project_id": "prj_" + strings.Repeat("B", 28), "target": "production", "production": true}
	cases := map[string]json.RawMessage{
		pa.ActionVercelRedeploy: js(t, map[string]any{"team_id": long["team_id"], "project_id": long["project_id"], "target": "production", "production": true,
			"deployment": "dpl_" + strings.Repeat("C", 24), "health_path": "/api/health"}),
		pa.ActionNeonRotate: js(t, map[string]any{"project_id": "polished-forest-12345678", "branch_id": "br-polished-forest-12345678", "roles": []string{"app_a", "app_b"}, // as derived
			"owner_role": "neondb_owner", "database": "neondb", "records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"},
			"vercel": []any{long}, "health_path": "/api/health"}),
		pa.ActionStripeWebhookRotate: js(t, map[string]any{"endpoint_id": "we_" + strings.Repeat("D", 24), "record": "STRIPE_WEBHOOK_SECRET",
			"previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS", "vercel": []any{long}, "health_path": "/api/health"}),
	}
	ident := "claude agent session 3f2a9c1e in workspace ws-main"
	for action, params := range cases {
		text, ok := pa.Parse(action, params)
		if !ok {
			t.Fatalf("%s: params refused", action)
		}
		wants := []string{"PRODUCTION", "STAGED", "/api/health", "PROMOTE", "auto ROLL BACK on failure"}
		if action == pa.ActionVercelRedeploy {
			wants = append(wants, "check health at /api/health", "verify production serves it and recheck", "must be dpl_")
		}
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s plan lacks %q: %s", action, want, text)
			}
		}
		// As authz renders it: the label last, in fixed delimiters.
		reason := "perform a provider action: " + text + ", for " + ident + `; [agent label: "Rotate prod"]`
		if len(reason) > approval.MaxReasonBytes {
			t.Errorf("%s: %d-byte plan does not fit with its label: %s", action, len(text), reason)
		}
	}
	// Preview wording is unchanged.
	if a, _ := pa.Parse(pa.ActionNeonRotate, rotateParams(t)); strings.Contains(a, "PROMOTE") || strings.Contains(a, "ROLL BACK") {
		t.Errorf("preview plan mentions promotion: %s", a)
	}
}

func TestProductionNeonRotateOrder(t *testing.T) {
	e := newEnv(t, nil)
	st := e.run(t, pa.ActionNeonRotate, prodRotateParams(t))
	if st.State != pa.StateSucceeded {
		t.Fatalf("status %+v", st)
	}
	want := []string{
		"neon.database_owner appdb",
		"vercel.env_present production",
		"neon.database_owner appdb",
		"neon.roles_ready neondb_owner app_a,app_b",
		"vercel.current", // the deployment serving production: the rollback target
		"neon.reset app_b",
		"vault.store DATABASE_URL",
		"vault.store DATABASE_URL_UNPOOLED",
		"vercel.env_present production",
		"vercel.upsert DATABASE_URL production",
		"vercel.upsert DATABASE_URL_UNPOOLED production",
		"vercel.redeploy dpl_current",
		"vercel.wait_ready",
		"vercel.health /api/health", "vercel.health /api/health", "vercel.health /api/health",
		"vercel.current", // still the previous deployment
		"vercel.promote dpl_new0001",
		"vercel.current", // proven serving the new deployment
		"vercel.health /api/health", "vercel.health /api/health", "vercel.health /api/health",
		"vercel.current", // confirmed again before the invalidation
		"neon.invalidate app_a",
	}
	if got := e.log.Calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("call order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	wantSteps := []string{pa.StepControl, pa.StepBindingCheck, pa.StepNeonCheckRoles, pa.StepVercelCurrent, pa.StepBindingPending, pa.StepNeonResetNewRole, pa.StepBindingSave,
		pa.StepVercelEnvPush, pa.StepVercelRedeploy, pa.StepVercelWaitReady, pa.StepHealth, pa.StepVercelPromote, pa.StepVercelVerifyProduction,
		pa.StepHealthProduction, pa.StepVercelConfirmProduction, pa.StepNeonInvalidateOld, pa.StepBindingFinish}
	if strings.Join(st.Steps, ",") != strings.Join(wantSteps, ",") {
		t.Fatalf("steps %v", st.Steps)
	}
	r := st.Result
	if r.PreviousDeploymentID != "dpl_current" || r.DeploymentID != "dpl_new0001" || !r.Promoted || !r.ProductionVerified || r.RolledBack || r.Rollback != "" ||
		r.Health == nil || r.ProductionHealth == nil || r.ProductionHealth.Checks < 3 || r.InvalidatedRole != "app_a" || e.fake.Production() != "dpl_new0001" {
		t.Fatalf("result %+v", r)
	}
	raw, _ := json.Marshal(r)
	for _, field := range []string{`"previous_deployment_id":"dpl_current"`, `"promoted":true`, `"production_verified":true`, `"production_health":{`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("result JSON lacks %s: %s", field, raw)
		}
	}
	e.noLeak(t, "status", st)
}

// Failures at and after the promote never invalidate the old role; the
// outcome of the recovery is reported.
func TestProductionFailuresKeepOldRole(t *testing.T) {
	cases := []struct {
		name, fail string
		stuck      bool
		step, code string
		rollback   string
	}{
		{name: "promote refused", fail: "vercel.promote dpl_new0001", step: pa.StepVercelPromote, code: pa.CodeProviderFailed, rollback: pa.RollbackNotNeeded},
		{name: "never serving", stuck: true, step: pa.StepVercelVerifyProduction, code: pa.CodeProductionNotServing, rollback: pa.RollbackNotNeeded},
		{name: "pushed env", fail: "vercel.upsert DATABASE_URL production", step: pa.StepVercelEnvPush, code: pa.CodeProviderFailed},
		{name: "baseline", fail: "vercel.current", step: pa.StepVercelCurrent, code: pa.CodeProviderFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.fake.Fail, e.fake.StuckPromotion = c.fail, c.stuck
			st := e.run(t, pa.ActionNeonRotate, prodRotateParams(t))
			if st.State != pa.StateFailed || st.Step != c.step || st.Code != c.code || st.Result.Rollback != c.rollback || st.Result.RolledBack {
				t.Fatalf("status %+v result %+v", st, st.Result)
			}
			if e.log.Index("neon.invalidate app_a") >= 0 || e.log.Index("vercel.rollback dpl_current") >= 0 || e.fake.Production() != "dpl_current" {
				t.Fatalf("old role invalidated or production changed: %v", e.log.Calls())
			}
			if c.step == pa.StepVercelCurrent && e.log.Index("neon.reset app_b") >= 0 {
				t.Fatal("a side effect before production was read")
			}
			e.noLeak(t, "failed status", st)
		})
	}
	t.Run("production health fails after the promote", func(t *testing.T) {
		e := newEnv(t, nil)
		// The fourth health call is the first one after the promote.
		e.fake.FailAfter = map[string]int{"vercel.health /api/health": 4}
		st := e.run(t, pa.ActionNeonRotate, prodRotateParams(t))
		if st.State != pa.StateFailed || st.Step != pa.StepHealthProduction || st.Code != pa.CodeHealthFailed ||
			!st.Result.RolledBack || st.Result.Rollback != pa.RollbackDone || e.fake.Production() != "dpl_current" {
			t.Fatalf("status %+v result %+v", st, st.Result)
		}
		if e.log.Index("vercel.rollback dpl_current") < e.log.Index("vercel.promote dpl_new0001") || e.log.Index("neon.invalidate app_a") >= 0 {
			t.Fatalf("calls %v", e.log.Calls())
		}
		e.noLeak(t, "failed status", st)
	})
}
