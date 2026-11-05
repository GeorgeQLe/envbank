package authz

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// Realistic provider IDs at their usual lengths.
var (
	budgetTeam     = "team_" + strings.Repeat("a", 24)
	budgetTeam2    = "team_" + strings.Repeat("z", 24)
	budgetProject  = "prj_" + strings.Repeat("B", 28)
	budgetProject2 = "prj_" + strings.Repeat("C", 28)
	budgetNeon     = "polished-forest-12345678"
	budgetBranch   = "br-polished-forest-12345678"
	budgetEndpoint = "we_" + strings.Repeat("D", 24)
)

type budgetLayout struct {
	scopes []provideraction.DeployTarget
	// stripeFits: the Stripe plan (which also names the endpoint URL)
	// fits; when false it is refused PLAN_TOO_LONG before any prompt.
	stripeFits bool
}

// budgetLayouts are rotation scope sets of 1, 2 and maxRotationTargets (3)
// scopes: in one project, across two projects and across two teams, with
// realistic branch names.
func budgetLayouts() map[string]budgetLayout {
	prod := func(team, prj string) provideraction.DeployTarget {
		return provideraction.DeployTarget{TeamID: team, ProjectID: prj, Target: "production"}
	}
	prev := func(team, prj, branch string) provideraction.DeployTarget {
		return provideraction.DeployTarget{TeamID: team, ProjectID: prj, Target: "preview", GitBranch: branch}
	}
	return map[string]budgetLayout{
		"1 scope":           {[]provideraction.DeployTarget{prod(budgetTeam, budgetProject)}, true},
		"2 scopes":          {[]provideraction.DeployTarget{prev(budgetTeam, budgetProject, "main"), prod(budgetTeam, budgetProject)}, true},
		"2 scopes, 2 proj":  {[]provideraction.DeployTarget{prev(budgetTeam, budgetProject2, "main"), prod(budgetTeam, budgetProject)}, true},
		"3 scopes":          {[]provideraction.DeployTarget{prev(budgetTeam, budgetProject, "main"), prev(budgetTeam, budgetProject, "feature/checkout-v2"), prod(budgetTeam, budgetProject)}, true},
		"3 scopes, 2 proj":  {[]provideraction.DeployTarget{prev(budgetTeam, budgetProject, "feature/checkout-v2"), prod(budgetTeam, budgetProject), prev(budgetTeam, budgetProject2, "main")}, false},
		"3 scopes, 2 teams": {[]provideraction.DeployTarget{prev(budgetTeam, budgetProject, "main"), prod(budgetTeam, budgetProject), prev(budgetTeam2, budgetProject2, "main")}, false},
	}
}

// TestRotationApprovalBudget (finding H1): rotations of 1 to
// maxRotationTargets scopes, with realistic IDs, workspace and session,
// fit the Touch ID prompt with room for the agent label, which is clipped
// rather than making the approval fail. Every Neon layout fits; a Stripe
// plan spanning projects or teams does not (it also names the endpoint
// URL) and is refused PLAN_TOO_LONG, never clipped.
func TestRotationApprovalBudget(t *testing.T) {
	sess := Session{ID: "sess_" + strings.Repeat("k", 40), AgentKind: "claude", Workspace: "/Users/georgele/Developer/Projects/myapp",
		Label: strings.Repeat("Rotate the production database credentials now ", 2)[:80]}
	if err := sess.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, l := range budgetLayouts() {
		for _, action := range []string{provideraction.ActionNeonRotate, provideraction.ActionStripeWebhookRotate} {
			summary := budgetSummary(t, action, l.scopes)
			reason, code := providerReason(sess, summary)
			if action == provideraction.ActionStripeWebhookRotate && !l.stripeFits {
				if code != provideraction.CodePlanTooLong || reason != "" {
					t.Errorf("%s %s: %q (%d-byte plan): want PLAN_TOO_LONG", action, name, code, len(summary))
				}
				continue
			}
			if code != "" {
				t.Errorf("%s %s: %s (%d-byte plan): %s", action, name, code, len(summary), summary)
				continue
			}
			if len(reason) > approval.MaxReasonBytes || !strings.HasPrefix(reason, "perform a provider action: "+summary+", for "+sess.Ident()) {
				t.Errorf("%s %s: reason %d bytes: %s", action, name, len(reason), reason)
			}
			// The label is shown (at least its minimum), last.
			if !strings.Contains(reason, labelOpen+sess.Label[:minLabelRunes]) || !strings.HasSuffix(reason, labelClose) {
				t.Errorf("%s %s: label missing: %s", action, name, reason)
			}
			for _, want := range []string{"PRODUCTION", "PROMOTE", "ROLL BACK"} {
				if !strings.Contains(summary, want) {
					t.Errorf("%s %s: plan lacks %q: %s", action, name, want, summary)
				}
			}
			t.Logf("%s %s: plan %d bytes, reason %d of %d", action, name, len(summary), len(reason), approval.MaxReasonBytes)
		}
	}
	// More scopes than the maximum are refused by the params themselves.
	four := []any{}
	for _, b := range []string{"main", "staging", "feature/checkout-v2"} {
		four = append(four, map[string]any{"team_id": budgetTeam, "project_id": budgetProject, "target": "preview", "git_branch": b})
	}
	four = append(four, map[string]any{"team_id": budgetTeam, "project_id": budgetProject, "target": "production", "production": true})
	raw, _ := json.Marshal(map[string]any{"project_id": budgetNeon, "branch_id": budgetBranch, "owner_role": "neondb_owner", "database": "neondb",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}, "vercel": four, "health_path": "/api/health"})
	if _, ok := provideraction.Parse(provideraction.ActionNeonRotate, raw); ok {
		t.Error("a rotation of 4 scopes was accepted")
	}
}

// budgetSummary prepares action against a vault whose records are bound
// to the realistic resources and deployed to exactly scopes, and returns
// the approval plan text (with what precheck learned, e.g. the Stripe URL).
func budgetSummary(t *testing.T, action string, scopes []provideraction.DeployTarget) string {
	t.Helper()
	log := &provideractiontest.Log{}
	v := provideractiontest.NewVault(log, map[string]string{
		provideraction.ControlNeon:   provideractiontest.Sentinel("napi_"),
		provideraction.ControlVercel: provideractiontest.Sentinel("vcp_"),
		provideraction.ControlStripe: provideractiontest.Sentinel("rk_test_"),
		"DATABASE_URL":               provideractiontest.Sentinel("postgresql://app_a:"),
		"DATABASE_URL_UNPOOLED":      provideractiontest.Sentinel("postgresql://app_a:"),
		"STRIPE_WEBHOOK_SECRET":      provideractiontest.Sentinel("whsec_"),
	})
	var dests []provideraction.Destination
	seen := map[provideraction.Destination]bool{}
	deployed := func(env string) []provideraction.Deployed {
		var out []provideraction.Deployed
		for _, s := range scopes {
			out = append(out, provideraction.Deployed{DeployTarget: s, Env: env})
		}
		return out
	}
	var refs []any
	for _, s := range scopes {
		d := provideraction.Destination{TeamID: s.TeamID, ProjectID: s.ProjectID}
		if !seen[d] {
			seen[d] = true
			dests = append(dests, d)
		}
		ref := map[string]any{"team_id": s.TeamID, "project_id": s.ProjectID, "target": s.Target}
		if s.Target == "production" {
			ref["production"] = true
		} else {
			ref["git_branch"] = s.GitBranch
		}
		refs = append(refs, ref)
	}
	neonRes := provideraction.BindingResource{ProjectID: budgetNeon, BranchID: budgetBranch}
	for rec, kind := range map[string]string{"DATABASE_URL": provideraction.KindNeonPooled, "DATABASE_URL_UNPOOLED": provideraction.KindNeonDirect} {
		v.Bind(provideraction.Binding{Record: rec, Provider: provideraction.ProviderNeon, Kind: kind, Resource: neonRes, AllowedDestinations: dests,
			Roles: []string{"app_a", "app_b"}, ActiveRole: "app_a", DeployedTo: deployed(rec)})
	}
	v.Bind(provideraction.Binding{Record: "STRIPE_WEBHOOK_SECRET", Provider: provideraction.ProviderStripe, Kind: provideraction.KindStripeWebhookSecret,
		Resource: provideraction.BindingResource{EndpointID: budgetEndpoint, Lineage: budgetEndpoint}, AllowedDestinations: dests, DeployedTo: deployed("STRIPE_WEBHOOK_SECRET")})
	v.CreatedEndpoint(budgetEndpoint, budgetEndpoint)
	svc := provideraction.New(provideraction.Options{Vault: v, Factory: provideractiontest.NewProviders(log), Clock: &provideractiontest.Clock{T: time.Now()}})
	t.Cleanup(svc.Close)

	var params map[string]any
	if action == provideraction.ActionNeonRotate {
		params = map[string]any{"project_id": budgetNeon, "branch_id": budgetBranch, "owner_role": "neondb_owner", "database": "neondb",
			"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}}
	} else {
		params = map[string]any{"endpoint_id": budgetEndpoint, "record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS"}
	}
	params["vercel"], params["health_path"] = refs, "/api/health"
	raw, _ := json.Marshal(params)
	prep, code := svc.Prepare(context.Background(), action, raw)
	if code != "" {
		t.Fatalf("%s: prepare refused: %s", action, code)
	}
	defer prep.Release()
	return prep.Summary()
}
