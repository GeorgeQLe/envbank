package live

import (
	"encoding/json"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
)

// End-to-end checks for the security-review fixes, through authz.Gate and
// the real adapters against the loopback fakes.

// A branch-scoped preview redeploy rebuilds that branch's newest deployment,
// and the port proves the branch itself: a list that ignored the branch
// filter is refused, never trusted.
func TestBranchScopedPreviewRedeploy(t *testing.T) {
	h := newHarness(t, Config{})
	h.grant(provideraction.Actions()...)
	team := h.fx.team
	project := h.mustSucceed(provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-branches"}).ProjectID
	mainDep := h.fx.vercel.seedPreview(project, "main")
	h.fx.vercel.seedPreview(project, "feat-x") // newer, another branch
	params := map[string]any{"team_id": team, "project_id": project, "target": "preview", "git_branch": "main", "health_path": "/api/health"}
	rd := h.mustSucceed(provideraction.ActionVercelRedeploy, params)
	h.fx.vercel.mu.Lock()
	got := h.fx.vercel.deps[rd.DeploymentID]
	h.fx.vercel.mu.Unlock()
	if got == nil || got.branch != "main" || got.meta[vercel.MetaSourceKey] != mainDep {
		t.Fatalf("redeployed %+v, want a rebuild of %s", got, mainDep)
	}
	h.fx.vercel.seedPreview(project, "feat-x") // newest again
	h.fx.vercel.mu.Lock()
	h.fx.vercel.ignoreBranchFilter = true
	h.fx.vercel.mu.Unlock()
	r := h.act(provideraction.ActionVercelRedeploy, params)
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepVercelCurrent {
		t.Fatalf("unfiltered list: %+v", r.resp)
	}
}

// Rotations are refused before the prompt unless they cover every scope
// the records were deployed to; a covering rotation rewrites them all.
func TestRotationScopeEndToEnd(t *testing.T) {
	p := newProdFixture(t) // records pushed to production of p.project
	h := p.h
	preview := map[string]any{"team_id": h.fx.team, "project_id": p.project, "target": "preview", "git_branch": "main"}
	push := map[string]any{"team_id": h.fx.team, "project_id": p.project, "target": "preview", "git_branch": "main",
		"variables": map[string]string{"DATABASE_URL": "DATABASE_URL", "DATABASE_URL_UNPOOLED": "DATABASE_URL_UNPOOLED"}}
	h.mustSucceed(provideraction.ActionVercelEnvPush, push)
	args := map[string]any{}
	for k, v := range p.rotateArgs {
		args[k] = v
	}
	args["vercel"] = []any{preview}
	before := len(h.own.approvals())
	r := h.call(map[string]any{"op": "provider_action", "action": provideraction.ActionNeonRotate, "params": args})
	if r.OK || r.Code != provideraction.CodeRotationScopeIncomplete || len(h.own.approvals()) != before {
		t.Fatalf("preview-only rotation: %+v", r)
	}
	args["vercel"] = []any{p.vercel(), preview}
	rot := h.mustSucceed(provideraction.ActionNeonRotate, args)
	appB := value(h.vault, "DATABASE_URL")
	if len(rot.Redeployed) != 2 || rot.Redeployed[1].Target != "production" || !rot.ProductionVerified || rot.InvalidatedRole != "app_a" ||
		h.fx.vercel.envValueIn(p.project, "DATABASE_URL", "production") != appB || h.fx.vercel.envValueAt(p.project, "DATABASE_URL", "preview", "main") != appB {
		t.Fatalf("rotation %+v", rot)
	}
	p.noLeaks(t)
}

// A Stripe rotation re-run over an unfinished one is refused before the
// prompt, and the refusal names the endpoint to clean up.
func TestStripeOrphanRefusalNamesTheEndpoint(t *testing.T) {
	h := newHarness(t, Config{})
	h.grant(provideraction.Actions()...)
	team := h.fx.team
	project := h.mustSucceed(provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-stripe"}).ProjectID
	first := h.mustSucceed(provideraction.ActionStripeWebhookCreate, map[string]any{"url": "https://envbank-e2e-stripe.vercel.app/api/stripe",
		"events": []string{"invoice.paid"}, "record": "STRIPE_WEBHOOK_SECRET"}).EndpointID
	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"STRIPE_WEBHOOK_SECRET"}, "team_id": team, "project_id": project})
	preview := []any{map[string]any{"team_id": team, "project_id": project, "target": "preview", "git_branch": "main"}}
	rotate := func(endpoint string) map[string]any {
		return map[string]any{"endpoint_id": endpoint, "record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS",
			"vercel": preview, "health_path": "/api/health"}
	}
	h.fx.vercel.mu.Lock()
	h.fx.vercel.protect = true // health fails: the rotation stops before deleting the old endpoint
	h.fx.vercel.mu.Unlock()
	r := h.act(provideraction.ActionStripeWebhookRotate, rotate(first))
	if r.resp.State != provideraction.StateFailed || r.res.EndpointID == "" {
		t.Fatalf("interrupted %+v", r.resp)
	}
	second := r.res.EndpointID
	h.fx.vercel.mu.Lock()
	h.fx.vercel.protect = false
	h.fx.vercel.mu.Unlock()
	before := len(h.own.approvals())
	resp := h.call(map[string]any{"op": "provider_action", "action": provideraction.ActionStripeWebhookRotate, "params": rotate(second)})
	var detail provideraction.Result
	if resp.OK || resp.Code != provideraction.CodeStripeOrphanEndpoint || json.Unmarshal(resp.Result, &detail) != nil || detail.OrphanEndpointID != first ||
		len(h.own.approvals()) != before {
		t.Fatalf("orphan refusal: %+v (%s)", resp, resp.Result)
	}
	if h.fx.stripe.endpoint(first).deleted {
		t.Fatal("orphan deleted without approval")
	}
}
