package live

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// prodFixture is a Vercel project whose verified production domain serves a
// promoted deployment built with app_a's URIs, and a Neon project with
// bound records allowed to it.
type prodFixture struct {
	h          *harness
	project    string
	np         provideraction.Result
	previous   string // the seeded production deployment
	appA       string // DATABASE_URL production uses now
	rotateArgs map[string]any
}

func (p *prodFixture) vercel() map[string]any {
	return map[string]any{"team_id": p.h.fx.team, "project_id": p.project, "target": "production", "production": true}
}

func newProdFixture(t *testing.T) *prodFixture {
	h := newHarness(t, Config{})
	h.grant(provideraction.Actions()...)
	team := h.fx.team
	p := &prodFixture{h: h}
	p.project = h.mustSucceed(provideraction.ActionVercelProjectCreate, map[string]any{"team_id": team, "name": "envbank-e2e-prod"}).ProjectID
	p.np = h.mustSucceed(provideraction.ActionNeonProjectCreate, map[string]any{"name": "envbank-e2e-db",
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"}})
	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"}, "team_id": team, "project_id": p.project})
	push := p.vercel()
	push["variables"] = map[string]string{"DATABASE_URL": "DATABASE_URL", "DATABASE_URL_UNPOOLED": "DATABASE_URL_UNPOOLED"}
	h.mustSucceed(provideraction.ActionVercelEnvPush, push)
	p.appA = value(h.vault, "DATABASE_URL")
	if h.fx.vercel.envValueIn(p.project, "DATABASE_URL", "production") != p.appA {
		t.Fatal("production env not pushed")
	}
	p.previous = h.fx.vercel.seedProduction(p.project, "app.envbank-e2e.example.com")
	p.rotateArgs = map[string]any{"project_id": p.np.ProjectID, "branch_id": p.np.BranchID,
		"roles": []string{"app_a", "app_b"}, "owner_role": p.np.Role, "database": p.np.Database,
		"records": map[string]string{"pooled": "DATABASE_URL", "direct": "DATABASE_URL_UNPOOLED"},
		"vercel":  []any{p.vercel()}, "health_path": "/api/health"}
	return p
}

// noLeaks scans every owner-facing text and the health requests.
func (p *prodFixture) noLeaks(t *testing.T) {
	t.Helper()
	if leak := provideractiontest.Leak([]byte(p.h.own.texts()), p.h.secrets()...); leak != "" {
		t.Fatal("owner-facing text leaked a value")
	}
	for _, r := range p.h.fx.vercel.healthReqs {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("x-vercel-protection-bypass") != "" || !strings.HasSuffix(r.URL.Host, ".vercel.app") {
			t.Fatalf("health request carried credentials or left vercel.app: %v", r.URL)
		}
	}
}

// oldRoleKept checks a failed production rotation left app_a valid.
func (p *prodFixture) oldRoleKept(t *testing.T, mark int, res provideraction.Result) {
	t.Helper()
	for _, e := range p.h.fx.ev.list()[mark:] {
		if e == "neon.reset app_a" {
			t.Fatalf("the old role was invalidated: %v", p.h.fx.ev.list()[mark:])
		}
	}
	if !p.h.fx.neon.validURI(p.appA) || res.InvalidatedRole != "" {
		t.Fatal("the old role's URI is no longer valid")
	}
}

func (p *prodFixture) rotate() result { return p.h.act(provideraction.ActionNeonRotate, p.rotateArgs) }

func after(all []string, from int, prefix string) int {
	for i := from + 1; i < len(all); i++ {
		if strings.HasPrefix(all[i], prefix) {
			return i
		}
	}
	return -1
}

// Production rotation: staged redeploy, health on it, promote, proof that
// production serves it, health again, and only then is app_a invalidated.
func TestProductionNeonRotation(t *testing.T) {
	p := newProdFixture(t)
	h := p.h
	h.fx.vercel.mu.Lock()
	h.fx.vercel.aliasDelay = 2 // the promote's alias job runs for two project reads
	h.fx.vercel.mu.Unlock()
	mark := len(h.fx.ev.list())
	rot := h.mustSucceed(provideraction.ActionNeonRotate, p.rotateArgs)
	if rot.ActiveRole != "app_b" || rot.InvalidatedRole != "app_a" || !rot.Promoted || !rot.ProductionVerified || rot.RolledBack || rot.Rollback != "" ||
		rot.PreviousDeploymentID != p.previous || rot.Health == nil || rot.ProductionHealth == nil || rot.ProductionHealth.Checks < provideraction.MinHealthChecks {
		t.Fatalf("rotate result %+v", rot)
	}
	appB := value(h.vault, "DATABASE_URL")
	if h.fx.vercel.production(p.project) != rot.DeploymentID || h.fx.vercel.snapshot(rot.DeploymentID, "DATABASE_URL") != appB ||
		h.fx.vercel.envValueIn(p.project, "DATABASE_URL", "production") != appB {
		t.Fatal("production does not serve the deployment built with app_b")
	}
	if h.fx.neon.validURI(p.appA) || !h.fx.neon.validURI(appB) {
		t.Fatal("app_a still valid or app_b not")
	}
	all := h.fx.ev.list()
	resetNew := after(all, mark-1, "neon.reset app_b")
	push := after(all, resetNew, "vercel.env DATABASE_URL")
	deploy := after(all, push, "vercel.deploy "+rot.DeploymentID)
	staged := after(all, deploy, "health "+rot.DeploymentID+" 200")
	promote := after(all, staged, "vercel.promote "+rot.DeploymentID)
	verified := after(all, promote, "vercel.alias "+rot.DeploymentID)
	prodHealth := after(all, verified, "health "+rot.DeploymentID+" 200")
	resetOld := after(all, prodHealth, "neon.reset app_a")
	if resetNew < 0 || push < 0 || deploy < 0 || staged < 0 || promote < 0 || verified < 0 || prodHealth < 0 || resetOld < 0 {
		t.Fatalf("production rotation order wrong: %v", all[mark:])
	}
	// The staged checks all ran before the promote.
	n := 0
	for _, e := range all[deploy:promote] {
		if e == "health "+rot.DeploymentID+" 200" {
			n++
		}
	}
	if n < provideraction.MinHealthChecks {
		t.Fatalf("%d staged health checks before the promote", n)
	}
	a := h.own.approvals()
	text := a[len(a)-1]
	for _, want := range []string{"PRODUCTION", "STAGED redeploy", "PROMOTE", "verify production serves it", "auto ROLL BACK on failure", "then invalidate role app_a"} {
		if !strings.Contains(text, want) {
			t.Errorf("approval lacks %q: %s", want, text)
		}
	}
	if !strings.HasSuffix(text, `; [agent label: "E2E provider actions"]`) {
		t.Errorf("label dropped from a production approval: %s", text)
	}
	p.noLeaks(t)
}

// The promote request fails after Vercel moved the alias: production is
// rolled back and app_a stays valid.
func TestProductionPromoteFailureRollsBack(t *testing.T) {
	p := newProdFixture(t)
	h := p.h
	h.fx.vercel.mu.Lock()
	h.fx.vercel.promoteError = true
	h.fx.vercel.mu.Unlock()
	mark := len(h.fx.ev.list())
	r := p.rotate()
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepVercelPromote || r.resp.Code != provideraction.CodeProviderFailed {
		t.Fatalf("status %+v", r.resp)
	}
	if r.res.Promoted || !r.res.RolledBack || r.res.Rollback != provideraction.RollbackDone || r.res.PreviousDeploymentID != p.previous {
		t.Fatalf("result %+v", r.res)
	}
	if h.fx.ev.last("vercel.rollback "+p.previous) < mark || h.fx.vercel.production(p.project) != p.previous {
		t.Fatalf("not rolled back: %v", h.fx.ev.list()[mark:])
	}
	if !contains(r.resp.Steps, provideraction.StepVercelRollback) {
		t.Fatalf("steps %v", r.resp.Steps)
	}
	p.oldRoleKept(t, mark, r.res)
	p.noLeaks(t)
}

// Production verification fails after the promote (the new deployment is
// unhealthy once it serves production): rolled back, app_a stays valid.
func TestProductionVerifyFailureRollsBack(t *testing.T) {
	p := newProdFixture(t)
	h := p.h
	h.fx.vercel.mu.Lock()
	h.fx.vercel.failWhileServing = true
	h.fx.vercel.mu.Unlock()
	mark := len(h.fx.ev.list())
	r := p.rotate()
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepHealthProduction || r.resp.Code != provideraction.CodeHealthFailed {
		t.Fatalf("status %+v", r.resp)
	}
	if !r.res.Promoted || !r.res.ProductionVerified || !r.res.RolledBack || r.res.Rollback != provideraction.RollbackDone {
		t.Fatalf("result %+v", r.res)
	}
	if h.fx.vercel.production(p.project) != p.previous || h.fx.ev.last("vercel.rollback "+p.previous) < h.fx.ev.last("vercel.promote "+r.res.DeploymentID) {
		t.Fatalf("not rolled back: %v", h.fx.ev.list()[mark:])
	}
	p.oldRoleKept(t, mark, r.res)
	// The previous deployment serves production again, and is healthy.
	h.fx.vercel.mu.Lock()
	prev := h.fx.vercel.deps[p.previous]
	h.fx.vercel.mu.Unlock()
	if !h.fx.vercel.healthy(prev) {
		t.Fatal("the restored deployment's credentials are no longer valid")
	}
	p.noLeaks(t)
}

// The promote's alias job fails (aliases never move): the proof times out,
// production was never left, and app_a stays valid.
func TestProductionNotServingKeepsOldCredential(t *testing.T) {
	p := newProdFixture(t)
	h := p.h
	h.fx.vercel.mu.Lock()
	h.fx.vercel.promoteJobFails = true
	h.fx.vercel.mu.Unlock()
	mark := len(h.fx.ev.list())
	r := p.rotate()
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepVercelVerifyProduction || r.resp.Code != provideraction.CodeProductionNotServing {
		t.Fatalf("status %+v", r.resp)
	}
	if !r.res.Promoted || r.res.ProductionVerified || r.res.RolledBack || r.res.Rollback != provideraction.RollbackNotNeeded {
		t.Fatalf("result %+v", r.res)
	}
	if h.fx.ev.last("vercel.rollback") >= 0 || h.fx.vercel.production(p.project) != p.previous {
		t.Fatal("unexpected rollback or production moved")
	}
	p.oldRoleKept(t, mark, r.res)
	p.noLeaks(t)
}

// A standalone production vercel.redeploy promotes after the staged health
// checks; a failure before the promote leaves production untouched; and a
// production Stripe rotation deletes the old endpoint only after production
// serves the new secret.
func TestProductionRedeployAndStripeRotation(t *testing.T) {
	p := newProdFixture(t)
	h := p.h
	rd := p.vercel()
	rd["health_path"] = "/api/health"
	res := h.mustSucceed(provideraction.ActionVercelRedeploy, rd)
	if !res.Promoted || !res.ProductionVerified || res.PreviousDeploymentID != p.previous || h.fx.vercel.production(p.project) != res.DeploymentID ||
		res.Health == nil || res.ProductionHealth == nil {
		t.Fatalf("redeploy result %+v", res)
	}
	a := h.own.approvals()
	for _, want := range []string{"REDEPLOY Vercel " + p.project + " (" + h.fx.team + ") PRODUCTION from the current deployment as STAGED, check health at /api/health, PROMOTE",
		"auto ROLL BACK on failure"} {
		if !strings.Contains(a[len(a)-1], want) {
			t.Errorf("approval lacks %q: %s", want, a[len(a)-1])
		}
	}
	current := res.DeploymentID

	// Before the promote: protection fails the staged health check, and
	// production is untouched.
	h.fx.vercel.mu.Lock()
	h.fx.vercel.protect = true
	h.fx.vercel.mu.Unlock()
	mark := len(h.fx.ev.list())
	r := h.act(provideraction.ActionVercelRedeploy, rd)
	if r.resp.State != provideraction.StateFailed || r.resp.Step != provideraction.StepHealth || r.resp.Code != provideraction.CodeHealthProtected ||
		r.res.Promoted || r.res.Rollback != "" || h.fx.vercel.production(p.project) != current || after(h.fx.ev.list(), mark-1, "vercel.promote") >= 0 {
		t.Fatalf("pre-promote failure touched production: %+v %+v", r.resp, r.res)
	}
	h.fx.vercel.mu.Lock()
	h.fx.vercel.protect = false
	h.fx.vercel.mu.Unlock()

	// Stripe rotation on production.
	wc := h.mustSucceed(provideraction.ActionStripeWebhookCreate, map[string]any{"url": "https://app.envbank-e2e.example.com/api/stripe",
		"events": []string{"invoice.paid"}, "record": "STRIPE_WEBHOOK_SECRET"})
	h.mustSucceed(provideraction.ActionBindingAllow, map[string]any{"records": []string{"STRIPE_WEBHOOK_SECRET"}, "team_id": h.fx.team, "project_id": p.project})
	sr := h.mustSucceed(provideraction.ActionStripeWebhookRotate, map[string]any{"endpoint_id": wc.EndpointID,
		"record": "STRIPE_WEBHOOK_SECRET", "previous_record": "STRIPE_WEBHOOK_SECRET_PREVIOUS", "vercel": []any{p.vercel()}, "health_path": "/api/health"})
	if !sr.Promoted || !sr.ProductionVerified || sr.DeletedEndpointID != wc.EndpointID || sr.PreviousDeploymentID != current ||
		h.fx.vercel.production(p.project) != sr.DeploymentID || h.fx.vercel.snapshot(sr.DeploymentID, "STRIPE_WEBHOOK_SECRET") != value(h.vault, "STRIPE_WEBHOOK_SECRET") {
		t.Fatalf("stripe rotate result %+v", sr)
	}
	all := h.fx.ev.list()
	alias := h.fx.ev.last("vercel.alias " + sr.DeploymentID)
	if alias < 0 || after(all, alias, "health "+sr.DeploymentID+" 200") < 0 || h.fx.ev.index("stripe.delete "+wc.EndpointID) < after(all, alias, "health "+sr.DeploymentID+" 200") {
		t.Fatalf("old endpoint deleted before production served the new secret: %v", all)
	}
	p.noLeaks(t)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
