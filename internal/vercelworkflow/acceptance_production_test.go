package vercelworkflow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

// olderFixture is the previously deployed generated test value (>=32 bytes)
// that the rollback baseline must hold. It is not a real credential.
const olderFixture = "older-generated-acceptance-value-for-rollback-baseline"

// prodAcceptanceAdapter models a disposable Production project: distinct
// fixture hosts per deployment, a read-only guard, and optional lost
// promotion/rollback responses or delayed alias convergence.
type prodAcceptanceAdapter struct {
	*fakeAdapter
	guardErr       error
	guardFailAfter int
	guardCalls     int
	guardReads     []int
	lostPromote    bool
	lostRollback   bool
	aliasLag       int
	lagRemaining   int
	previous       string
}

func withFixtureHost(d vercel.Deployment) vercel.Deployment {
	d.URL = strings.TrimPrefix(d.ID, "dpl_") + "-fixture.vercel.app"
	return d
}

func (a *prodAcceptanceAdapter) VerifyDisposableProductionProject(_ context.Context, name string) error {
	a.guardCalls++
	a.guardReads = append(a.guardReads, a.store.reads)
	if name != acceptanceProject {
		return provider.NewError("acceptance_guard", 0, "ACCEPTANCE_PROJECT_NOT_MARKED", provider.RetryNever)
	}
	if a.guardFailAfter > 0 && a.guardCalls > a.guardFailAfter {
		return provider.NewError("acceptance_guard", 0, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", provider.RetryNever)
	}
	return a.guardErr
}
func (a *prodAcceptanceAdapter) Deployment(ctx context.Context, id string) (vercel.Deployment, error) {
	d, e := a.fakeAdapter.Deployment(ctx, id)
	return withFixtureHost(d), e
}
func (a *prodAcceptanceAdapter) ProveDeployment(ctx context.Context, id, source, op string) (vercel.Deployment, error) {
	d, e := a.fakeAdapter.ProveDeployment(ctx, id, source, op)
	if e != nil {
		return d, e
	}
	return withFixtureHost(d), nil
}
func (a *prodAcceptanceAdapter) CurrentDeployment(context.Context) (vercel.Deployment, error) {
	if a.lagRemaining > 0 {
		a.lagRemaining--
		return withFixtureHost(a.dep(a.previous)), nil
	}
	return withFixtureHost(a.dep(a.current)), nil
}
func (a *prodAcceptanceAdapter) switchAlias(to string) {
	a.previous, a.current, a.lagRemaining = a.current, to, a.aliasLag
}
func (a *prodAcceptanceAdapter) Promote(context.Context, string) error {
	a.promotes++
	a.switchAlias("dpl_new")
	if a.lostPromote {
		return errors.New("response lost after provider accepted promotion")
	}
	return nil
}
func (a *prodAcceptanceAdapter) Rollback(context.Context, string) error {
	a.rollbacks++
	a.switchAlias("dpl_source")
	if a.lostRollback {
		return errors.New("response lost after provider accepted rollback")
	}
	return nil
}

func productionAcceptanceDocument() *contract.Document {
	return &contract.Document{Digest: strings.Repeat("f", 64), Manifest: contract.Manifest{Version: 1, Bundle: "fixture",
		Records: map[string]contract.Record{"acceptance": {Source: "generate", Sensitivity: "secret"}},
		Targets: map[string]contract.Target{"vercel": {TeamID: "team_fixture", Project: acceptanceProject, ProjectID: "prj_fixture", Environment: "production",
			Services: map[string]contract.Service{"environment": {Variables: map[string]contract.Variable{AcceptanceRecordName: {Source: "record", Record: "acceptance"}}}}}}}}
}

func productionAcceptanceTarget() ProductionAcceptanceTarget {
	return ProductionAcceptanceTarget{TeamID: "team_fixture", ProjectID: "prj_fixture", ProjectName: acceptanceProject}
}

type prodHarness struct {
	b       *Backend
	s       *memoryStore
	a       *prodAcceptanceAdapter
	plan    string
	device  ed25519.PrivateKey
	site    *fixtureSite
	healthy map[string]bool
	runner  ProductionAcceptanceRunner
}

func productionAcceptanceFixture(t *testing.T) *prodHarness {
	t.Helper()
	now := fixtureBase
	doc := productionAcceptanceDocument()
	scope := vercel.Scope{TeamID: "team_fixture", ProjectID: "prj_fixture", Environment: "production"}
	s := &memoryStore{plans: map[string]rollout.ProviderPlan{}, ops: map[string]rollout.Operation{}, states: map[string]State{}, revisions: map[string]int64{}, snapshot: bundle.Snapshot{Version: 1, Bundle: "fixture", ManifestDigest: doc.Digest, PhysicalToLogical: map[string]string{"fixture/acceptance": "acceptance"}, Sources: map[string]bundle.SourceStatus{"acceptance": {Source: "generate", Status: "ready"}}, RecordRevisions: map[string]int64{"acceptance": 1}, CreatedAt: now.Format(time.RFC3339)}}
	a := &prodAcceptanceAdapter{fakeAdapter: &fakeAdapter{scope: scope, store: s, now: func() time.Time { return now }, current: "dpl_source"}}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := &Backend{Document: doc, Adapter: a, Store: s, VaultID: "vault", DeviceID: "device", TrustedPolicyKey: public, OwnerApprovalKey: testOwner.PublicKey(), Now: func() time.Time { return now }, Wait: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }, Probe: func(context.Context, vercel.Deployment, string) (bool, error) { return true, nil }}
	r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
	if e != nil || r.PlanID == "" {
		t.Fatal("production acceptance plan unavailable")
	}
	s.policy = lifecycle.AutomationPolicy{Version: 1, ID: PolicyID(r.PlanID), VaultID: "vault", Bundle: "fixture", ManifestDigest: doc.Digest, Environment: "production", ProviderIdentities: map[string]string{"vercel": scope.TeamID + ":" + scope.ProjectID}, CredentialClasses: []string{"vercel-environment-secret"}, Operations: []string{"stage", "activate", "verify", "rollback"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "manual", HealthChecks: []string{AcceptanceHealthPath}, GracePeriod: "24h", Rollback: "previous-deployment", RetryBudget: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ApprovingDevice: "device", DeploymentPlanID: r.PlanID, DeploymentSourceID: "dpl_source", DeploymentScopeFingerprint: scope.Fingerprint(), DeploymentHealthPath: AcceptanceHealthPath}
	if e = ownerSign(&s.policy, private); e != nil {
		t.Fatal(e)
	}
	site := &fixtureSite{t: t, values: map[string]string{sourceHost: olderFixture, newHost: ""}, always204: map[string]bool{}}
	a.afterWrite = func() { site.values[newHost] = privateFixture }
	probe, closeProbe, e := newAcceptanceProbe(scope, nil, site.client())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(closeProbe)
	healthy := map[string]bool{sourceHost: true, newHost: true}
	health := func(_ context.Context, d vercel.Deployment, path string) (bool, error) {
		if path != AcceptanceHealthPath {
			t.Error("unexpected health path")
		}
		return healthy[d.URL], nil
	}
	return &prodHarness{b: b, s: s, a: a, plan: r.PlanID, device: private, site: site, healthy: healthy,
		runner: ProductionAcceptanceRunner{Backend: b, Target: productionAcceptanceTarget(), Probe: probe, Health: health}}
}

func assertNoProductionSecretEvidence(t *testing.T, h *prodHarness, receipt ProductionAcceptanceReceipt) {
	t.Helper()
	raw, _ := json.Marshal(receipt)
	for _, secret := range []string{privateFixture, olderFixture} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("fixture value in production acceptance receipt")
		}
	}
	for _, proof := range h.site.proofs {
		if proof != "" && strings.Contains(string(raw), proof) {
			t.Fatal("fixture proof or challenge in production acceptance receipt")
		}
	}
	for _, forbidden := range []string{"proof\"", "challenge\"", "hash", "sha256", "hmac"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("receipt contains %q", forbidden)
		}
	}
	journal, _ := json.Marshal(h.s.states)
	if strings.Contains(string(journal), privateFixture) {
		t.Fatal("fixture value in journal")
	}
}

func assertVariablesHonest(t *testing.T, receipt ProductionAcceptanceReceipt, written bool) {
	t.Helper()
	if receipt.VariablesReverted {
		t.Fatal("receipt claims project variables were reverted")
	}
	if written && (receipt.VariableState != "applied-not-reverted" || !strings.Contains(receipt.VariableNote, "remains applied")) {
		t.Fatalf("receipt hid applied variable state: %s / %s", receipt.VariableState, receipt.VariableNote)
	}
	if !written && receipt.VariableState != "not-started" {
		t.Fatalf("receipt reported variable state %s without a write", receipt.VariableState)
	}
}

func TestProductionAcceptancePromotesThenRollsBack(t *testing.T) {
	h := productionAcceptanceFixture(t)
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Result != "PASS" || receipt.Blocker != "" {
		t.Fatalf("production acceptance blocked: %s (%s) at %s", receipt.Blocker, receipt.GuardCode, receipt.Stage)
	}
	want := ProductionFixtureEvidence{SourceHealthStatus: 200, SourceStatus: FixtureMismatch, DeploymentStatus: FixtureMatch, NegativeControlStatus: FixtureMismatch, RollbackHealthStatus: 200, RollbackStatus: FixtureMismatch}
	if receipt.Fixture != want {
		t.Fatalf("unexpected fixture evidence %+v", receipt.Fixture)
	}
	if h.a.writes != 1 || h.a.creates != 1 || h.a.promotes != 1 || h.a.rollbacks != 1 || h.a.current != "dpl_source" {
		t.Fatal("acceptance did not drive exactly one promotion and one rollback")
	}
	if receipt.Stage != "rolled-back" || receipt.DeploymentID != "dpl_new" || receipt.SourceDeploymentID != "dpl_source" || receipt.CurrentDeploymentID != "dpl_source" || receipt.HealthChecks < 3 {
		t.Fatalf("receipt does not prove rollback to source: %+v", receipt)
	}
	// One pre-run guard plus one fresh guard before each of write, redeploy,
	// promote and rollback; the first guard ran before the record was read.
	if h.a.guardCalls != 5 || h.a.guardReads[0] != 0 {
		t.Fatalf("guard not fresh per mutation: calls=%d", h.a.guardCalls)
	}
	if receipt.Level != "provider-production" || receipt.APIPromotionRollback != "pass" || receipt.FullWorkflow != "not-qualified" || len(receipt.FullWorkflowBlockers) != 3 || receipt.OwnerApprovalKeyID == "" {
		t.Fatal("receipt overstated qualification")
	}
	if len(receipt.Recovery) != 0 || len(receipt.Cleanup) != 3 {
		t.Fatal("PASS receipt has recovery steps or incomplete cleanup")
	}
	for _, step := range receipt.Cleanup {
		if !strings.Contains(step, "prj_fixture") && !strings.Contains(step, "token") {
			t.Fatal("cleanup is not scoped to the disposable project")
		}
	}
	assertVariablesHonest(t, receipt, true)
	assertNoProductionSecretEvidence(t, h, receipt)
}

func TestProductionAcceptanceReconcilesLostResponsesReadOnly(t *testing.T) {
	cases := map[string]func(*prodAcceptanceAdapter){
		"lost promote":  func(a *prodAcceptanceAdapter) { a.lostPromote = true },
		"lost rollback": func(a *prodAcceptanceAdapter) { a.lostRollback = true },
		"alias lag":     func(a *prodAcceptanceAdapter) { a.aliasLag = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := productionAcceptanceFixture(t)
			mutate(h.a)
			receipt := h.runner.Run(context.Background(), h.plan)
			if receipt.Result != "PASS" || h.a.promotes != 1 || h.a.rollbacks != 1 || h.a.guardCalls != 5 {
				t.Fatalf("lost response was not reconciled read-only: %s promotes=%d rollbacks=%d", receipt.Blocker, h.a.promotes, h.a.rollbacks)
			}
		})
	}
}

func TestProductionAcceptanceStopsWhenAliasNeverConverges(t *testing.T) {
	h := productionAcceptanceFixture(t)
	h.a.aliasLag = 1000
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Result == "PASS" || receipt.Blocker != "ALIAS_RECONCILIATION_REQUIRED" || h.a.promotes != 1 || h.a.rollbacks != 0 || receipt.Stage != "promoting" {
		t.Fatalf("unconverged promotion: %s at %s", receipt.Blocker, receipt.Stage)
	}
	if !strings.Contains(strings.Join(receipt.Recovery, "\n"), "envbank vercel rollback --manifest MANIFEST --operation "+receipt.OperationID) {
		t.Fatal("no scoped rollback offered after possible activation")
	}
	assertVariablesHonest(t, receipt, true)
}

func TestProductionAcceptanceRefusesBadBaselineBeforeMutation(t *testing.T) {
	cases := []struct {
		want   string
		mutate func(*prodHarness)
		reads  int
	}{
		{"ACCEPTANCE_FIXTURE_NOT_FRESH", func(h *prodHarness) { h.site.values[sourceHost] = privateFixture }, 1},
		{"ACCEPTANCE_BASELINE_FIXTURE_ABSENT", func(h *prodHarness) { h.site.values[sourceHost] = "" }, 1},
		{"ACCEPTANCE_BASELINE_UNHEALTHY", func(h *prodHarness) { h.healthy[sourceHost] = false }, 0},
		{"ACCEPTANCE_SOURCE_NOT_CURRENT_PRODUCTION", func(h *prodHarness) { h.a.current = "dpl_other" }, 0},
		{"ACCEPTANCE_FIXTURE_TOO_SHORT", func(h *prodHarness) { h.b.Store = shortValueStore{h.s} }, 0},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			h := productionAcceptanceFixture(t)
			c.mutate(h)
			receipt := h.runner.Run(context.Background(), h.plan)
			if receipt.Blocker != c.want || h.a.writes != 0 || h.a.creates != 0 || h.a.promotes != 0 || len(h.s.states) != 0 || h.s.reads != c.reads {
				t.Fatalf("got %s writes=%d reads=%d", receipt.Blocker, h.a.writes, h.s.reads)
			}
			assertVariablesHonest(t, receipt, false)
			assertNoProductionSecretEvidence(t, h, receipt)
		})
	}
}

func TestProductionAcceptanceGuardRefusesCustomDomainBeforeRecordRead(t *testing.T) {
	h := productionAcceptanceFixture(t)
	h.a.guardErr = provider.NewError("acceptance_guard", 0, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", provider.RetryNever)
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_PRODUCTION_PROJECT_NOT_DISPOSABLE" || receipt.GuardCode != "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT" || h.s.reads != 0 || h.a.writes != 0 || h.site.requests != 0 || len(h.s.states) != 0 {
		t.Fatalf("custom domain not refused first: %s/%s reads=%d", receipt.Blocker, receipt.GuardCode, h.s.reads)
	}
	assertVariablesHonest(t, receipt, false)
}

func TestProductionAcceptanceGuardRechecksBeforePromotion(t *testing.T) {
	h := productionAcceptanceFixture(t)
	// Pre-run, write and redeploy are admitted; a domain appears before promote.
	h.a.guardFailAfter = 3
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Result == "PASS" || receipt.Blocker != "PROMOTION_REQUEST_NOT_SENT" || receipt.GuardCode != "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT" || h.a.promotes != 0 || h.a.current != "dpl_source" || receipt.Stage != "promote-pending" {
		t.Fatalf("promotion not refused by fresh guard: %s/%s at %s promotes=%d", receipt.Blocker, receipt.GuardCode, receipt.Stage, h.a.promotes)
	}
	recovery := strings.Join(receipt.Recovery, "\n")
	if !strings.Contains(recovery, "was not promoted") || strings.Contains(recovery, "vercel rollback") || receipt.OperationID == "" {
		t.Fatal("recovery misreports unpromoted state")
	}
	assertVariablesHonest(t, receipt, true)
}

func TestProductionAcceptanceRequiresOwnerPinProofAndRollbackAuthority(t *testing.T) {
	cases := map[string]func(*prodHarness){
		"OWNER_APPROVAL_KEY_NOT_PINNED": func(h *prodHarness) { h.b.OwnerApprovalKey = nil },
		"OWNER_APPROVAL_REQUIRED": func(h *prodHarness) {
			h.s.policy.OwnerApproval = nil
			if err := h.s.policy.Sign(h.device); err != nil {
				t.Fatal(err)
			}
		},
		"OWNER_APPROVAL_REQUIRED/no-rollback": func(h *prodHarness) {
			h.s.policy.Operations = []string{"stage", "activate", "verify"}
			if err := ownerSign(&h.s.policy, h.device); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := productionAcceptanceFixture(t)
			mutate(h)
			receipt := h.runner.Run(context.Background(), h.plan)
			want, _, _ := strings.Cut(name, "/")
			if receipt.Blocker != want || h.s.reads != 0 || h.a.writes != 0 || h.site.requests != 0 {
				t.Fatalf("got %s reads=%d", receipt.Blocker, h.s.reads)
			}
		})
	}
}

func TestProductionAcceptanceFixtureFailuresKeepEvidence(t *testing.T) {
	h := productionAcceptanceFixture(t)
	h.site.always204[newHost] = true
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_FIXTURE_CONTROL_FAILED" || receipt.Stage != "complete" || h.a.rollbacks != 0 || receipt.DeploymentID != "dpl_new" || receipt.APIPromotionRollback != "not-qualified" {
		t.Fatalf("negative control failure: %s at %s", receipt.Blocker, receipt.Stage)
	}
	if !strings.Contains(strings.Join(receipt.Recovery, "\n"), "envbank vercel rollback --manifest MANIFEST --operation "+receipt.OperationID) || len(h.s.states) != 1 {
		t.Fatal("activation evidence erased or rollback not offered")
	}
	assertVariablesHonest(t, receipt, true)
	assertNoProductionSecretEvidence(t, h, receipt)

	h = productionAcceptanceFixture(t)
	h.a.afterWrite = nil
	h.site.values[newHost] = olderFixture
	receipt = h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_FRESH_VALUE_NOT_CONSUMED" || receipt.Fixture.DeploymentStatus != FixtureMismatch || h.a.rollbacks != 0 {
		t.Fatalf("stale build accepted: %s", receipt.Blocker)
	}

	h = productionAcceptanceFixture(t)
	calls := 0
	h.runner.Health = func(context.Context, vercel.Deployment, string) (bool, error) { calls++; return calls == 1, nil }
	receipt = h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_ROLLBACK_UNHEALTHY" || receipt.Stage != "rolled-back" || receipt.Fixture.RollbackHealthStatus != 0 || receipt.APIPromotionRollback != "not-qualified" {
		t.Fatalf("unhealthy rollback accepted: %s", receipt.Blocker)
	}
	assertVariablesHonest(t, receipt, true)
}

func TestProductionAcceptanceRefusesRerunOfStartedOperation(t *testing.T) {
	h := productionAcceptanceFixture(t)
	h.site.always204[newHost] = true
	_ = h.runner.Run(context.Background(), h.plan)
	reads, promotes := h.s.reads, h.a.promotes
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_OPERATION_ALREADY_STARTED" || h.s.reads != reads || h.a.promotes != promotes || receipt.Stage != "complete" {
		t.Fatalf("rerun re-drove a started operation: %s", receipt.Blocker)
	}
}

func TestProductionAcceptanceModeSeparation(t *testing.T) {
	_, _, _, plan, _, _, preview := acceptanceFixture(t)
	receipt := ProductionAcceptanceRunner{Backend: preview.Backend, Target: ProductionAcceptanceTarget{TeamID: "team_fixture", ProjectID: "prj_fixture", ProjectName: acceptanceProject}, Probe: preview.Probe}.Run(context.Background(), plan)
	if receipt.Blocker != "ACCEPTANCE_PRODUCTION_ONLY" {
		t.Fatalf("production runner accepted preview backend: %s", receipt.Blocker)
	}
	h := productionAcceptanceFixture(t)
	previewReceipt := AcceptanceRunner{Backend: h.b, Target: acceptanceTarget(), Probe: h.runner.Probe}.Run(context.Background(), h.plan)
	if previewReceipt.Blocker != "ACCEPTANCE_PREVIEW_ONLY" || h.a.writes != 0 {
		t.Fatalf("preview runner accepted production backend: %s", previewReceipt.Blocker)
	}
	if CheckAcceptanceManifest(h.b.Document, acceptanceTarget()) == nil {
		t.Fatal("preview manifest check accepted production")
	}
	h.runner.Target.ProjectID = "prj_other"
	if r := h.runner.Run(context.Background(), h.plan); r.Blocker != "ACCEPTANCE_TARGET_MISMATCH" {
		t.Fatalf("target mismatch: %s", r.Blocker)
	}
	h.runner.Target = productionAcceptanceTarget()
	h.runner.Target.ProjectName = "envbank-acceptance-other"
	if r := h.runner.Run(context.Background(), h.plan); r.Blocker != "ACCEPTANCE_MANIFEST_NOT_DISPOSABLE" || h.a.guardCalls != 0 {
		t.Fatalf("name mismatch: %s", r.Blocker)
	}
}

func TestProductionAcceptanceTargetAndManifest(t *testing.T) {
	good := "disposable-production:team_fixture/prj_fixture/envbank-acceptance-fixture"
	target, e := ParseProductionAcceptanceTarget(good)
	if e != nil || target != productionAcceptanceTarget() {
		t.Fatal("valid production target refused")
	}
	for _, bad := range []string{
		"disposable:team_fixture/prj_fixture/envbank-acceptance-fixture@envbank-acceptance-run1",
		"disposable-production:team_fixture/prj_fixture/envbank-acceptance-fixture@main",
		"disposable-production:team_fixture/prj_fixture/my-app",
		"disposable-production:team_fixture/prj_fixture",
		"disposable-production:team_fixture/prj_fixture/envbank-acceptance-fixture/extra",
		"disposable-production:bad/prj_fixture/envbank-acceptance-fixture",
		"",
	} {
		if _, e := ParseProductionAcceptanceTarget(bad); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, e := ParseAcceptanceTarget(good); e == nil {
		t.Fatal("preview parser accepted production target")
	}
	if CheckProductionAcceptanceManifest(productionAcceptanceDocument(), target) != nil {
		t.Fatal("valid production manifest refused")
	}
	for name, mutate := range map[string]func(*contract.Document){
		"preview": func(d *contract.Document) {
			v := d.Manifest.Targets["vercel"]
			v.Environment = "preview"
			d.Manifest.Targets["vercel"] = v
		},
		"branch": func(d *contract.Document) {
			v := d.Manifest.Targets["vercel"]
			v.GitBranch = "main"
			d.Manifest.Targets["vercel"] = v
		},
		"import": func(d *contract.Document) { d.Manifest.Records["acceptance"] = contract.Record{Source: "import"} },
		"name": func(d *contract.Document) {
			v := d.Manifest.Targets["vercel"]
			v.Project = "real-app"
			d.Manifest.Targets["vercel"] = v
		},
		"variable": func(d *contract.Document) {
			d.Manifest.Targets["vercel"].Services["environment"].Variables["OTHER"] = contract.Variable{Source: "record", Record: "acceptance"}
		},
	} {
		doc := productionAcceptanceDocument()
		mutate(doc)
		if CheckProductionAcceptanceManifest(doc, target) == nil {
			t.Fatalf("%s manifest accepted", name)
		}
	}
}

func TestProductionAcceptanceChecksGeneratedProvenanceAtReadBoundary(t *testing.T) {
	for _, delay := range []bool{false, true} {
		h := productionAcceptanceFixture(t)
		if delay {
			h.runner.Random = delayedAcceptanceRandom{backend: h.b, at: h.b.now().Add(2 * time.Hour)}
		} else {
			source := h.s.snapshot.Sources["acceptance"]
			source.Source = "import"
			h.s.snapshot.Sources["acceptance"] = source
		}
		receipt := h.runner.Run(context.Background(), h.plan)
		want := "ACCEPTANCE_GENERATED_FIXTURE_REQUIRED"
		if delay {
			want = "OWNER_APPROVAL_REQUIRED"
		}
		if receipt.Blocker != want || h.s.reads != 0 || h.a.writes != 0 || h.a.promotes != 0 {
			t.Fatal("production read boundary admitted stale approval or imported credentials")
		}
	}
}

func TestProductionRecoveryDoesNotClaimUncertainWritesApplied(t *testing.T) {
	h := productionAcceptanceFixture(t)
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Result != "PASS" {
		t.Fatal("fixture setup failed")
	}
	state := h.s.states[receipt.OperationID]
	state.Stage = "writing"
	h.s.states[state.ID] = state
	receipt = h.runner.finish(context.Background(), receipt, "LOST_CHECKPOINT")
	if receipt.VariableState != "possibly-partially-applied-not-reverted" || strings.Contains(receipt.VariableNote, "remains applied") || !strings.Contains(receipt.VariableNote, "may be partially") || receipt.VariablesReverted {
		t.Fatal("uncertain write receipt overstated value state")
	}
}

func TestProductionAcceptanceJournalFailureIsNotAnExistingRun(t *testing.T) {
	h := productionAcceptanceFixture(t)
	h.b.Store = unavailableAcceptanceJournal{Store: h.s}
	receipt := h.runner.Run(context.Background(), h.plan)
	if receipt.Blocker != "ACCEPTANCE_JOURNAL_UNAVAILABLE" || h.s.reads != 0 || h.a.writes != 0 {
		t.Fatal("journal failure was misreported or allowed work")
	}
}
