package vercelworkflow

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

const (
	acceptanceProject = "envbank-acceptance-fixture"
	acceptanceBranch  = "envbank-acceptance-run1"
	sourceHost        = "source-fixture.vercel.app"
	newHost           = "new-fixture.vercel.app"
)

// namedAdapter adds the provider-reported project name and distinct fixture
// hosts for the source and redeployed deployments.
type namedAdapter struct {
	*fakeAdapter
	name string
}

func (a *namedAdapter) ProjectName(context.Context) (string, error) { return a.name, nil }

func (a *namedAdapter) withHost(d vercel.Deployment) vercel.Deployment {
	d.URL = strings.TrimPrefix(d.ID, "dpl_") + "-fixture.vercel.app"
	return d
}
func (a *namedAdapter) Deployment(ctx context.Context, id string) (vercel.Deployment, error) {
	d, e := a.fakeAdapter.Deployment(ctx, id)
	return a.withHost(d), e
}
func (a *namedAdapter) ProveDeployment(ctx context.Context, id, source, op string) (vercel.Deployment, error) {
	d, e := a.fakeAdapter.ProveDeployment(ctx, id, source, op)
	if e != nil {
		return d, e
	}
	return a.withHost(d), nil
}

// fixtureSite is a Go reference of e2e/fixtures/vercel-acceptance: it returns
// status only, computes the same HMAC and never returns a body.
type fixtureSite struct {
	t         *testing.T
	values    map[string]string
	always204 map[string]bool
	proofs    []string
	requests  int
}

func (f *fixtureSite) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.requests++
		if r.Method != http.MethodGet || r.URL.Path != AcceptanceFixturePath || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || strings.Contains(r.URL.String(), privateFixture) {
			f.t.Error("unsafe acceptance fixture request")
		}
		for _, values := range r.Header {
			for _, value := range values {
				if strings.Contains(value, privateFixture) {
					f.t.Error("fixture value sent to deployment")
				}
			}
		}
		challenge, proof := r.Header.Get(AcceptanceChallengeHeader), r.Header.Get(AcceptanceProofHeader)
		f.proofs = append(f.proofs, proof)
		value, known := f.values[r.URL.Host]
		status := http.StatusNotFound
		switch {
		case !known:
		case f.always204[r.URL.Host]:
			status = FixtureMatch
		case len(value) < 32:
			status = FixtureAbsent
		case challenge == "" || proof == "":
			status = http.StatusBadRequest
		case hmac.Equal([]byte(AcceptanceProof([]byte(value), challenge)), []byte(proof)):
			status = FixtureMatch
		default:
			status = FixtureMismatch
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
}

func acceptanceDocument() *contract.Document {
	return &contract.Document{Digest: strings.Repeat("e", 64), Manifest: contract.Manifest{Version: 1, Bundle: "fixture",
		Records: map[string]contract.Record{"acceptance": {Source: "generate", Sensitivity: "secret"}},
		Targets: map[string]contract.Target{"vercel": {TeamID: "team_fixture", Project: acceptanceProject, ProjectID: "prj_fixture", Environment: "preview", GitBranch: acceptanceBranch,
			Services: map[string]contract.Service{"environment": {Variables: map[string]contract.Variable{AcceptanceRecordName: {Source: "record", Record: "acceptance"}}}}}}}}
}

func acceptanceTarget() AcceptanceTarget {
	return AcceptanceTarget{TeamID: "team_fixture", ProjectID: "prj_fixture", ProjectName: acceptanceProject, GitBranch: acceptanceBranch}
}

func acceptanceFixture(t *testing.T) (*Backend, *memoryStore, *namedAdapter, string, ed25519.PrivateKey, *fixtureSite, AcceptanceRunner) {
	t.Helper()
	now := fixtureBase
	doc := acceptanceDocument()
	scope := vercel.Scope{TeamID: "team_fixture", ProjectID: "prj_fixture", Environment: "preview", GitBranch: acceptanceBranch}
	s := &memoryStore{plans: map[string]rollout.ProviderPlan{}, ops: map[string]rollout.Operation{}, states: map[string]State{}, revisions: map[string]int64{}, snapshot: bundle.Snapshot{Version: 1, Bundle: "fixture", ManifestDigest: doc.Digest, PhysicalToLogical: map[string]string{"fixture/acceptance": "acceptance"}, Sources: map[string]bundle.SourceStatus{"acceptance": {Source: "generate", Status: "ready"}}, RecordRevisions: map[string]int64{"acceptance": 1}, CreatedAt: now.Format(time.RFC3339)}}
	a := &namedAdapter{fakeAdapter: &fakeAdapter{scope: scope, store: s, now: func() time.Time { return now }, current: "dpl_source"}, name: acceptanceProject}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := &Backend{Document: doc, Adapter: a, Store: s, VaultID: "vault", DeviceID: "device", TrustedPolicyKey: public, OwnerApprovalKey: testOwner.PublicKey(), Now: func() time.Time { return now }, Wait: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }, Probe: func(context.Context, vercel.Deployment, string) (bool, error) { return true, nil }}
	r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
	if e != nil {
		t.Fatal(e)
	}
	s.policy = lifecycle.AutomationPolicy{Version: 1, ID: PolicyID(r.PlanID), VaultID: "vault", Bundle: "fixture", ManifestDigest: doc.Digest, Environment: "staging", ProviderIdentities: map[string]string{"vercel": scope.TeamID + ":" + scope.ProjectID}, CredentialClasses: []string{"vercel-environment-secret"}, Operations: []string{"stage", "activate", "verify", "rollback"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "manual", HealthChecks: []string{AcceptanceHealthPath}, GracePeriod: "15m", Rollback: "previous-deployment", RetryBudget: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ApprovingDevice: "device", DeploymentPlanID: r.PlanID, DeploymentSourceID: "dpl_source", DeploymentScopeFingerprint: scope.Fingerprint(), DeploymentHealthPath: AcceptanceHealthPath}
	if e = ownerSign(&s.policy, private); e != nil {
		t.Fatal(e)
	}
	site := &fixtureSite{t: t, values: map[string]string{sourceHost: "", newHost: ""}, always204: map[string]bool{}}
	// A successful write models the redeploy consuming the written value.
	a.afterWrite = func() { site.values[newHost] = privateFixture }
	probe, closeProbe, e := newAcceptanceProbe(scope, nil, site.client())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(closeProbe)
	return b, s, a, r.PlanID, private, site, AcceptanceRunner{Backend: b, Target: acceptanceTarget(), Probe: probe}
}

func assertNoSecretEvidence(t *testing.T, receipt AcceptanceReceipt, site *fixtureSite) {
	t.Helper()
	raw, _ := json.Marshal(receipt)
	if strings.Contains(string(raw), privateFixture) {
		t.Fatal("fixture value in acceptance receipt")
	}
	for _, proof := range site.proofs {
		if proof != "" && strings.Contains(string(raw), proof) {
			t.Fatal("fixture proof in acceptance receipt")
		}
	}
	for _, forbidden := range []string{"proof\"", "challenge\"", "hash", "sha256"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("receipt contains %q field", forbidden)
		}
	}
}

func TestAcceptancePassProvesFreshConsumptionWithStatusOnlyEvidence(t *testing.T) {
	_, s, a, plan, _, site, runner := acceptanceFixture(t)
	receipt := runner.Run(context.Background(), plan)
	if receipt.Result != "PASS" || receipt.Blocker != "" {
		t.Fatalf("acceptance blocked: %s at %s", receipt.Blocker, receipt.Stage)
	}
	if receipt.Fixture != (AcceptanceFixtureEvidence{SourceStatus: FixtureAbsent, DeploymentStatus: FixtureMatch, NegativeControlStatus: FixtureMismatch}) {
		t.Fatalf("unexpected fixture evidence %+v", receipt.Fixture)
	}
	if a.writes != 1 || a.creates != 1 || a.promotes != 0 || receipt.DeploymentID != "dpl_new" || receipt.Stage != "complete" || receipt.HealthChecks < 3 || site.requests != 3 {
		t.Fatal("acceptance did not drive exactly one approved Preview workflow")
	}
	if receipt.Level != "provider-preview" || receipt.FullWorkflow != "not-qualified" || len(receipt.FullWorkflowBlockers) == 0 || receipt.OwnerApprovalKeyID == "" || len(receipt.Cleanup) != 3 {
		t.Fatal("receipt overstated qualification or omitted cleanup scope")
	}
	for _, step := range receipt.Cleanup {
		if !strings.Contains(step, "prj_fixture") && !strings.Contains(step, "token") {
			t.Fatal("cleanup is not scoped to the created/marked resources")
		}
	}
	assertNoSecretEvidence(t, receipt, site)
	raw, _ := json.Marshal(s.states)
	if strings.Contains(string(raw), privateFixture) {
		t.Fatal("fixture value in journal")
	}
}

func TestAcceptanceRefusesWhenSourceAlreadyHoldsValue(t *testing.T) {
	_, s, a, plan, _, site, runner := acceptanceFixture(t)
	site.values[sourceHost] = privateFixture
	receipt := runner.Run(context.Background(), plan)
	if receipt.Blocker != "ACCEPTANCE_FIXTURE_NOT_FRESH" || a.writes != 0 || a.creates != 0 || len(s.states) != 0 {
		t.Fatalf("non-fresh fixture mutated provider: %s", receipt.Blocker)
	}
	assertNoSecretEvidence(t, receipt, site)
}

func TestAcceptanceDetectsStaleBuildAndAlways204Fixture(t *testing.T) {
	_, _, a, plan, _, site, runner := acceptanceFixture(t)
	a.afterWrite = nil
	site.values[newHost] = "older-value-that-is-long-enough-for-fixture-use"
	receipt := runner.Run(context.Background(), plan)
	if receipt.Result == "PASS" || receipt.Blocker != "ACCEPTANCE_FRESH_VALUE_NOT_CONSUMED" || receipt.Fixture.DeploymentStatus != FixtureMismatch {
		t.Fatalf("stale build accepted: %s", receipt.Blocker)
	}
	_, _, _, plan, _, site, runner = acceptanceFixture(t)
	site.always204[newHost] = true
	receipt = runner.Run(context.Background(), plan)
	if receipt.Result == "PASS" || receipt.Blocker != "ACCEPTANCE_FIXTURE_CONTROL_FAILED" {
		t.Fatalf("always-success fixture accepted: %s", receipt.Blocker)
	}
}

func TestAcceptanceRefusesUnmarkedOrMismatchedTargetsBeforeReadingRecord(t *testing.T) {
	cases := map[string]func(*Backend, *namedAdapter, *AcceptanceRunner){
		"ACCEPTANCE_PROJECT_NOT_MARKED": func(_ *Backend, a *namedAdapter, _ *AcceptanceRunner) { a.name = "real-production-app" },
		"ACCEPTANCE_TARGET_MISMATCH": func(_ *Backend, _ *namedAdapter, r *AcceptanceRunner) {
			r.Target.GitBranch = "envbank-acceptance-other"
		},
		"ACCEPTANCE_MANIFEST_NOT_DISPOSABLE": func(b *Backend, _ *namedAdapter, r *AcceptanceRunner) {
			r.Target.ProjectName = "envbank-acceptance-other"
		},
		"OWNER_APPROVAL_KEY_NOT_PINNED": func(b *Backend, _ *namedAdapter, _ *AcceptanceRunner) { b.OwnerApprovalKey = nil },
		"VERCEL_BACKEND_UNAVAILABLE":    func(_ *Backend, _ *namedAdapter, r *AcceptanceRunner) { r.Probe = nil },
	}
	for want, mutate := range cases {
		t.Run(want, func(t *testing.T) {
			b, s, a, plan, _, site, runner := acceptanceFixture(t)
			mutate(b, a, &runner)
			receipt := runner.Run(context.Background(), plan)
			if receipt.Blocker != want || s.reads != 0 || a.writes != 0 || site.requests != 0 {
				t.Fatalf("got %s, reads=%d writes=%d", receipt.Blocker, s.reads, a.writes)
			}
		})
	}
}

func TestAcceptanceRequiresHardwareOwnerApproval(t *testing.T) {
	_, s, a, plan, device, site, runner := acceptanceFixture(t)
	s.policy.OwnerApproval = nil
	if err := s.policy.Sign(device); err != nil {
		t.Fatal(err)
	}
	receipt := runner.Run(context.Background(), plan)
	if receipt.Blocker != "OWNER_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 || site.requests != 0 {
		t.Fatalf("device-only approval ran acceptance: %s", receipt.Blocker)
	}
}

func TestAcceptanceRefusesShortFixtureValue(t *testing.T) {
	b, s, a, plan, _, site, runner := acceptanceFixture(t)
	b.Store = shortValueStore{s}
	receipt := runner.Run(context.Background(), plan)
	if receipt.Blocker != "ACCEPTANCE_FIXTURE_TOO_SHORT" || a.writes != 0 || site.requests != 0 {
		t.Fatalf("short fixture accepted: %s", receipt.Blocker)
	}
}

type shortValueStore struct{ *memoryStore }

func (shortValueStore) LoadRecord(context.Context, string, string, int64) ([]byte, error) {
	return []byte("short"), nil
}

func TestAcceptanceManifestAndTargetParsing(t *testing.T) {
	target, err := ParseAcceptanceTarget("disposable:team_fixture/prj_fixture/envbank-acceptance-fixture@envbank-acceptance-run1")
	if err != nil || target != acceptanceTarget() {
		t.Fatalf("valid target rejected: %v", err)
	}
	for _, raw := range []string{
		"team_fixture/prj_fixture/envbank-acceptance-fixture@envbank-acceptance-run1",
		"disposable:team_fixture/prj_fixture/my-app@envbank-acceptance-run1",
		"disposable:team_fixture/prj_fixture/envbank-acceptance-fixture@main",
		"disposable:team_fixture/prj_fixture/envbank-acceptance-fixture",
		"disposable:team_fixture/prj_fixture/envbank-acceptance-fixture@",
		"disposable:team_fixture/prj_fixture/x/envbank-acceptance-fixture@envbank-acceptance-run1",
	} {
		if _, err := ParseAcceptanceTarget(raw); err == nil {
			t.Fatalf("unsafe target accepted: %q", raw)
		}
	}
	doc := acceptanceDocument()
	if CheckAcceptanceManifest(doc, acceptanceTarget()) != nil {
		t.Fatal("dedicated manifest rejected")
	}
	extra := acceptanceDocument()
	extra.Manifest.Targets["vercel"].Services["environment"].Variables["API_SECRET"] = contract.Variable{Source: "record", Record: "acceptance"}
	production := acceptanceDocument()
	vercelTarget := production.Manifest.Targets["vercel"]
	vercelTarget.Environment, vercelTarget.GitBranch = "production", ""
	production.Manifest.Targets["vercel"] = vercelTarget
	for _, bad := range []*contract.Document{extra, production, nil} {
		if CheckAcceptanceManifest(bad, acceptanceTarget()) == nil {
			t.Fatal("non-dedicated manifest accepted")
		}
	}
}

// The deployable fixture must keep the same status/header/HMAC contract as
// the Go reference above. This is a source assertion, not a Node execution.
func TestDeployableFixtureMatchesContract(t *testing.T) {
	root := filepath.Join("..", "..", "e2e", "fixtures", "vercel-acceptance", "api")
	acceptance, err := os.ReadFile(filepath.Join(root, "envbank-acceptance.js"))
	if err != nil {
		t.Fatal(err)
	}
	health, err := os.ReadFile(filepath.Join(root, "health.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{AcceptanceRecordName, AcceptanceChallengeHeader, AcceptanceProofHeader, AcceptanceProofDomain, "timingSafeEqual", "204", "409", "424", "no-store"} {
		if !strings.Contains(string(acceptance), want) {
			t.Fatalf("fixture missing %q", want)
		}
	}
	for _, source := range [][]byte{acceptance, health} {
		for _, forbidden := range []string{"console.", "res.json", "res.send", "fetch(", "require('fs')", "process.stdout", "JSON.stringify"} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("fixture may emit or forward data: %q", forbidden)
			}
		}
	}
}

type delayedAcceptanceRandom struct {
	backend *Backend
	at      time.Time
}

func (r delayedAcceptanceRandom) Read(p []byte) (int, error) {
	r.backend.Now = func() time.Time { return r.at }
	return rand.Read(p)
}

func TestAcceptanceRechecksApprovalBeforePrivateFixtureRead(t *testing.T) {
	b, s, a, plan, _, site, runner := acceptanceFixture(t)
	runner.Random = delayedAcceptanceRandom{backend: b, at: b.now().Add(2 * time.Hour)}
	receipt := runner.Run(context.Background(), plan)
	if receipt.Blocker != "OWNER_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 || site.requests != 0 {
		t.Fatal("expired approval allowed private fixture read")
	}
}

func TestAcceptanceRequiresGeneratedSnapshotProvenance(t *testing.T) {
	_, s, a, plan, _, site, runner := acceptanceFixture(t)
	source := s.snapshot.Sources["acceptance"]
	source.Source = "import"
	s.snapshot.Sources["acceptance"] = source
	receipt := runner.Run(context.Background(), plan)
	if receipt.Blocker != "ACCEPTANCE_GENERATED_FIXTURE_REQUIRED" || s.reads != 0 || a.writes != 0 || site.requests != 0 {
		t.Fatal("imported upstream record was repurposed as a fixture")
	}
	doc := acceptanceDocument()
	record := doc.Manifest.Records["acceptance"]
	record.Source = "import"
	doc.Manifest.Records["acceptance"] = record
	if CheckAcceptanceManifest(doc, acceptanceTarget()) == nil {
		t.Fatal("imported fixture manifest accepted")
	}
}

func TestAcceptanceProbeRefusesOtherHeaders(t *testing.T) {
	b, _, a, _, _, site, _ := acceptanceFixture(t)
	probe, closeProbe, e := newAcceptanceProbe(b.Adapter.Scope(), nil, site.client())
	if e != nil {
		t.Fatal(e)
	}
	defer closeProbe()
	for _, header := range []string{"Authorization", "Host", "x-vercel-protection-bypass", "Cookie"} {
		_, e = probe(context.Background(), a.dep("dpl_source"), map[string]string{header: "fake-forbidden-value"})
		if e == nil || site.requests != 0 {
			t.Fatal("arbitrary header accepted")
		}
	}
}

type unavailableAcceptanceJournal struct{ Store }

func (s unavailableAcceptanceJournal) LoadLink(context.Context, string) (string, int64, error) {
	return "", 0, errors.New("journal unavailable")
}
func (s unavailableAcceptanceJournal) SaveLink(context.Context, string, string, int64) (int64, error) {
	return 0, errors.New("journal unavailable")
}
func (s unavailableAcceptanceJournal) LoadDeployment(context.Context, string) (State, int64, error) {
	return State{}, 0, errors.New("synthetic unavailable journal")
}
func TestAcceptanceDoesNotAdoptPriorRunOrHideUnavailableJournal(t *testing.T) {
	b, s, a, plan, _, site, runner := acceptanceFixture(t)
	first := runner.Run(context.Background(), plan)
	if first.Result != "PASS" {
		t.Fatal("fixture setup failed")
	}
	writes, requests := a.writes, site.requests
	again := runner.Run(context.Background(), plan)
	if again.Blocker != "ACCEPTANCE_OPERATION_ALREADY_STARTED" || again.OperationID != first.OperationID || a.writes != writes || site.requests != requests {
		t.Fatal("prior operation counted as a fresh acceptance run")
	}
	b.Store = unavailableAcceptanceJournal{Store: s}
	again = runner.Run(context.Background(), plan)
	if again.Blocker != "ACCEPTANCE_JOURNAL_UNAVAILABLE" {
		t.Fatal("journal failure was reported as an existing operation")
	}
}
