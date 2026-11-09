package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

// memStore is an in-memory stand-in for lifecycle.VaultStore with the same
// optimistic-revision and lease semantics.
type memStore struct {
	mu         sync.Mutex
	policies   map[string]lifecycle.AutomationPolicy
	operations map[string]lifecycle.Operation
	revisions  map[string]int64
	evidence   map[string][]lifecycle.Evidence
	lease      *lifecycle.Lease
	now        func() time.Time
	saveErr    error
}

func newMemStore(now func() time.Time) *memStore {
	return &memStore{policies: map[string]lifecycle.AutomationPolicy{}, operations: map[string]lifecycle.Operation{}, revisions: map[string]int64{}, evidence: map[string][]lifecycle.Evidence{}, now: now}
}
func (store *memStore) LoadPolicy(_ context.Context, id string) (lifecycle.AutomationPolicy, int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	policy, ok := store.policies[id]
	if !ok {
		return policy, 0, errors.New("missing policy")
	}
	return policy, 1, nil
}
func (store *memStore) SaveOperation(_ context.Context, operation lifecycle.Operation, expected int64) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.saveErr != nil {
		return 0, store.saveErr
	}
	if err := operation.Validate(); err != nil {
		return 0, err
	}
	if store.revisions[operation.ID] != expected {
		return 0, errors.New("revision conflict")
	}
	store.revisions[operation.ID]++
	store.operations[operation.ID] = operation
	return store.revisions[operation.ID], nil
}
func (store *memStore) LoadOperation(_ context.Context, id string) (lifecycle.Operation, int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	operation, ok := store.operations[id]
	if !ok {
		return operation, 0, errors.New("missing operation")
	}
	return operation, store.revisions[id], nil
}
func (store *memStore) AcquireLease(_ context.Context, bundle, owner string, ttl time.Duration) (lifecycle.Lease, int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lease != nil {
		expires, _ := time.Parse(time.RFC3339, store.lease.ExpiresAt)
		if store.now().Before(expires) {
			return lifecycle.Lease{}, 0, lifecycle.ErrLeaseHeld
		}
	}
	lease := lifecycle.Lease{Bundle: bundle, Owner: owner, AcquiredAt: store.now().Format(time.RFC3339), ExpiresAt: store.now().Add(ttl).Format(time.RFC3339)}
	store.lease = &lease
	return lease, 1, nil
}
func (store *memStore) ReleaseLease(_ context.Context, lease lifecycle.Lease, _ int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lease != nil && store.lease.Owner == lease.Owner {
		store.lease = nil
	}
	return nil
}
func (store *memStore) LoadEvidence(_ context.Context, id string, public ed25519.PublicKey) ([]lifecycle.Evidence, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	chain := append([]lifecycle.Evidence{}, store.evidence[id]...)
	if err := lifecycle.VerifyEvidenceChain(chain, public); err != nil {
		return nil, err
	}
	return chain, nil
}
func (store *memStore) AppendEvidence(_ context.Context, id string, evidence lifecycle.Evidence, public ed25519.PublicKey) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	chain := append(append([]lifecycle.Evidence{}, store.evidence[id]...), evidence)
	if err := lifecycle.VerifyEvidenceChain(chain, public); err != nil {
		return 0, err
	}
	store.evidence[id] = chain
	return int64(len(chain)), nil
}

type records struct {
	mu       sync.Mutex
	revision int64
	values   map[string][]byte
}

func (writer *records) StoreSecret(_ context.Context, record string, provide func(func([]byte) error) error) (int64, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.values == nil {
		writer.values = map[string][]byte{}
	}
	err := provide(func(value []byte) error { writer.values[record] = append([]byte(nil), value...); return nil })
	if err != nil {
		return 0, err
	}
	writer.revision++
	return writer.revision, nil
}

type fakeAdapter struct {
	identity   provider.Identity
	createErrs []error
	revokeErrs []error
	created    []lifecycle.CredentialRequest
	revoked    []string
	minted     int
}

func (adapter *fakeAdapter) Identify(context.Context) (provider.Identity, error) {
	return adapter.identity, nil
}
func (*fakeAdapter) Capabilities() map[string]lifecycle.CredentialCapability {
	return map[string]lifecycle.CredentialCapability{"role-password": lifecycle.CapabilityAutomatic}
}
func (adapter *fakeAdapter) Create(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	adapter.created = append(adapter.created, request)
	if len(adapter.createErrs) > 0 {
		err := adapter.createErrs[0]
		adapter.createErrs = adapter.createErrs[1:]
		if err != nil {
			return lifecycle.CredentialEvidence{}, err
		}
	}
	adapter.minted++
	receipt, err := sink.StoreBytes(ctx, []byte("npg_minted_value_"+strings.Repeat("x", adapter.minted)))
	if err != nil {
		return lifecycle.CredentialEvidence{}, err
	}
	return lifecycle.CredentialEvidence{CredentialID: "role:p/b/app_b", CreatedAt: "2026-11-08T00:00:00Z", Receipt: receipt}, nil
}
func (*fakeAdapter) Validate(context.Context, string) (provider.VerifyEvidence, error) {
	return provider.VerifyEvidence{}, errors.New("unused")
}
func (adapter *fakeAdapter) Revoke(_ context.Context, id string) error {
	adapter.revoked = append(adapter.revoked, id)
	if len(adapter.revokeErrs) > 0 {
		err := adapter.revokeErrs[0]
		adapter.revokeErrs = adapter.revokeErrs[1:]
		return err
	}
	return nil
}

type fakeDeployer struct {
	stageErrs    []error
	activateErrs []error
	unhealthy    bool
	rollbackErr  error
	staged       []lifecycle.DeploymentRequest
	activated    []string
	rolledBack   []string
}

func (deployer *fakeDeployer) Stage(_ context.Context, request lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error) {
	deployer.staged = append(deployer.staged, request)
	if len(deployer.stageErrs) > 0 {
		err := deployer.stageErrs[0]
		deployer.stageErrs = deployer.stageErrs[1:]
		if err != nil {
			return lifecycle.DeploymentEvidence{}, err
		}
	}
	return lifecycle.DeploymentEvidence{DeploymentID: "dpl_1", Status: "READY", At: "2026-11-08T00:00:00Z"}, nil
}
func (deployer *fakeDeployer) Activate(_ context.Context, _ lifecycle.DeploymentRequest, deployment string) (lifecycle.HealthEvidence, error) {
	deployer.activated = append(deployer.activated, deployment)
	if len(deployer.activateErrs) > 0 {
		err := deployer.activateErrs[0]
		deployer.activateErrs = deployer.activateErrs[1:]
		if err != nil {
			return lifecycle.HealthEvidence{}, err
		}
	}
	if deployer.unhealthy {
		return lifecycle.HealthEvidence{SuccessfulChecks: 1, Healthy: false}, nil
	}
	return lifecycle.HealthEvidence{SuccessfulChecks: 3, FirstSuccessAt: "2026-11-08T00:00:00Z", LastSuccessAt: "2026-11-08T00:00:40Z", Healthy: true}, nil
}
func (deployer *fakeDeployer) Rollback(_ context.Context, _ lifecycle.DeploymentRequest, deployment string) error {
	deployer.rolledBack = append(deployer.rolledBack, deployment)
	return deployer.rollbackErr
}

type harness struct {
	engine   *Engine
	store    *memStore
	adapter  *fakeAdapter
	deployer *fakeDeployer
	records  *records
	clock    time.Time
	policy   lifecycle.AutomationPolicy
	owner    error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{clock: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC), adapter: &fakeAdapter{identity: provider.Identity{Provider: "neon", ID: "acct-1"}}, deployer: &fakeDeployer{}, records: &records{revision: 1}}
	now := func() time.Time { return h.clock }
	h.store = newMemStore(now)
	h.policy = lifecycle.AutomationPolicy{Version: lifecycle.PolicyVersion, ID: "rotation-neon", VaultID: "vault", Bundle: "bundle", ManifestDigest: strings.Repeat("a", 64), Environment: "staging", ProviderIdentities: map[string]string{"neon": "acct-1"}, CredentialClasses: []string{"role-password"}, Operations: []string{"create", "stage", "activate", "verify", "rollback", "revoke"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: "prj_1", EnvironmentID: "preview"}}, Schedule: "on-demand", HealthChecks: []string{"/api/health"}, GracePeriod: "15m", Rollback: "previous-deployment", RetryBudget: 2, ExpiresAt: h.clock.Add(30 * 24 * time.Hour).Format(time.RFC3339), ApprovingDevice: "device-1"}
	if err := h.policy.Sign(private); err != nil {
		t.Fatal(err)
	}
	h.store.policies[h.policy.ID] = h.policy
	h.engine = &Engine{Store: h.store, Deployer: h.deployer, Credentials: h.adapter, Records: h.records, VaultID: "vault", DeviceID: "device-1", DevicePrivate: private, PolicyKey: public, OwnerVerify: func(lifecycle.AutomationPolicy, time.Time) error { return h.owner }, Now: now}
	return h
}

func (h *harness) input() PlanInput {
	return PlanInput{OperationID: "op-1", PolicyID: h.policy.ID, Bundle: "bundle", ManifestDigest: strings.Repeat("a", 64), Provider: "neon", ProviderIdentity: "acct-1", CredentialClass: "role-password", DestinationRecord: "DATABASE_URL", PreviousRecordRevision: 1, PreviousCredentialID: "role:p/b/app_a", Target: lifecycle.TargetPolicy{Provider: "vercel", ProjectID: "prj_1", EnvironmentID: "preview"}, CreateParameters: map[string][]string{"project_id": {"p"}, "branch_id": {"b"}, "role_name": {"app_b"}}}
}

func (h *harness) planAndRun(t *testing.T) lifecycle.Operation {
	t.Helper()
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	operation, err := h.engine.Run(context.Background(), "op-1")
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func TestRotationCompletesAfterGracePeriod(t *testing.T) {
	h := newHarness(t)
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateGracePeriod || operation.NewRecordRevision != 2 || operation.NewCredentialID != "role:p/b/app_b" || operation.DeploymentID != "dpl_1" || operation.HealthEvidenceDigest == "" {
		t.Fatalf("operation=%+v", operation)
	}
	if len(h.adapter.revoked) != 0 || h.adapter.created[0].IdempotencyKey != "op-1:create" || h.adapter.created[0].Parameters["role_name"][0] != "app_b" {
		t.Fatalf("adapter=%+v", h.adapter)
	}
	if string(h.records.values["DATABASE_URL"]) != "npg_minted_value_x" || h.deployer.staged[0].RecordRevisions["DATABASE_URL"] != 2 || h.deployer.staged[0].PreviousRecordRevisions["DATABASE_URL"] != 1 {
		t.Fatalf("records=%q staged=%+v", h.records.values, h.deployer.staged)
	}
	// Still inside the grace period: nothing changes.
	h.clock = h.clock.Add(10 * time.Minute)
	if again, err := h.engine.Run(context.Background(), "op-1"); err != nil || again.State != lifecycle.StateGracePeriod || len(h.adapter.revoked) != 0 {
		t.Fatalf("state=%s err=%v revoked=%v", again.State, err, h.adapter.revoked)
	}
	h.clock = h.clock.Add(6 * time.Minute)
	final, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || final.State != lifecycle.StateComplete || len(h.adapter.revoked) != 1 || h.adapter.revoked[0] != "role:p/b/app_a" {
		t.Fatalf("state=%s err=%v revoked=%v", final.State, err, h.adapter.revoked)
	}
	chain, err := h.store.LoadEvidence(context.Background(), "op-1", h.engine.PolicyKey)
	if err != nil || len(chain) < 10 || chain[len(chain)-1].Code != "complete" {
		t.Fatalf("chain=%d err=%v", len(chain), err)
	}
}

func TestOwnerApprovalGatesEveryStep(t *testing.T) {
	h := newHarness(t)
	h.owner = errors.New("no owner signature")
	if _, err := h.engine.Plan(context.Background(), h.input()); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
	h.owner = nil
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	h.owner = errors.New("approval withdrawn")
	if _, err := h.engine.Run(context.Background(), "op-1"); !errors.Is(err, ErrNotApproved) || len(h.adapter.created) != 0 {
		t.Fatalf("err=%v created=%d", err, len(h.adapter.created))
	}
}

func TestPolicyFromAnotherDeviceOrKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := h.policy
	forged.Signature = nil
	if err := forged.Sign(other); err != nil {
		t.Fatal(err)
	}
	h.store.policies[h.policy.ID] = forged
	if _, err := h.engine.Plan(context.Background(), h.input()); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
	h.store.policies[h.policy.ID] = h.policy
	h.engine.DeviceID = "device-2"
	if _, err := h.engine.Plan(context.Background(), h.input()); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
}

func TestPolicyChangeAfterPlanStopsTheRun(t *testing.T) {
	h := newHarness(t)
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	changed := h.policy
	changed.GracePeriod = "16m"
	changed.PublicKey = nil
	changed.Signature = nil
	if err := changed.Sign(private); err != nil {
		t.Fatal(err)
	}
	changed.PublicKey = h.policy.PublicKey // wrong key for signature; caught by Validate
	h.store.policies[h.policy.ID] = changed
	if _, err := h.engine.Run(context.Background(), "op-1"); !errors.Is(err, ErrNotApproved) || len(h.adapter.created) != 0 {
		t.Fatalf("err=%v", err)
	}
}

func TestSafeCreateFailureRetriesWithSameKeyThenExhaustsBudget(t *testing.T) {
	h := newHarness(t)
	h.adapter.createErrs = []error{provider.NewError("create", 503, "NEON_RESPONSE", provider.RetrySafe)}
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateGracePeriod || len(h.adapter.created) != 2 || h.adapter.created[1].IdempotencyKey != "op-1:create" || operation.Attempts != 1 {
		t.Fatalf("state=%s created=%d attempts=%d", operation.State, len(h.adapter.created), operation.Attempts)
	}

	h = newHarness(t)
	safe := provider.NewError("create", 503, "NEON_RESPONSE", provider.RetrySafe)
	h.adapter.createErrs = []error{safe, safe, safe}
	operation = h.planAndRun(t)
	if operation.State != lifecycle.StateTerminalFailure || len(h.adapter.created) != 3 || len(h.deployer.staged) != 0 {
		t.Fatalf("state=%s created=%d", operation.State, len(h.adapter.created))
	}
}

func TestAmbiguousCreateRequiresReconciliationAndNeverRetries(t *testing.T) {
	h := newHarness(t)
	h.adapter.createErrs = []error{provider.NewError("create", 0, "TRANSPORT_FAILED", provider.RetryAmbiguous)}
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateReconciliationRequired || len(h.adapter.created) != 1 {
		t.Fatalf("state=%s created=%d", operation.State, len(h.adapter.created))
	}
	again, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || again.State != lifecycle.StateReconciliationRequired || len(h.adapter.created) != 1 {
		t.Fatalf("state=%s err=%v created=%d", again.State, err, len(h.adapter.created))
	}
}

func TestRefusedCreateIsTerminal(t *testing.T) {
	h := newHarness(t)
	h.adapter.createErrs = []error{provider.NewError("create", 403, "NEON_RESPONSE", provider.RetryNever)}
	if operation := h.planAndRun(t); operation.State != lifecycle.StateTerminalFailure || len(h.adapter.created) != 1 {
		t.Fatalf("state=%s", operation.State)
	}
}

func TestIdentityMismatchStopsBeforeMinting(t *testing.T) {
	h := newHarness(t)
	h.adapter.identity = provider.Identity{Provider: "neon", ID: "acct-other"}
	if operation := h.planAndRun(t); operation.State != lifecycle.StateTerminalFailure || len(h.adapter.created) != 0 {
		t.Fatalf("state=%s created=%d", operation.State, len(h.adapter.created))
	}
}

func TestStageFailureRollsBackAndQuarantinesNewCredential(t *testing.T) {
	h := newHarness(t)
	h.deployer.stageErrs = []error{errors.New("vercel write failed")}
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateQuarantined || len(h.deployer.rolledBack) != 0 || len(h.adapter.revoked) != 1 || h.adapter.revoked[0] != "role:p/b/app_b" {
		t.Fatalf("state=%s rolledBack=%v revoked=%v", operation.State, h.deployer.rolledBack, h.adapter.revoked)
	}
}

func TestUnhealthyActivationRollsBackDeployment(t *testing.T) {
	h := newHarness(t)
	h.deployer.unhealthy = true
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateQuarantined || len(h.deployer.rolledBack) != 1 || h.deployer.rolledBack[0] != "dpl_1" || len(h.adapter.revoked) != 1 || h.adapter.revoked[0] != "role:p/b/app_b" {
		t.Fatalf("state=%s rolledBack=%v revoked=%v", operation.State, h.deployer.rolledBack, h.adapter.revoked)
	}
	chain, _ := h.store.LoadEvidence(context.Background(), "op-1", h.engine.PolicyKey)
	codes := []string{}
	for _, evidence := range chain {
		codes = append(codes, evidence.Stage+"/"+evidence.Code)
	}
	joined := strings.Join(codes, " ")
	if !strings.Contains(joined, "activate/unhealthy") || !strings.Contains(joined, "rollback/rolled-back") || !strings.HasSuffix(joined, "quarantine/revoked") {
		t.Fatalf("codes=%s", joined)
	}
}

func TestQuarantineRevokeFailureIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.deployer.unhealthy = true
	h.adapter.revokeErrs = []error{provider.NewError("revoke", 500, "NEON_RESPONSE", provider.RetryAmbiguous)}
	operation := h.planAndRun(t)
	chain, _ := h.store.LoadEvidence(context.Background(), "op-1", h.engine.PolicyKey)
	if operation.State != lifecycle.StateQuarantined || chain[len(chain)-1].Code != "revoke-failed" {
		t.Fatalf("state=%s last=%s", operation.State, chain[len(chain)-1].Code)
	}
}

func TestSafeActivateFailureRetriesWithoutRestaging(t *testing.T) {
	h := newHarness(t)
	h.deployer.activateErrs = []error{provider.NewError("activate", 503, "VERCEL_RESPONSE", provider.RetrySafe)}
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateGracePeriod || len(h.deployer.staged) != 1 || len(h.deployer.activated) != 2 || len(h.adapter.created) != 1 {
		t.Fatalf("state=%s staged=%d activated=%d", operation.State, len(h.deployer.staged), len(h.deployer.activated))
	}
}

func TestAmbiguousRevokeRequiresReconciliation(t *testing.T) {
	h := newHarness(t)
	h.adapter.revokeErrs = []error{provider.NewError("revoke", 500, "NEON_RESPONSE", provider.RetryAmbiguous)}
	h.planAndRun(t)
	h.clock = h.clock.Add(16 * time.Minute)
	operation, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || operation.State != lifecycle.StateReconciliationRequired || len(h.adapter.revoked) != 1 {
		t.Fatalf("state=%s err=%v", operation.State, err)
	}
}

func TestRecordRevisionMustAdvance(t *testing.T) {
	h := newHarness(t)
	h.records.revision = 0 // the writer will return revision 1, equal to the previous one
	if operation := h.planAndRun(t); operation.State != lifecycle.StateReconciliationRequired {
		t.Fatalf("state=%s", operation.State)
	}
}

func TestLeaseHeldByAnotherRunIsReported(t *testing.T) {
	h := newHarness(t)
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.store.AcquireLease(context.Background(), "bundle", "someone-else", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := h.engine.Run(context.Background(), "op-1"); !errors.Is(err, ErrBusy) || len(h.adapter.created) != 0 {
		t.Fatalf("err=%v", err)
	}
}

func TestUnpersistedTransitionStopsBeforeMutation(t *testing.T) {
	h := newHarness(t)
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	h.store.saveErr = errors.New("vault unavailable")
	if _, err := h.engine.Run(context.Background(), "op-1"); err == nil || len(h.adapter.created) != 0 {
		t.Fatalf("err=%v created=%d", err, len(h.adapter.created))
	}
}

func TestPlanRefusesUnapprovedCredentialClassOrTarget(t *testing.T) {
	h := newHarness(t)
	input := h.input()
	input.CredentialClass = "api-key"
	if _, err := h.engine.Plan(context.Background(), input); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
	input = h.input()
	input.Target.EnvironmentID = "production"
	if _, err := h.engine.Plan(context.Background(), input); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
	input = h.input()
	input.ProviderIdentity = "acct-other"
	if _, err := h.engine.Plan(context.Background(), input); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err=%v", err)
	}
}

func TestInterruptedCreateIsNotReplayed(t *testing.T) {
	h := newHarness(t)
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	// Simulate an earlier run that died after entering acquiring.
	operation, revision, _ := h.store.LoadOperation(context.Background(), "op-1")
	if err := operation.Move(lifecycle.StateAcquiring, h.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SaveOperation(context.Background(), operation, revision); err != nil {
		t.Fatal(err)
	}
	resumed, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || resumed.State != lifecycle.StateReconciliationRequired || len(h.adapter.created) != 0 {
		t.Fatalf("state=%s err=%v created=%d", resumed.State, err, len(h.adapter.created))
	}
}

func TestInterruptedDeploymentStepRollsBack(t *testing.T) {
	for _, state := range []lifecycle.State{lifecycle.StateStaging, lifecycle.StateActivating} {
		h := newHarness(t)
		if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
			t.Fatal(err)
		}
		operation, revision, _ := h.store.LoadOperation(context.Background(), "op-1")
		operation.State = lifecycle.StateStored
		operation.NewRecordRevision = 2
		operation.NewCredentialID = "role:p/b/app_b"
		if state == lifecycle.StateActivating {
			operation.State = lifecycle.StateStaged
			operation.DeploymentID = "dpl_1"
		}
		if err := operation.Move(state, h.clock); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.SaveOperation(context.Background(), operation, revision); err != nil {
			t.Fatal(err)
		}
		resumed, err := h.engine.Run(context.Background(), "op-1")
		if err != nil || resumed.State != lifecycle.StateQuarantined || len(h.deployer.staged) != 0 || len(h.deployer.activated) != 0 || len(h.adapter.revoked) != 1 {
			t.Fatalf("%s: state=%s err=%v staged=%d activated=%d revoked=%v", state, resumed.State, err, len(h.deployer.staged), len(h.deployer.activated), h.adapter.revoked)
		}
		if state == lifecycle.StateActivating && (len(h.deployer.rolledBack) != 1 || h.deployer.rolledBack[0] != "dpl_1") {
			t.Fatalf("rolledBack=%v", h.deployer.rolledBack)
		}
	}
}

func TestPlanRequiresCompensationCapabilities(t *testing.T) {
	for _, missing := range []string{"rollback", "revoke"} {
		h := newHarness(t)
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		h.engine.PolicyKey = private.Public().(ed25519.PublicKey)
		h.engine.DevicePrivate = private
		operations := []string{}
		for _, action := range h.policy.Operations {
			if action != missing {
				operations = append(operations, action)
			}
		}
		h.policy.Operations = operations
		h.policy.PublicKey, h.policy.Signature = nil, nil
		if err := h.policy.Sign(private); err != nil {
			t.Fatal(err)
		}
		h.store.policies[h.policy.ID] = h.policy
		if _, err := h.engine.Plan(context.Background(), h.input()); !errors.Is(err, ErrNotApproved) {
			t.Fatalf("policy without %s accepted: %v", missing, err)
		}
	}
}

func TestExhaustedStageRetriesQuarantineMintedCredential(t *testing.T) {
	h := newHarness(t)
	safe := provider.NewError("stage", 503, "VERCEL_RESPONSE", provider.RetrySafe)
	h.deployer.stageErrs = []error{safe, safe, safe}
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateQuarantined || len(h.deployer.staged) != 3 || len(h.adapter.revoked) != 1 || h.adapter.revoked[0] != "role:p/b/app_b" {
		t.Fatalf("state=%s staged=%d revoked=%v", operation.State, len(h.deployer.staged), h.adapter.revoked)
	}
}

func TestExhaustedRevokeRetriesRequireReconciliation(t *testing.T) {
	h := newHarness(t)
	safe := provider.NewError("revoke", 503, "NEON_RESPONSE", provider.RetrySafe)
	h.adapter.revokeErrs = []error{safe, safe, safe}
	h.planAndRun(t)
	h.clock = h.clock.Add(16 * time.Minute)
	operation, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || operation.State != lifecycle.StateReconciliationRequired || len(h.adapter.revoked) != 3 {
		t.Fatalf("state=%s err=%v revoked=%d", operation.State, err, len(h.adapter.revoked))
	}
}

type slowDeployer struct {
	fakeDeployer
	advance func()
}

func (deployer *slowDeployer) Stage(ctx context.Context, request lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error) {
	deployer.advance()
	return deployer.fakeDeployer.Stage(ctx, request)
}

func TestLeaseExpiryFencesTheRun(t *testing.T) {
	h := newHarness(t)
	slow := &slowDeployer{advance: func() { h.clock = h.clock.Add(time.Hour) }}
	h.engine.Deployer = slow
	h.engine.LeaseTTL = 10 * time.Minute
	if _, err := h.engine.Plan(context.Background(), h.input()); err != nil {
		t.Fatal(err)
	}
	operation, err := h.engine.Run(context.Background(), "op-1")
	if !errors.Is(err, ErrLeaseExpired) || operation.State != lifecycle.StateStaged || len(slow.activated) != 0 {
		t.Fatalf("state=%s err=%v activated=%d", operation.State, err, len(slow.activated))
	}
	// A later run, holding a fresh lease, resumes from the persisted state.
	resumed, err := h.engine.Run(context.Background(), "op-1")
	if err != nil || resumed.State != lifecycle.StateGracePeriod {
		t.Fatalf("state=%s err=%v", resumed.State, err)
	}
}

type partialStageDeployer struct{ fakeDeployer }

func (deployer *partialStageDeployer) Stage(ctx context.Context, request lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error) {
	deployer.staged = append(deployer.staged, request)
	return lifecycle.DeploymentEvidence{DeploymentID: "vd-partial", Status: "unexpected-promotion"}, provider.NewError("stage", 0, "UNEXPECTED_PROMOTION_ROLLBACK_REQUIRED", provider.RetryAmbiguous)
}

func TestFailedStageKeepsWorkflowForRollback(t *testing.T) {
	h := newHarness(t)
	partial := &partialStageDeployer{}
	h.engine.Deployer = partial
	operation := h.planAndRun(t)
	if operation.State != lifecycle.StateQuarantined || len(partial.rolledBack) != 1 || partial.rolledBack[0] != "vd-partial" || operation.DeploymentID != "vd-partial" {
		t.Fatalf("state=%s rolledBack=%v deployment=%s", operation.State, partial.rolledBack, operation.DeploymentID)
	}
}
