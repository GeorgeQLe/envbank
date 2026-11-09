package rotationrun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/rotation"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"github.com/GeorgeQLe/envbank/internal/vercelworkflow"
)

// memVault is an in-memory sync service: encrypted records by ID and typed
// objects by kind/key, each with optimistic revisions.
type memVault struct {
	mu        sync.Mutex
	records   map[string]protocol.Record
	objects   map[string]vaultobject.VaultObject
	revisions map[string]int64
	now       func() time.Time
}

func newMemVault(now func() time.Time) *memVault {
	return &memVault{records: map[string]protocol.Record{}, objects: map[string]vaultobject.VaultObject{}, revisions: map[string]int64{}, now: now}
}
func (vault *memVault) ListRecords() ([]protocol.Record, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	out := []protocol.Record{}
	for _, record := range vault.records {
		out = append(out, record)
	}
	return out, nil
}
func (vault *memVault) PutRecord(id string, request protocol.PutRecordRequest) (protocol.Record, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.records[id].Revision != request.ExpectedRevision {
		return protocol.Record{}, errors.New("record revision conflict")
	}
	record := protocol.Record{ID: id, Revision: request.ExpectedRevision + 1, Blob: request.Blob, ModifiedAt: vault.now().Format(time.RFC3339)}
	vault.records[id] = record
	return record, nil
}
func (vault *memVault) GetObject(_ []byte, kind, key string) (vaultobject.VaultObject, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	object, ok := vault.objects[kind+"\x00"+key]
	if !ok {
		return vaultobject.VaultObject{}, errors.New("object not found")
	}
	return object, nil
}
func (vault *memVault) PutObject(_ []byte, kind, key string, payload any, expected int64) (vaultobject.VaultObject, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	id := kind + "\x00" + key
	if vault.revisions[id] != expected {
		return vaultobject.VaultObject{}, errors.New("object revision conflict")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return vaultobject.VaultObject{}, err
	}
	vault.revisions[id]++
	object := vaultobject.VaultObject{Kind: kind, Key: key, Revision: vault.revisions[id], ModifiedAt: vault.now().Format(time.RFC3339), Payload: raw}
	vault.objects[id] = object
	return object, nil
}

// engineStore adapts memVault to rotation.Store using the real lifecycle
// object encodings.
type engineStore struct {
	vault *memVault
	key   []byte
}

func (store *engineStore) LoadPolicy(_ context.Context, id string) (lifecycle.AutomationPolicy, int64, error) {
	object, err := store.vault.GetObject(store.key, vaultobject.KindAutomationPolicy, id)
	if err != nil {
		return lifecycle.AutomationPolicy{}, 0, err
	}
	var policy lifecycle.AutomationPolicy
	return policy, object.Revision, json.Unmarshal(object.Payload, &policy)
}
func (store *engineStore) SaveOperation(_ context.Context, operation lifecycle.Operation, expected int64) (int64, error) {
	if err := operation.Validate(); err != nil {
		return 0, err
	}
	object, err := store.vault.PutObject(store.key, vaultobject.KindLifecycleOperation, operation.ID, operation, expected)
	return object.Revision, err
}
func (store *engineStore) LoadOperation(_ context.Context, id string) (lifecycle.Operation, int64, error) {
	object, err := store.vault.GetObject(store.key, vaultobject.KindLifecycleOperation, id)
	if err != nil {
		return lifecycle.Operation{}, 0, err
	}
	var operation lifecycle.Operation
	return operation, object.Revision, json.Unmarshal(object.Payload, &operation)
}
func (store *engineStore) AcquireLease(_ context.Context, bundleID, owner string, ttl time.Duration) (lifecycle.Lease, int64, error) {
	now := store.vault.now()
	return lifecycle.Lease{Bundle: bundleID, Owner: owner, AcquiredAt: now.Format(time.RFC3339), ExpiresAt: now.Add(ttl).Format(time.RFC3339)}, 1, nil
}
func (store *engineStore) ReleaseLease(context.Context, lifecycle.Lease, int64) error { return nil }
func (store *engineStore) LoadEvidence(_ context.Context, id string, public ed25519.PublicKey) ([]lifecycle.Evidence, error) {
	object, err := store.vault.GetObject(store.key, vaultobject.KindOperationEvidence, id)
	if err != nil {
		return []lifecycle.Evidence{}, nil
	}
	var chain []lifecycle.Evidence
	if err := json.Unmarshal(object.Payload, &chain); err != nil {
		return nil, err
	}
	return chain, lifecycle.VerifyEvidenceChain(chain, public)
}
func (store *engineStore) AppendEvidence(ctx context.Context, id string, evidence lifecycle.Evidence, public ed25519.PublicKey) (int64, error) {
	chain, err := store.LoadEvidence(ctx, id, public)
	if err != nil {
		return 0, err
	}
	expected := int64(0)
	if object, err := store.vault.GetObject(store.key, vaultobject.KindOperationEvidence, id); err == nil {
		expected = object.Revision
	}
	chain = append(chain, evidence)
	if err := lifecycle.VerifyEvidenceChain(chain, public); err != nil {
		return 0, err
	}
	object, err := store.vault.PutObject(store.key, vaultobject.KindOperationEvidence, id, chain, expected)
	return object.Revision, err
}

type fakeNeon struct {
	created []lifecycle.CredentialRequest
	revoked []string
	minted  int
}

func (*fakeNeon) Identify(context.Context) (provider.Identity, error) {
	return provider.Identity{Provider: "neon", ID: "acct-1"}, nil
}
func (*fakeNeon) Capabilities() map[string]lifecycle.CredentialCapability {
	return map[string]lifecycle.CredentialCapability{"role-password": lifecycle.CapabilityAutomatic}
}
func (neon *fakeNeon) Create(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	neon.created = append(neon.created, request)
	neon.minted++
	role := request.Parameters["role_name"][0]
	receipt, err := sink.StoreBytes(ctx, []byte("postgresql://"+role+":npg_minted_"+strings.Repeat("x", neon.minted)+"@host/db"))
	if err != nil {
		return lifecycle.CredentialEvidence{}, err
	}
	return lifecycle.CredentialEvidence{CredentialID: "role:proj/br/" + role, CreatedAt: "2026-11-09T00:00:00Z", Receipt: receipt}, nil
}
func (*fakeNeon) Validate(context.Context, string) (provider.VerifyEvidence, error) {
	return provider.VerifyEvidence{}, errors.New("unused")
}
func (neon *fakeNeon) Revoke(_ context.Context, id string) error {
	neon.revoked = append(neon.revoked, id)
	return nil
}

// snapshotDeployer asserts the deployer sees the stored revision in the
// snapshot, the contract the real Vercel deployer enforces.
type snapshotDeployer struct {
	vault  *Vault
	bundle string
	staged []lifecycle.DeploymentRequest
}

func (deployer *snapshotDeployer) Stage(_ context.Context, request lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error) {
	deployer.staged = append(deployer.staged, request)
	snapshot, _, err := deployer.vault.loadSnapshot(deployer.bundle)
	if err != nil {
		return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "SNAPSHOT_UNAVAILABLE", provider.RetryNever)
	}
	for record, want := range request.RecordRevisions {
		if snapshot.RecordRevisions[record] != want {
			return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "SNAPSHOT_STALE", provider.RetryNever)
		}
	}
	return lifecycle.DeploymentEvidence{DeploymentID: "vd-1", Status: "promote-pending", At: "2026-11-09T00:00:00Z"}, nil
}
func (*snapshotDeployer) Activate(context.Context, lifecycle.DeploymentRequest, string) (lifecycle.HealthEvidence, error) {
	return lifecycle.HealthEvidence{SuccessfulChecks: 3, FirstSuccessAt: "2026-11-09T00:00:00Z", LastSuccessAt: "2026-11-09T00:00:40Z", Healthy: true}, nil
}
func (*snapshotDeployer) Rollback(context.Context, lifecycle.DeploymentRequest, string) error {
	return nil
}

type harness struct {
	runner   *Runner
	vault    *Vault
	mem      *memVault
	neon     *fakeNeon
	deployer *snapshotDeployer
	clock    time.Time
	policy   lifecycle.AutomationPolicy
	document *contract.Document
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{clock: time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC), neon: &fakeNeon{}}
	now := func() time.Time { return h.clock }
	h.mem = newMemVault(now)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	h.vault = &Vault{API: h.mem, VaultID: "vault", VaultKey: key, Now: now}
	h.document = &contract.Document{Digest: strings.Repeat("a", 64), Manifest: contract.Manifest{Version: 2, Bundle: "arcade/app", Environment: "staging",
		Records:     map[string]contract.Record{"DATABASE_URL": {Source: "import", Sensitivity: "secret"}},
		Credentials: map[string]contract.Credential{"db": {Provider: "neon", Type: "role-password", Mode: "automatic", Record: "DATABASE_URL", Validation: "role-lookup", Revoke: "reset-password", Parameters: map[string]string{"project_id": "proj", "branch_id": "br", "database_name": "appdb"}, Alternates: []string{"app_a", "app_b"}}},
		Targets:     map[string]contract.Target{"vercel": {TeamID: "team_1", Project: "app", ProjectID: "prj_1", Environment: "preview", GitBranch: "main", Services: map[string]contract.Service{"environment": {Variables: map[string]contract.Variable{"DATABASE_URL": {Source: "record", Record: "DATABASE_URL"}}}}}}}}
	// Seed the prepared record at revision 1 and a matching snapshot.
	physical := bundle.PhysicalName("arcade/app", "DATABASE_URL")
	id, blob, err := client.EncryptRecord("vault", key, protocol.SecretRecord{Name: physical, Value: "postgresql://app_a:old@host/db", CreatedAt: "2026-11-01T00:00:00Z", RotatedAt: "2026-11-01T00:00:00Z", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.mem.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: 0, Blob: blob}); err != nil {
		t.Fatal(err)
	}
	snapshot := bundle.Snapshot{Version: bundle.SnapshotVersion, Bundle: "arcade/app", ManifestDigest: h.document.Digest, PhysicalToLogical: map[string]string{physical: "DATABASE_URL"}, Sources: map[string]bundle.SourceStatus{"DATABASE_URL": {Source: "import", Status: "ready", Sensitivity: "secret"}}, RecordRevisions: map[string]int64{"DATABASE_URL": 1}, CreatedAt: h.clock.Format(time.RFC3339)}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mem.PutObject(key, vaultobject.KindBundleSnapshot, "arcade/app", snapshot, 0); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := vercelworkflow.ScopeForManifest(h.document)
	if err != nil {
		t.Fatal(err)
	}
	h.policy = lifecycle.AutomationPolicy{Version: lifecycle.PolicyVersion, ID: "rotation-arcade", VaultID: "vault", Bundle: "arcade/app", ManifestDigest: h.document.Digest, Environment: "staging", ProviderIdentities: map[string]string{"neon": "acct-1", "vercel": "team_1:prj_1"}, CredentialClasses: []string{"role-password", "vercel-environment-secret"}, Operations: []string{"create", "stage", "activate", "verify", "rollback", "revoke"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: "prj_1", EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "on-demand", HealthChecks: []string{"/api/health"}, GracePeriod: "15m", Rollback: "previous-deployment", RetryBudget: 2, ExpiresAt: h.clock.Add(30 * 24 * time.Hour).Format(time.RFC3339), ApprovingDevice: "device-1"}
	if err := h.policy.Sign(private); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mem.PutObject(key, vaultobject.KindAutomationPolicy, h.policy.ID, h.policy, 0); err != nil {
		t.Fatal(err)
	}
	h.deployer = &snapshotDeployer{vault: h.vault, bundle: "arcade/app"}
	engine := &rotation.Engine{Store: &engineStore{vault: h.mem, key: key}, Deployer: h.deployer, Credentials: h.neon, Records: &RecordStore{Vault: h.vault, Document: h.document}, VaultID: "vault", DeviceID: "device-1", DevicePrivate: private, PolicyKey: public, OwnerVerify: func(lifecycle.AutomationPolicy, time.Time) error { return nil }, Now: now}
	h.runner = &Runner{Engine: engine, Vault: h.vault, Document: h.document}
	return h
}

func (h *harness) target(t *testing.T) lifecycle.TargetPolicy {
	t.Helper()
	target, err := h.runner.Target()
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestManifestTargetMatchesPolicyShape(t *testing.T) {
	h := newHarness(t)
	target := h.target(t)
	if target != h.policy.Targets[0] {
		t.Fatalf("target=%+v policy=%+v", target, h.policy.Targets[0])
	}
}

func TestRotationAlternatesRolesAndAdvancesSnapshotAndBinding(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.runner.Plan(ctx, "db", h.policy.ID); !errors.Is(err, ErrUnbound) {
		t.Fatalf("unbound plan err=%v", err)
	}
	if _, err := h.runner.Bind(ctx, "db", "role:proj/br/app_a"); err != nil {
		t.Fatal(err)
	}
	operation, err := h.runner.Plan(ctx, "db", h.policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.PreviousCredentialID != "role:proj/br/app_a" || operation.CreateParameters["role_name"][0] != "app_b" || operation.CreateParameters["database_name"][0] != "appdb" || operation.PreviousRecordRevision != 1 || operation.ProviderIdentity != "acct-1" {
		t.Fatalf("operation=%+v", operation)
	}
	resting, err := h.runner.Run(ctx, operation.ID)
	if err != nil || resting.State != lifecycle.StateGracePeriod || resting.NewRecordRevision != 2 || resting.NewCredentialID != "role:proj/br/app_b" {
		t.Fatalf("state=%s err=%v op=%+v", resting.State, err, resting)
	}
	snapshot, _, err := h.vault.loadSnapshot("arcade/app")
	if err != nil || snapshot.RecordRevisions["DATABASE_URL"] != 2 || len(snapshot.PreviousRecordRevisions["DATABASE_URL"]) != 1 || snapshot.PreviousRecordRevisions["DATABASE_URL"][0] != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if h.deployer.staged[0].RecordRevisions["DATABASE_URL"] != 2 {
		t.Fatalf("deployer saw %+v", h.deployer.staged[0])
	}
	records, _ := h.mem.ListRecords()
	decrypted, err := client.DecryptRecords("vault", h.vault.VaultKey, records)
	if err != nil || len(decrypted) != 1 || decrypted[0].Revision != 2 || !strings.Contains(decrypted[0].Value, "app_b:npg_minted_x@") || decrypted[0].CreatedAt != "2026-11-01T00:00:00Z" {
		t.Fatalf("records=%+v err=%v", decrypted, err)
	}
	binding, _, err := h.vault.LoadBinding("arcade/app", "DATABASE_URL")
	if err != nil || binding.CredentialID != "role:proj/br/app_b" || binding.RecordRevision != 2 || binding.OperationID != operation.ID {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	// Finish the grace period: the retired role is reset.
	h.clock = h.clock.Add(16 * time.Minute)
	final, err := h.runner.Run(ctx, operation.ID)
	if err != nil || final.State != lifecycle.StateComplete || len(h.neon.revoked) != 1 || h.neon.revoked[0] != "role:proj/br/app_a" {
		t.Fatalf("state=%s err=%v revoked=%v", final.State, err, h.neon.revoked)
	}
	// The next rotation goes back to app_a.
	next, err := h.runner.Plan(ctx, "db", h.policy.ID)
	if err != nil || next.CreateParameters["role_name"][0] != "app_a" || next.PreviousCredentialID != "role:proj/br/app_b" || next.PreviousRecordRevision != 2 {
		t.Fatalf("next=%+v err=%v", next, err)
	}
}

func TestBindRejectsForeignOrNonAlternateIDs(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{"api-key:42", "role:proj/br/other", "role:proj/br/app_a/extra"} {
		if _, err := h.runner.Bind(context.Background(), "db", id); err == nil {
			t.Fatalf("bind %q accepted", id)
		}
	}
	if _, err := h.runner.Bind(context.Background(), "missing", "role:proj/br/app_a"); err == nil {
		t.Fatal("unknown credential accepted")
	}
}

func TestPlanRefusesDriftedRecordRevision(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.runner.Bind(ctx, "db", "role:proj/br/app_a"); err != nil {
		t.Fatal(err)
	}
	snapshot, revision, _ := h.vault.loadSnapshot("arcade/app")
	snapshot.RecordRevisions["DATABASE_URL"] = 5
	if _, err := h.mem.PutObject(h.vault.VaultKey, vaultobject.KindBundleSnapshot, "arcade/app", snapshot, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := h.runner.Plan(ctx, "db", h.policy.ID); err == nil || !strings.Contains(err.Error(), "rebind") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecordStoreRefusesUndeclaredRecordAndStaleSnapshot(t *testing.T) {
	h := newHarness(t)
	store := &RecordStore{Vault: h.vault, Document: h.document}
	provide := func(consume func([]byte) error) error { return consume([]byte("value")) }
	if _, err := store.StoreSecret(context.Background(), "OTHER", provide); err == nil {
		t.Fatal("undeclared record stored")
	}
	snapshot, revision, _ := h.vault.loadSnapshot("arcade/app")
	snapshot.RecordRevisions["DATABASE_URL"] = 7
	if _, err := h.mem.PutObject(h.vault.VaultKey, vaultobject.KindBundleSnapshot, "arcade/app", snapshot, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StoreSecret(context.Background(), "DATABASE_URL", provide); err == nil {
		t.Fatal("stale snapshot accepted")
	}
}

func TestMCPRotationRunPlansByCredentialAndResumesByOperation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	backend := &MCPBackend{Runners: map[string]*Runner{"neon": h.runner}, PolicyID: h.policy.ID}
	result, err := backend.Call(ctx, "envbank_rotation_run", mcpserver.Request{Credential: "db"})
	if err != nil || result.BlockerCode != "ROTATION_CREDENTIAL_UNBOUND" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := h.runner.Bind(ctx, "db", "role:proj/br/app_a"); err != nil {
		t.Fatal(err)
	}
	result, err = backend.Call(ctx, "envbank_rotation_run", mcpserver.Request{Credential: "db", Provider: "neon"})
	if err != nil || result.BlockerCode != "" || result.Stage != string(lifecycle.StateGracePeriod) || !strings.HasPrefix(result.OperationID, "rot-") || result.ResourceIDs[0] != "vd-1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	h.clock = h.clock.Add(16 * time.Minute)
	resumed, err := backend.Call(ctx, "envbank_rotation_run", mcpserver.Request{OperationID: result.OperationID})
	if err != nil || resumed.Stage != string(lifecycle.StateComplete) {
		t.Fatalf("resumed=%+v err=%v", resumed, err)
	}
	if mismatch, _ := backend.Call(ctx, "envbank_rotation_run", mcpserver.Request{Credential: "db", Provider: "stripe"}); mismatch.BlockerCode != "POLICY_BINDING_MISMATCH" {
		t.Fatalf("mismatch=%+v", mismatch)
	}
	if due, _ := backend.Call(ctx, "envbank_rotation_due", mcpserver.Request{}); due.BlockerCode != "ROTATION_SCHEDULE_NOT_IMPLEMENTED" {
		t.Fatalf("due=%+v", due)
	}
	if other, _ := backend.Call(ctx, "envbank_workflow_status", mcpserver.Request{}); other.BlockerCode != "PROVIDER_ROTATION_UNAVAILABLE" {
		t.Fatalf("other=%+v", other)
	}
}

func TestMCPResultNeverCarriesValues(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.runner.Bind(ctx, "db", "role:proj/br/app_a"); err != nil {
		t.Fatal(err)
	}
	backend := &MCPBackend{Runners: map[string]*Runner{"neon": h.runner}, PolicyID: h.policy.ID}
	result, _ := backend.Call(ctx, "envbank_rotation_run", mcpserver.Request{Credential: "db"})
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "npg_") || strings.Contains(string(raw), "postgresql://") {
		t.Fatalf("result leaks a value: %s", raw)
	}
}
