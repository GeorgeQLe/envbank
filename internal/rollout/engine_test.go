package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

type memoryStore struct {
	plans        map[string]ProviderPlan
	planRevision map[string]int64
	operations   map[string]Operation
	opRevision   map[string]int64
	records      map[string][]byte
	snapshotOK   bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{plans: map[string]ProviderPlan{}, planRevision: map[string]int64{},
		operations: map[string]Operation{}, opRevision: map[string]int64{},
		records: map[string][]byte{}, snapshotOK: true}
}

func (store *memoryStore) SavePlan(_ context.Context, plan ProviderPlan, expected int64) (int64, error) {
	if store.planRevision[plan.ID()] != expected {
		return 0, errors.New("plan conflict")
	}
	store.planRevision[plan.ID()]++
	store.plans[plan.ID()] = cloneJSON(plan)
	return store.planRevision[plan.ID()], nil
}

func (store *memoryStore) LoadPlan(_ context.Context, id string) (ProviderPlan, int64, error) {
	plan, exists := store.plans[id]
	if !exists {
		return ProviderPlan{}, 0, errors.New("plan missing")
	}
	return cloneJSON(plan), store.planRevision[id], nil
}

func (store *memoryStore) SaveOperation(_ context.Context, operation Operation, expected int64) (int64, error) {
	if store.opRevision[operation.ID] != expected {
		return 0, errors.New("operation conflict")
	}
	if err := operation.Validate(); err != nil {
		return 0, err
	}
	store.opRevision[operation.ID]++
	store.operations[operation.ID] = cloneJSON(operation)
	return store.opRevision[operation.ID], nil
}

func (store *memoryStore) LoadOperation(_ context.Context, id string) (Operation, int64, error) {
	operation, exists := store.operations[id]
	if !exists {
		return Operation{}, 0, errors.New("operation missing")
	}
	return cloneJSON(operation), store.opRevision[id], nil
}

func (store *memoryStore) ValidateSnapshot(_ context.Context, _ ProviderPlan) error {
	if !store.snapshotOK {
		return errors.New("provider plan does not match the current bundle snapshot")
	}
	return nil
}

func (store *memoryStore) LoadRecord(_ context.Context, _ string, logical string, expected int64) ([]byte, error) {
	value, exists := store.records[fmt.Sprintf("%s:%d", logical, expected)]
	if !exists {
		return nil, errors.New("record missing or stale")
	}
	return append([]byte(nil), value...), nil
}

type fakeWrite struct {
	action string
	key    string
	value  string
}

type fakeAdapter struct {
	capabilities provider.Capabilities
	identity     provider.Identity
	metadata     provider.MetadataState
	writes       []fakeWrite
	verifyNames  []string
	writeErrors  []error
	verifyResult provider.Verification
}

type fakeBatchAdapter struct {
	*fakeAdapter
	stages         int
	stagedValues   []string
	verifyVersion  []string
	verifyExpected []provider.Presence
}

func (adapter *fakeBatchAdapter) Stage(_ context.Context, requests []provider.WriteRequest) (provider.WriteEvidence, error) {
	adapter.stages++
	for _, request := range requests {
		if err := request.ViewSecret(func(value []byte) error {
			adapter.stagedValues = append(adapter.stagedValues, string(value))
			return nil
		}); err != nil {
			return provider.WriteEvidence{}, err
		}
	}
	return provider.WriteEvidence{ProviderOperationID: "staged-version-id",
		CommittedAt: rolloutTime.Format(time.RFC3339)}, nil
}

func (adapter *fakeBatchAdapter) Verify(_ context.Context, request provider.VerifyRequest) (provider.VerifyEvidence, error) {
	adapter.verifyVersion = append(adapter.verifyVersion, request.ProviderOperationID)
	adapter.verifyExpected = append(adapter.verifyExpected, request.ExpectedPresence)
	return provider.VerifyEvidence{Result: provider.VerificationVerified, Presence: request.ExpectedPresence,
		VerifiedAt: rolloutTime.Format(time.RFC3339)}, nil
}

func (adapter *fakeAdapter) Capabilities() provider.Capabilities { return adapter.capabilities }
func (adapter *fakeAdapter) Identity(context.Context) (provider.Identity, error) {
	return adapter.identity, nil
}
func (adapter *fakeAdapter) Inspect(context.Context, provider.Target) (provider.MetadataState, error) {
	return cloneJSON(adapter.metadata), nil
}
func (adapter *fakeAdapter) Write(_ context.Context, request provider.WriteRequest) (provider.WriteEvidence, error) {
	call := fakeWrite{action: request.Service + "/" + request.Name, key: request.IdempotencyKey}
	if err := request.ViewSecret(func(value []byte) error { call.value = string(value); return nil }); err != nil {
		return provider.WriteEvidence{}, err
	}
	adapter.writes = append(adapter.writes, call)
	if len(adapter.writeErrors) != 0 {
		err := adapter.writeErrors[0]
		adapter.writeErrors = adapter.writeErrors[1:]
		if err != nil {
			return provider.WriteEvidence{}, err
		}
	}
	return provider.WriteEvidence{ProviderOperationID: "provider-operation",
		CommittedAt: rolloutTime.Format(time.RFC3339)}, nil
}
func (adapter *fakeAdapter) Verify(_ context.Context, request provider.VerifyRequest) (provider.VerifyEvidence, error) {
	adapter.verifyNames = append(adapter.verifyNames, request.Service+"/"+request.Name)
	result := adapter.verifyResult
	if result == "" {
		result = provider.VerificationVerified
	}
	return provider.VerifyEvidence{Result: result, Presence: provider.PresencePresent,
		VerifiedAt: rolloutTime.Format(time.RFC3339)}, nil
}

var rolloutTime = time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)

func fixtureEngine(actionCount int) (*Engine, *memoryStore, *fakeAdapter, PlanInput) {
	store := newMemoryStore()
	adapter := &fakeAdapter{
		capabilities: provider.Capabilities{Create: true, ReadMetadata: true, Update: true,
			Validate: true, Revoke: true},
		identity: provider.Identity{Provider: "fake", ID: "credential-scope"},
		metadata: provider.MetadataState{Target: provider.Target{ProjectID: "project-id",
			EnvironmentID: "environment-id", ServiceIDs: map[string]string{"api": "api-id"}},
			Variables: map[string]map[string]provider.VariableMetadata{"api": {}}},
	}
	actions := make([]Action, actionCount)
	for index := range actions {
		name := fmt.Sprintf("SECRET_%d", index+1)
		record := fmt.Sprintf("record-%d", index+1)
		actions[index] = Action{ID: fmt.Sprintf("action-%d", index+1), Operation: "upsert",
			Service: "api", ServiceID: "api-id", Name: name, Record: record,
			ExpectedRecordRevision: int64(index + 4)}
		store.records[fmt.Sprintf("%s:%d", record, index+4)] = []byte("plaintext-SENTINEL-" + name)
	}
	input := PlanInput{Bundle: "short-editor/example/staging",
		ManifestDigest: strings.Repeat("a", 64), SnapshotRevision: 3,
		Target: TargetBinding{ProjectID: "project-id", EnvironmentID: "environment-id",
			ServiceIDs: map[string]string{"api": "api-id"}}, Actions: actions}
	engine := &Engine{Adapter: adapter, Store: store, Now: func() time.Time { return rolloutTime },
		Random: func(value []byte) error {
			for index := range value {
				value[index] = byte(index + 1)
			}
			return nil
		}}
	return engine, store, adapter, input
}

func TestEnginePlansAppliesAndPersistsRedactedEvidence(t *testing.T) {
	engine, store, adapter, input := fixtureEngine(1)
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapter.writes) != 0 || plan.ID() == "" || store.planRevision[plan.ID()] != 1 {
		t.Fatal("planning was not a read-only provider operation with durable local state")
	}
	confirmations := 0
	operation, err := engine.Apply(context.Background(), plan.ID(), func(_ context.Context, request Confirmation) error {
		confirmations++
		if request.Kind != "apply" || request.ActionCount != 1 {
			t.Fatalf("unexpected confirmation: %+v", request)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != StatusReady || confirmations != 1 || len(adapter.writes) != 1 || len(adapter.verifyNames) != 1 {
		t.Fatalf("unexpected completed operation: status=%s confirmations=%d writes=%d verifies=%d",
			operation.Status, confirmations, len(adapter.writes), len(adapter.verifyNames))
	}
	if adapter.writes[0].value != "plaintext-SENTINEL-SECRET_1" {
		t.Fatal("adapter did not receive the exact record value")
	}
	raw, err := json.Marshal(store.operations[operation.ID])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "plaintext-SENTINEL") {
		t.Fatal("encrypted operation payload schema retained plaintext")
	}
}

func TestEngineStagesAtomicAdapterOnce(t *testing.T) {
	engine, store, ordinary, input := fixtureEngine(2)
	batch := &fakeBatchAdapter{fakeAdapter: ordinary}
	engine.Adapter = batch
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != StatusReady || batch.stages != 1 || len(ordinary.writes) != 0 ||
		len(batch.stagedValues) != 2 || len(batch.verifyVersion) != 2 {
		t.Fatalf("atomic stage result: status=%s stages=%d writes=%d values=%d verifies=%d",
			operation.Status, batch.stages, len(ordinary.writes), len(batch.stagedValues), len(batch.verifyVersion))
	}
	for index, version := range batch.verifyVersion {
		if version != "staged-version-id" || operation.Actions[index].WriteEvidence.ProviderOperationID != version {
			t.Fatal("staged version evidence was not used for verification")
		}
	}
	raw, err := json.Marshal(store.operations[operation.ID])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "plaintext-SENTINEL") {
		t.Fatal("atomic operation evidence retained plaintext")
	}
}

func TestEngineAtomicRevokeVerifiesExpectedAbsence(t *testing.T) {
	engine, _, ordinary, input := fixtureEngine(1)
	batch := &fakeBatchAdapter{fakeAdapter: ordinary}
	engine.Adapter = batch
	input.Actions[0] = Action{ID: "revoke-1", Operation: "revoke", Service: "api",
		ServiceID: "api-id", Name: "OLD_SECRET"}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != StatusReady || len(batch.verifyExpected) != 1 ||
		batch.verifyExpected[0] != provider.PresenceAbsent {
		t.Fatalf("revoke verification: status=%s expected=%v", operation.Status, batch.verifyExpected)
	}
}

func TestNamesOnlyPlanCannotBeApplied(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(1)
	input.Kind = PlanKindNamesOnly
	input.Actions = nil
	input.Names = []PlannedName{{Service: "api", ServiceID: "api-id", Name: "SECRET_1",
		Desired: "present", State: "unverifiable", Record: "record-1",
		ExpectedRecordRevision: 4}}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := false
	if _, err := engine.Apply(context.Background(), plan.ID(), func(context.Context, Confirmation) error {
		confirmed = true
		return nil
	}); err == nil || confirmed || len(adapter.writes) != 0 {
		t.Fatal("names-only plan reached confirmation or provider write")
	}
}

func TestApplyCancellationAndDestructiveSecondConfirmationAreNoWritePaths(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(1)
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Apply(context.Background(), plan.ID(), func(context.Context, Confirmation) error {
		return errors.New("operator declined")
	}); err == nil || len(adapter.writes) != 0 {
		t.Fatal("cancelled apply performed a write")
	}

	engine, _, adapter, input = fixtureEngine(1)
	input.Actions[0] = Action{ID: "revoke-1", Operation: "revoke", Service: "api",
		ServiceID: "api-id", Name: "OLD_SECRET"}
	plan, err = engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	confirmations := 0
	if _, err := engine.Apply(context.Background(), plan.ID(), func(_ context.Context, confirmation Confirmation) error {
		confirmations++
		if confirmation.Kind == "destructive" {
			return errors.New("declined deletion")
		}
		return nil
	}); err == nil || confirmations != 2 || len(adapter.writes) != 0 {
		t.Fatal("revoke did not require a no-write second confirmation")
	}
}

func TestPartialFailureResumesWithoutRedoingCommittedActions(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(2)
	adapter.writeErrors = []error{nil, provider.NewError("write", 429, "RATE_LIMITED", provider.RetrySafe), nil}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err == nil || operation.Status != StatusRetryable {
		t.Fatalf("partial failure was not retryable: status=%s err=%v", operation.Status, err)
	}
	operation, err = engine.Resume(context.Background(), operation.ID)
	if err != nil || operation.Status != StatusReady {
		t.Fatalf("resume failed: status=%s err=%v", operation.Status, err)
	}
	want := []string{"api/SECRET_1", "api/SECRET_2", "api/SECRET_2"}
	if fmt.Sprint(actionNames(adapter.writes)) != fmt.Sprint(want) {
		t.Fatalf("writes = %v, want %v", actionNames(adapter.writes), want)
	}
}

func TestAmbiguousNonIdempotentWriteStopsForReconciliation(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(1)
	adapter.metadata.Variables["api"]["SECRET_1"] = provider.VariableMetadata{Presence: provider.PresencePresent}
	adapter.writeErrors = []error{provider.NewError("write", 504, "TIMEOUT", provider.RetryAmbiguous)}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err == nil || operation.Status != StatusReconciliation {
		t.Fatalf("ambiguous outcome was not stopped: status=%s err=%v", operation.Status, err)
	}
	operation, err = engine.Resume(context.Background(), operation.ID)
	if !errors.Is(err, ErrReconciliationRequired) || operation.Status != StatusReconciliation || len(adapter.writes) != 1 {
		t.Fatalf("resume issued a blind duplicate: status=%s writes=%d err=%v",
			operation.Status, len(adapter.writes), err)
	}
}

func TestUntypedWriteErrorIsAmbiguousAndItsTextIsNeverJournaled(t *testing.T) {
	const sentinel = "provider-response-secret-SENTINEL"
	engine, store, adapter, input := fixtureEngine(1)
	adapter.metadata.Variables["api"]["SECRET_1"] = provider.VariableMetadata{Presence: provider.PresencePresent}
	adapter.writeErrors = []error{errors.New(sentinel)}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err == nil || operation.Status != StatusReconciliation {
		t.Fatalf("untyped write failure was not treated as ambiguous: status=%s err=%v", operation.Status, err)
	}
	raw, marshalErr := json.Marshal(store.operations[operation.ID])
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(string(raw), sentinel) {
		t.Fatal("provider error text reached output or the encrypted journal payload")
	}
}

func TestIdempotentAmbiguousWriteCanResumeAfterPlanExpiry(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(1)
	adapter.capabilities.SupportsIdempotencyKey = true
	adapter.writeErrors = []error{provider.NewError("write", 504, "TIMEOUT", provider.RetryAmbiguous), nil}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err == nil || operation.Status != StatusRetryable {
		t.Fatalf("ambiguous idempotent write was not retryable: %s %v", operation.Status, err)
	}
	engine.Now = func() time.Time { return rolloutTime.Add(PlanTTL + time.Hour) }
	operation, err = engine.Resume(context.Background(), operation.ID)
	if err != nil || operation.Status != StatusReady || len(adapter.writes) != 2 ||
		adapter.writes[0].key != adapter.writes[1].key {
		t.Fatalf("idempotent resume failed: status=%s writes=%d err=%v", operation.Status, len(adapter.writes), err)
	}
}

func TestApplyRejectsExpiredAndStalePlansBeforeWriting(t *testing.T) {
	engine, store, adapter, input := fixtureEngine(1)
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	engine.Now = func() time.Time { return rolloutTime.Add(PlanTTL) }
	if _, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation); err == nil || len(adapter.writes) != 0 {
		t.Fatal("expired plan was applied")
	}
	engine.Now = func() time.Time { return rolloutTime }
	store.snapshotOK = false
	if _, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation); err == nil || len(adapter.writes) != 0 {
		t.Fatal("stale snapshot plan was applied")
	}
}

func TestLocalRecordLoadFailureNeverCreatesAmbiguousInFlightState(t *testing.T) {
	engine, store, adapter, input := fixtureEngine(1)
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%s:%d", input.Actions[0].Record, input.Actions[0].ExpectedRecordRevision)
	value := store.records[key]
	delete(store.records, key)
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err == nil || len(adapter.writes) != 0 || operation.Actions[0].Status != ActionPending {
		t.Fatalf("local load failure became an attempted provider write: status=%s writes=%d err=%v",
			operation.Actions[0].Status, len(adapter.writes), err)
	}
	store.records[key] = value
	operation, err = engine.Resume(context.Background(), operation.ID)
	if err != nil || operation.Status != StatusReady || len(adapter.writes) != 1 {
		t.Fatalf("pending local failure did not resume safely: status=%s writes=%d err=%v",
			operation.Status, len(adapter.writes), err)
	}
}

func TestVerificationLimitationsAreTerminalAndHonest(t *testing.T) {
	engine, _, adapter, input := fixtureEngine(1)
	adapter.capabilities.Validate = false
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := engine.Apply(context.Background(), plan.ID(), allowConfirmation)
	if err != nil || operation.Status != StatusLimited || len(adapter.verifyNames) != 0 ||
		operation.Actions[0].VerifyEvidence.Result != provider.VerificationLimited {
		t.Fatalf("verification limit was overstated: status=%s verifies=%d err=%v",
			operation.Status, len(adapter.verifyNames), err)
	}
}

func allowConfirmation(context.Context, Confirmation) error { return nil }

func actionNames(writes []fakeWrite) []string {
	names := make([]string, len(writes))
	for index := range writes {
		names[index] = writes[index].action
	}
	return names
}

func cloneJSON[T any](value T) T {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned T
	if err := json.Unmarshal(raw, &cloned); err != nil {
		panic(err)
	}
	return cloned
}
