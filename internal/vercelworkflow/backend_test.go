package vercelworkflow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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

const privateFixture = "fake-private-value-no-output-acceptance-fixture"

type memoryStore struct {
	plans     map[string]rollout.ProviderPlan
	ops       map[string]rollout.Operation
	states    map[string]State
	revisions map[string]int64
	policy    lifecycle.AutomationPolicy
	snapshot  bundle.Snapshot
	lease     bool
	reads     int
	failStage string
}

func clone[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func (s *memoryStore) SavePlan(_ context.Context, p rollout.ProviderPlan, expected int64) (int64, error) {
	if s.revisions[p.ID()] != expected {
		return 0, errors.New("conflict")
	}
	s.plans[p.ID()] = clone(p)
	s.revisions[p.ID()]++
	return s.revisions[p.ID()], nil
}
func (s *memoryStore) LoadPlan(_ context.Context, id string) (rollout.ProviderPlan, int64, error) {
	p, ok := s.plans[id]
	if !ok {
		return p, 0, errors.New("missing")
	}
	return clone(p), s.revisions[id], nil
}
func (s *memoryStore) SaveOperation(_ context.Context, p rollout.Operation, expected int64) (int64, error) {
	if p.Validate() != nil || s.revisions[p.ID] != expected {
		return 0, errors.New("invalid operation/conflict")
	}
	s.ops[p.ID] = clone(p)
	s.revisions[p.ID]++
	return s.revisions[p.ID], nil
}
func (s *memoryStore) LoadOperation(_ context.Context, id string) (rollout.Operation, int64, error) {
	p, ok := s.ops[id]
	if !ok {
		return p, 0, errors.New("missing")
	}
	return clone(p), s.revisions[id], nil
}
func (s *memoryStore) ValidateSnapshot(_ context.Context, p rollout.ProviderPlan) error {
	if p.ManifestDigest != s.snapshot.ManifestDigest || p.SnapshotRevision != 1 {
		return errors.New("stale")
	}
	return nil
}
func (s *memoryStore) LoadRecord(_ context.Context, _, _ string, revision int64) ([]byte, error) {
	s.reads++
	if revision != 1 {
		return nil, errors.New("stale record")
	}
	return []byte(privateFixture), nil
}
func (s *memoryStore) Snapshot(context.Context, string) (bundle.Snapshot, int64, error) {
	return clone(s.snapshot), 1, nil
}
func (s *memoryStore) LoadPolicy(context.Context, string) (lifecycle.AutomationPolicy, int64, error) {
	return clone(s.policy), 1, nil
}
func (s *memoryStore) LoadDeployment(_ context.Context, id string) (State, int64, error) {
	p, ok := s.states[id]
	if !ok {
		return p, 0, ErrNotFound
	}
	return clone(p), s.revisions[id], nil
}
func (s *memoryStore) SaveDeployment(_ context.Context, p State, expected int64) (int64, error) {
	if p.Stage == s.failStage {
		return 0, errors.New("injected durable save failure")
	}
	if p.Validate() != nil || s.revisions[p.ID] != expected {
		return 0, errors.New("invalid state/conflict")
	}
	s.states[p.ID] = clone(p)
	s.revisions[p.ID]++
	return s.revisions[p.ID], nil
}
func (s *memoryStore) AcquireLease(_ context.Context, _, _ string, _ time.Duration) (lifecycle.Lease, int64, error) {
	if s.lease {
		return lifecycle.Lease{}, 0, lifecycle.ErrLeaseHeld
	}
	s.lease = true
	return lifecycle.Lease{}, 1, nil
}
func (s *memoryStore) ReleaseLease(context.Context, lifecycle.Lease, int64) error {
	s.lease = false
	return nil
}

type fakeAdapter struct {
	scope                                vercel.Scope
	store                                *memoryStore
	now                                  func() time.Time
	writes, creates, promotes, rollbacks int
	current                              string
	created                              bool
	ambiguous, missing, drift            bool
	attempts                             int
	failSecondOnce                       bool
	names                                map[string]bool
	proofCode                            string
	afterWrite                           func()
}

func (a *fakeAdapter) Scope() vercel.Scope { return a.scope }
func (a *fakeAdapter) Capabilities() provider.Capabilities {
	return provider.Capabilities{Create: true, ReadMetadata: true, Update: true, Validate: true, SupportsMaskedPresence: true}
}
func (a *fakeAdapter) Identity(context.Context) (provider.Identity, error) {
	return provider.Identity{Provider: "vercel", ID: a.scope.TeamID + ":" + a.scope.ProjectID}, nil
}
func (a *fakeAdapter) Inspect(_ context.Context, t provider.Target) (provider.MetadataState, error) {
	variables := map[string]provider.VariableMetadata{}
	for _, name := range []string{"API_SECRET", "API_SECRET_TWO"} {
		presence := provider.PresenceAbsent
		if a.names[name] {
			presence = provider.PresencePresent
		}
		variables[name] = provider.VariableMetadata{Presence: presence}
	}
	return provider.MetadataState{Target: t, Variables: map[string]map[string]provider.VariableMetadata{"environment": variables}, Revision: fmt.Sprintf("%064x", a.writes)}, nil
}
func (a *fakeAdapter) Write(_ context.Context, r provider.WriteRequest) (provider.WriteEvidence, error) {
	a.attempts++
	if a.attempts == 2 && a.failSecondOnce {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "READ_FAILED_BEFORE_WRITE", Retry: provider.RetrySafe}
	}
	if len(a.store.states) != 1 {
		return provider.WriteEvidence{}, errors.New("write before workflow journal")
	}
	for _, s := range a.store.states {
		if s.Stage != "writing" || s.RolloutID == "" {
			return provider.WriteEvidence{}, errors.New("write before durable rollout binding")
		}
	}
	e := r.ViewSecret(func(value []byte) error {
		if string(value) != privateFixture {
			return errors.New("wrong fixture")
		}
		return nil
	})
	if e != nil {
		return provider.WriteEvidence{}, e
	}
	a.writes++
	if a.names == nil {
		a.names = map[string]bool{}
	}
	a.names[r.Name] = true
	if a.afterWrite != nil {
		a.afterWrite()
	}
	return provider.WriteEvidence{MetadataRevision: fmt.Sprintf("%064x", a.writes), CommittedAt: a.now().Format(time.RFC3339), ProviderOperationID: "env_fixture"}, nil
}
func (a *fakeAdapter) Verify(context.Context, provider.VerifyRequest) (provider.VerifyEvidence, error) {
	return provider.VerifyEvidence{Result: provider.VerificationLimited, Presence: provider.PresencePresent, VerifiedAt: a.now().Format(time.RFC3339), Reason: "masked-presence-only"}, nil
}
func (a *fakeAdapter) dep(id string) vercel.Deployment {
	return vercel.Deployment{ID: id, ProjectID: a.scope.ProjectID, TeamID: a.scope.TeamID, Environment: a.scope.Environment, GitBranch: a.scope.GitBranch, ReadyState: "READY", URL: "fixture.vercel.app", CommitSHA: "abc1234def5678"}
}
func (a *fakeAdapter) ProveDeployment(_ context.Context, id, source, op string) (vercel.Deployment, error) {
	if source != "dpl_source" || op != a.store.states[op].ID || id != "dpl_new" {
		return vercel.Deployment{}, errors.New("wrong proof bindings")
	}
	if a.proofCode != "" {
		return vercel.Deployment{}, provider.NewError("deployment", 0, a.proofCode, provider.RetryNever)
	}
	return a.dep(id), nil
}
func (a *fakeAdapter) Deployment(_ context.Context, id string) (vercel.Deployment, error) {
	return a.dep(id), nil
}
func (a *fakeAdapter) CurrentDeployment(context.Context) (vercel.Deployment, error) {
	if a.drift {
		return a.dep("dpl_foreign"), nil
	}
	return a.dep(a.current), nil
}
func (a *fakeAdapter) Redeploy(_ context.Context, _ string, op string) (vercel.Deployment, error) {
	if a.store.states[op].Stage != "deploying" {
		return vercel.Deployment{}, errors.New("create before durable intent")
	}
	a.creates++
	a.created = true
	if a.ambiguous {
		return vercel.Deployment{}, errors.New("uncertain create")
	}
	return a.dep("dpl_new"), nil
}
func (a *fakeAdapter) FindDeployment(context.Context, string) (vercel.Deployment, error) {
	if !a.created || a.missing {
		return vercel.Deployment{}, errors.New("not yet visible")
	}
	return a.dep("dpl_new"), nil
}
func (a *fakeAdapter) Promote(context.Context, string) error {
	a.promotes++
	a.current = "dpl_new"
	return nil
}
func (a *fakeAdapter) Rollback(context.Context, string) error {
	a.rollbacks++
	a.current = "dpl_source"
	return nil
}

func fixture(t *testing.T, environment string) (*Backend, *memoryStore, *fakeAdapter, string, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	scope := vercel.Scope{TeamID: "team_fixture", ProjectID: "prj_fixture", Environment: environment}
	if environment == "preview" {
		scope.GitBranch = "acceptance"
	}
	doc := &contract.Document{Digest: strings.Repeat("a", 64), Manifest: contract.Manifest{Version: 1, Bundle: "fixture", Targets: map[string]contract.Target{"vercel": {TeamID: scope.TeamID, Project: "fixture", ProjectID: scope.ProjectID, Environment: scope.Environment, GitBranch: scope.GitBranch, Services: map[string]contract.Service{"environment": {Variables: map[string]contract.Variable{"API_SECRET": {Source: "record", Record: "api"}}}}}}}}
	s := &memoryStore{plans: map[string]rollout.ProviderPlan{}, ops: map[string]rollout.Operation{}, states: map[string]State{}, revisions: map[string]int64{}, snapshot: bundle.Snapshot{Version: 1, Bundle: "fixture", ManifestDigest: doc.Digest, PhysicalToLogical: map[string]string{"fixture/api": "api"}, Sources: map[string]bundle.SourceStatus{"api": {Source: "generate", Status: "ready"}}, RecordRevisions: map[string]int64{"api": 1}, CreatedAt: now.Format(time.RFC3339)}}
	a := &fakeAdapter{scope: scope, store: s, now: func() time.Time { return now }, current: "dpl_source"}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := &Backend{Document: doc, Adapter: a, Store: s, VaultID: "vault", DeviceID: "device", TrustedPolicyKey: public, OwnerApprovalKey: testOwner.PublicKey(), Now: func() time.Time { return now }, Wait: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }, Probe: func(context.Context, vercel.Deployment, string) (bool, error) { return true, nil }}
	r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
	if e != nil {
		t.Fatal(e)
	}
	stage, grace := "staging", "15m"
	if environment == "production" {
		stage, grace = "production", "24h"
	}
	s.policy = lifecycle.AutomationPolicy{Version: 1, ID: PolicyID(r.PlanID), VaultID: "vault", Bundle: "fixture", ManifestDigest: doc.Digest, Environment: stage, ProviderIdentities: map[string]string{"vercel": scope.TeamID + ":" + scope.ProjectID}, CredentialClasses: []string{"vercel-environment-secret"}, Operations: []string{"stage", "activate", "verify", "rollback"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "manual", HealthChecks: []string{"/health"}, GracePeriod: grace, Rollback: "previous-deployment", RetryBudget: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ApprovingDevice: "device", DeploymentPlanID: r.PlanID, DeploymentSourceID: "dpl_source", DeploymentScopeFingerprint: scope.Fingerprint(), DeploymentHealthPath: "/health"}
	if e = ownerSign(&s.policy, private); e != nil {
		t.Fatal(e)
	}
	return b, s, a, r.PlanID, private
}
func runTo(t *testing.T, b *Backend, planID, want string) mcpserver.Result {
	t.Helper()
	r, e := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: planID})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 12 && r.Stage != want; i++ {
		if r.BlockerCode != "" {
			t.Fatalf("unexpected blocker %s at %s", r.BlockerCode, r.Stage)
		}
		r, e = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
		if e != nil {
			t.Fatal(e)
		}
	}
	if r.Stage != want {
		t.Fatalf("wanted %s, got %s (%s)", want, r.Stage, r.BlockerCode)
	}
	return r
}

func TestSignedVaultToDeploymentAndRollback(t *testing.T) {
	for _, env := range []string{"preview", "production"} {
		t.Run(env, func(t *testing.T) {
			b, s, a, p, _ := fixture(t, env)
			r := runTo(t, b, p, "complete")
			if a.writes != 1 || a.creates != 1 || r.Health[0].SuccessfulChecks < 3 {
				t.Fatal("incomplete transfer/deployment health")
			}
			// Replaying start after completion must never issue another write/create.
			_, e := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
			if e != nil || a.writes != 1 || a.creates != 1 {
				t.Fatal("duplicate mutation")
			}
			if env == "production" {
				r, e = b.Rollback(context.Background(), r.OperationID)
				if e != nil || r.Stage != "rolled-back" || a.rollbacks != 1 || a.promotes != 1 {
					t.Fatal("production rollback failed")
				}
			} else if a.promotes != 0 {
				t.Fatal("preview touched production aliases")
			}
			raw, _ := json.Marshal(s.states)
			if strings.Contains(string(raw), privateFixture) {
				t.Fatal("private value in journal")
			}
			raw, _ = json.Marshal(r)
			if strings.Contains(string(raw), privateFixture) {
				t.Fatal("private value in receipt")
			}
		})
	}
}
func TestRejectsForgedPolicyAndBindingDriftBeforeSecretRead(t *testing.T) {
	b, s, a, p, _ := fixture(t, "preview")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_ = ownerSign(&s.policy, other)
	r, e := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if e != nil || r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 {
		t.Fatal("self-signed approval accepted")
	}
	r, _ = b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p, Bundle: "other"})
	if r.BlockerCode != "POLICY_BINDING_MISMATCH" {
		t.Fatal("scope override accepted")
	}
}
func TestUncertainCreateReconcilesWithoutRetry(t *testing.T) {
	b, _, a, p, _ := fixture(t, "preview")
	a.ambiguous = true
	r := runTo(t, b, p, "deployment-pending")
	r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.BlockerCode != "DEPLOYMENT_RECONCILIATION_REQUIRED" || a.creates != 1 {
		t.Fatal("uncertain create not retained")
	}
	a.missing = true
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.BlockerCode == "" || a.creates != 1 {
		t.Fatal("uncertain create retried")
	}
	a.missing = false
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.Stage != "building" || a.creates != 1 {
		t.Fatal("read-only reconciliation failed")
	}
}
func TestDurabilityFailureAndLeaseBlockMutation(t *testing.T) {
	b, s, a, p, _ := fixture(t, "preview")
	s.lease = true
	r, _ := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if r.BlockerCode != "VERCEL_OPERATION_BUSY" || s.reads != 0 {
		t.Fatal("lease bypass")
	}
	s.lease = false
	s.failStage = "writing"
	_, e := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if e == nil || a.writes != 0 || s.reads != 0 {
		t.Fatal("private write happened before durable rollout reference")
	}
}
func TestHealthFailureAndProductionDriftDoNotPromote(t *testing.T) {
	b, _, a, p, _ := fixture(t, "production")
	b.Probe = func(context.Context, vercel.Deployment, string) (bool, error) { return false, nil }
	r := runTo(t, b, p, "health")
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.Stage != "failed" || a.promotes != 0 {
		t.Fatal("unhealthy deployment promoted")
	}
	b, _, a, p, _ = fixture(t, "production")
	r = runTo(t, b, p, "promote-pending")
	a.drift = true
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.BlockerCode != "PRODUCTION_DEPLOYMENT_DRIFT" || a.promotes != 0 {
		t.Fatal("production drift overwritten")
	}
}

func TestPartialWriteResumeUsesOwnMetadataCheckpoint(t *testing.T) {
	b, s, a, _, private := fixture(t, "preview")
	service := b.Document.Manifest.Targets["vercel"].Services["environment"]
	service.Variables["API_SECRET_TWO"] = contract.Variable{Source: "record", Record: "api"}
	r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
	if e != nil {
		t.Fatal(e)
	}
	s.policy.ID = PolicyID(r.PlanID)
	s.policy.DeploymentPlanID = r.PlanID
	_ = ownerSign(&s.policy, private)
	a.failSecondOnce = true
	r, e = b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: r.PlanID})
	if e != nil {
		t.Fatal(e)
	}
	r, e = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.BlockerCode != "VERCEL_VARIABLE_WRITE_INCOMPLETE" || a.writes != 1 {
		t.Fatal("failed to pause after one committed write")
	}
	r, e = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "deployment-pending" || r.BlockerCode != "" || a.writes != 2 || a.attempts != 3 {
		t.Fatal("resume duplicated a confirmed write or rejected its own metadata revision")
	}
}

func TestExpiredApprovalStopsNextPrivateRecordRead(t *testing.T) {
	b, s, a, p, _ := fixture(t, "preview")
	r := runTo(t, b, p, "writing")
	base := b.now()
	b.Now = func() time.Time { return base.Add(2 * time.Hour) }
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 {
		t.Fatal("expired approval opened a private record")
	}
}

func TestFreshHealthRequiredAfterPause(t *testing.T) {
	b, _, a, p, _ := fixture(t, "production")
	r := runTo(t, b, p, "promote-pending")
	base := b.now()
	b.Now = func() time.Time { return base.Add(3 * time.Minute) }
	r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "health" || r.BlockerCode != "DEPLOYMENT_HEALTH_REQUIRED" || a.promotes != 0 || r.Health[0].SuccessfulChecks != 0 {
		t.Fatal("stale health authorized production")
	}
}

func TestUnexpectedPromotionOffersApprovedRollback(t *testing.T) {
	b, _, a, p, _ := fixture(t, "production")
	r := runTo(t, b, p, "building")
	a.current = "dpl_new"
	a.proofCode = "UNEXPECTED_PROMOTION"
	r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "unexpected-promotion" || a.promotes != 0 {
		t.Fatal("unexpected promotion did not stop health/activation")
	}
	r, e = b.Rollback(context.Background(), r.OperationID)
	if e != nil || r.Stage != "rolled-back" || a.rollbacks != 1 || r.VariableState != "applied-not-reverted" {
		t.Fatal("unexpected promotion lacks safe rollback evidence")
	}
}

func TestRecoveredWrongCommitNeverProceeds(t *testing.T) {
	b, _, a, p, _ := fixture(t, "preview")
	a.ambiguous = true
	r := runTo(t, b, p, "deployment-pending")
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	a.proofCode = "APPROVED_SOURCE_UNVERIFIED"
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.Stage != "deploying" || r.BlockerCode != "APPROVED_SOURCE_UNVERIFIED" || a.creates != 1 {
		t.Fatal("wrong-commit recovery accepted")
	}
}

func TestApprovalRenewalCanOnlyChangeExpiry(t *testing.T) {
	for _, change := range []string{"expiry", "operations", "retry", "health", "signature"} {
		t.Run(change, func(t *testing.T) {
			b, s, a, p, key := fixture(t, "preview")
			r := runTo(t, b, p, "writing")
			switch change {
			case "expiry":
				s.policy.ExpiresAt = b.now().Add(2 * time.Hour).Format(time.RFC3339)
			case "operations":
				s.policy.Operations = append(s.policy.Operations, "delete")
			case "retry":
				s.policy.RetryBudget = 2
			case "health":
				s.policy.HealthChecks = append(s.policy.HealthChecks, "/other")
			case "signature":
				s.policy.Signature[0] ^= 1
			}
			if change != "signature" {
				_ = ownerSign(&s.policy, key)
			}
			r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
			if e != nil {
				t.Fatal(e)
			}
			if change == "expiry" {
				if r.Stage != "deployment-pending" || a.writes != 1 {
					t.Fatal("expiry renewal rejected")
				}
			} else if r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || a.writes != 0 || s.reads != 0 {
				t.Fatal("renewal changed signed authority")
			}
		})
	}
}

func TestCheckpointFailureDoesNotBlindlyRepeatWrite(t *testing.T) {
	b, s, a, p, _ := fixture(t, "preview")
	r := runTo(t, b, p, "writing")
	s.failStage = "writing"
	r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if r.BlockerCode == "" || a.writes != 1 {
		t.Fatal("lost checkpoint not detected")
	}
	s.failStage = ""
	for i := 0; i < 3; i++ {
		r, _ = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	}
	if a.writes != 1 || a.creates != 0 || r.VariableState != "possibly-partially-applied-not-reverted" {
		t.Fatal("lost acknowledgement retried or hidden")
	}
}

func TestOutsidePromotionAtHealthGateCanBeRolledBack(t *testing.T) {
	b, _, a, p, _ := fixture(t, "production")
	r := runTo(t, b, p, "promote-pending")
	a.current = "dpl_new"
	r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "unexpected-promotion" || a.promotes != 0 {
		t.Fatal("outside promotion silently accepted or stuck")
	}
	r, e = b.Rollback(context.Background(), r.OperationID)
	if e != nil || r.Stage != "rolled-back" || a.rollbacks != 1 {
		t.Fatal("outside promotion lacks approved rollback")
	}
}

func TestMidBatchApprovalExpiryCanRenewWithoutDuplicateWrite(t *testing.T) {
	b, s, a, _, key := fixture(t, "preview")
	b.Document.Manifest.Targets["vercel"].Services["environment"].Variables["API_SECRET_TWO"] = contract.Variable{Source: "record", Record: "api"}
	r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
	if e != nil {
		t.Fatal(e)
	}
	s.policy.ID = PolicyID(r.PlanID)
	s.policy.DeploymentPlanID = r.PlanID
	_ = ownerSign(&s.policy, key)
	a.afterWrite = func() {
		s.policy.ExpiresAt = b.now().Add(-time.Second).Format(time.RFC3339)
		_ = ownerSign(&s.policy, key)
		a.afterWrite = nil
	}
	r, e = b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: r.PlanID})
	if e != nil {
		t.Fatal(e)
	}
	r, e = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "writing" || a.writes != 1 || s.reads != 1 {
		t.Fatal("expiry read the next record or made partial work terminal")
	}
	s.policy.ExpiresAt = b.now().Add(2 * time.Hour).Format(time.RFC3339)
	_ = ownerSign(&s.policy, key)
	r, e = b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.Stage != "deployment-pending" || a.writes != 2 || s.reads != 2 {
		t.Fatal("renewal repeated a confirmed write or could not resume")
	}
}
