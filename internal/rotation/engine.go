// Package rotation drives one credential rotation through the lifecycle state
// machine: mint the new credential into an encrypted record, stage and
// activate it at the deployment target, hold the old credential through the
// grace period, then revoke it. Every step is re-authorized against the
// signed automation policy, saved with an optimistic revision and recorded in
// the signed evidence chain, so a run can stop anywhere and resume later.
//
// The engine never sees a secret value: the provider adapter streams it into
// a SecretSink, and the deployer reads it by record revision.
package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

// Store is the encrypted vault persistence the engine needs. lifecycle.VaultStore
// satisfies it.
type Store interface {
	LoadPolicy(context.Context, string) (lifecycle.AutomationPolicy, int64, error)
	SaveOperation(context.Context, lifecycle.Operation, int64) (int64, error)
	LoadOperation(context.Context, string) (lifecycle.Operation, int64, error)
	AcquireLease(context.Context, string, string, time.Duration) (lifecycle.Lease, int64, error)
	ReleaseLease(context.Context, lifecycle.Lease, int64) error
	LoadEvidence(context.Context, string, ed25519.PublicKey) ([]lifecycle.Evidence, error)
	AppendEvidence(context.Context, string, lifecycle.Evidence, ed25519.PublicKey) (int64, error)
}

// Deployer moves a record revision into the deployment target. Stage must not
// change what the running application uses; Activate does, and must return
// health evidence that lifecycle.HealthEvidence.Validate accepts. Rollback
// restores the previous deployment.
type Deployer interface {
	Stage(context.Context, lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error)
	Activate(context.Context, lifecycle.DeploymentRequest, string) (lifecycle.HealthEvidence, error)
	Rollback(context.Context, lifecycle.DeploymentRequest, string) error
}

// OwnerVerifier checks the owner's separate approval of a policy. The device
// signature alone is never enough because the engine holds the device key.
// Implementations are the Secure Enclave verifier today and remote approval
// channels later; the engine does not care which.
type OwnerVerifier func(lifecycle.AutomationPolicy, time.Time) error

var (
	ErrNotApproved = errors.New("rotation policy is not approved for this operation")
	ErrBusy        = errors.New("another rotation holds this bundle's lease")
)

type Engine struct {
	Store       Store
	Deployer    Deployer
	Credentials lifecycle.CredentialAdapter
	Records     lifecycle.RecordWriter
	VaultID     string
	DeviceID    string
	// DevicePrivate signs evidence; PolicyKey is the device public key every
	// policy must carry.
	DevicePrivate ed25519.PrivateKey
	PolicyKey     ed25519.PublicKey
	OwnerVerify   OwnerVerifier
	Now           func() time.Time
	LeaseTTL      time.Duration
}

// PlanInput names the credential being rotated. Nothing in it is secret.
type PlanInput struct {
	OperationID            string
	PolicyID               string
	Bundle                 string
	ManifestDigest         string
	Provider               string
	ProviderIdentity       string
	CredentialClass        string
	DestinationRecord      string
	PreviousRecordRevision int64
	PreviousCredentialID   string
	Target                 lifecycle.TargetPolicy
	CreateParameters       map[string][]string
}

func (engine *Engine) ready() error {
	if engine == nil || engine.Store == nil || engine.Deployer == nil || engine.Credentials == nil || engine.Records == nil || engine.VaultID == "" || engine.DeviceID == "" || len(engine.DevicePrivate) != ed25519.PrivateKeySize || len(engine.PolicyKey) != ed25519.PublicKeySize || engine.OwnerVerify == nil {
		return errors.New("rotation engine is not configured")
	}
	return nil
}
func (engine *Engine) now() time.Time {
	if engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}

// Plan records a new operation in the planned state after proving the policy
// authorizes creating this credential class for this target.
func (engine *Engine) Plan(ctx context.Context, input PlanInput) (lifecycle.Operation, error) {
	if err := engine.ready(); err != nil {
		return lifecycle.Operation{}, err
	}
	policy, err := engine.policy(ctx, input.PolicyID, "")
	if err != nil {
		return lifecycle.Operation{}, err
	}
	digest, _ := policy.Digest()
	now := engine.now().Format(time.RFC3339)
	operation := lifecycle.Operation{Version: lifecycle.OperationVersion, ID: input.OperationID, PolicyID: policy.ID, PolicyDigest: digest, VaultID: engine.VaultID, Bundle: input.Bundle, ManifestDigest: input.ManifestDigest, Provider: input.Provider, ProviderIdentity: input.ProviderIdentity, Target: input.Target, CredentialClass: input.CredentialClass, DestinationRecord: input.DestinationRecord, PreviousRecordRevision: input.PreviousRecordRevision, PreviousCredentialID: input.PreviousCredentialID, CreateParameters: input.CreateParameters, State: lifecycle.StatePlanned, CreatedAt: now, UpdatedAt: now}
	if err := operation.Validate(); err != nil {
		return lifecycle.Operation{}, err
	}
	// Compensation (rollback, revoke) must be approved up front: a run that
	// cannot clean up after itself must never start.
	for _, action := range []string{"create", "stage", "activate", "verify", "rollback", "revoke"} {
		if err := policy.Authorizes(binding(operation, policy, action), engine.now()); err != nil {
			return lifecycle.Operation{}, ErrNotApproved
		}
	}
	if _, err := engine.Store.SaveOperation(ctx, operation, 0); err != nil {
		return lifecycle.Operation{}, fmt.Errorf("rotation operation could not be recorded: %w", err)
	}
	if err := engine.record(ctx, &run{operation: operation}, "plan", "planned"); err != nil {
		return lifecycle.Operation{}, err
	}
	return operation, nil
}

// Run advances the operation as far as it can and returns its resting state.
// It returns without error when the operation is complete, waiting for the
// grace period, needs reconciliation, or has failed terminally; callers read
// the state. Errors are infrastructure failures that changed nothing.
func (engine *Engine) Run(ctx context.Context, operationID string) (lifecycle.Operation, error) {
	if err := engine.ready(); err != nil {
		return lifecycle.Operation{}, err
	}
	operation, revision, err := engine.Store.LoadOperation(ctx, operationID)
	if err != nil {
		return lifecycle.Operation{}, fmt.Errorf("rotation operation unavailable: %w", err)
	}
	if operation.VaultID != engine.VaultID {
		return lifecycle.Operation{}, errors.New("rotation operation belongs to another vault")
	}
	ttl := engine.LeaseTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	lease, leaseRevision, err := engine.Store.AcquireLease(ctx, operation.Bundle, engine.DeviceID, ttl)
	if err != nil {
		if errors.Is(err, lifecycle.ErrLeaseHeld) {
			return operation, ErrBusy
		}
		return operation, fmt.Errorf("rotation lease unavailable: %w", err)
	}
	defer func() { _ = engine.Store.ReleaseLease(context.WithoutCancel(ctx), lease, leaseRevision) }()
	// Another runner may have advanced the operation between the first load
	// and the lease; only the copy read under the lease is authoritative.
	operation, revision, err = engine.Store.LoadOperation(ctx, operationID)
	if err != nil {
		return lifecycle.Operation{}, fmt.Errorf("rotation operation unavailable: %w", err)
	}
	leaseEnds, err := time.Parse(time.RFC3339, lease.ExpiresAt)
	if err != nil {
		return operation, errors.New("rotation lease expiry is invalid")
	}
	// No mutation may outlive the lease: once it lapses another runner could
	// acquire it, so the whole run is fenced to the lease window.
	ctx, cancel := context.WithDeadline(ctx, leaseEnds)
	defer cancel()

	chain, err := engine.Store.LoadEvidence(ctx, operationID, engine.PolicyKey)
	if err != nil {
		return operation, err
	}
	current := &run{operation: operation, revision: revision, leaseEnds: leaseEnds}
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		current.previous = &last
	}
	for {
		done, err := engine.step(ctx, current)
		if err != nil || done {
			return current.operation, err
		}
	}
}

type run struct {
	operation lifecycle.Operation
	revision  int64
	previous  *lifecycle.Evidence
	leaseEnds time.Time
	// entered is the last state this run transitioned into itself. A mutating
	// state found on disk that this run did not enter was interrupted
	// mid-mutation by an earlier run and must not be replayed.
	entered lifecycle.State
}

var ErrLeaseExpired = errors.New("rotation lease expired before the run finished")

// mutatingStates are the states in which an upstream mutation is in flight.
var mutatingStates = map[lifecycle.State]bool{lifecycle.StateAcquiring: true, lifecycle.StateStaging: true, lifecycle.StateActivating: true, lifecycle.StateRevoking: true}

// step performs one state transition. It returns done when the operation is
// at rest.
func (engine *Engine) step(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	if !current.leaseEnds.IsZero() && !engine.now().Before(current.leaseEnds) {
		return true, ErrLeaseExpired
	}
	policy, err := engine.policy(ctx, operation.PolicyID, operation.PolicyDigest)
	if err != nil {
		return true, err
	}
	if mutatingStates[operation.State] && current.entered != operation.State {
		return engine.interrupted(ctx, current)
	}
	switch operation.State {
	case lifecycle.StatePlanned:
		return false, engine.move(ctx, current, lifecycle.StateAcquiring, "plan", "acquiring")
	case lifecycle.StateAcquiring:
		return engine.acquire(ctx, current, policy)
	case lifecycle.StateStored:
		if err := engine.authorize(policy, *operation, "stage"); err != nil {
			return true, engine.fail(ctx, current, "stage", "not-approved")
		}
		return false, engine.move(ctx, current, lifecycle.StateStaging, "stage", "staging")
	case lifecycle.StateStaging:
		return engine.stage(ctx, current)
	case lifecycle.StateStaged:
		if err := engine.authorize(policy, *operation, "activate"); err != nil {
			return false, engine.move(ctx, current, lifecycle.StateRollingBack, "activate", "not-approved")
		}
		return false, engine.move(ctx, current, lifecycle.StateActivating, "activate", "activating")
	case lifecycle.StateActivating:
		return engine.activate(ctx, current)
	case lifecycle.StateHealthy:
		if err := engine.authorize(policy, *operation, "verify"); err != nil {
			return false, engine.move(ctx, current, lifecycle.StateRollingBack, "verify", "not-approved")
		}
		grace, _ := time.ParseDuration(policy.GracePeriod)
		operation.GraceEndsAt = engine.now().Add(grace).Format(time.RFC3339)
		return false, engine.move(ctx, current, lifecycle.StateGracePeriod, "verify", "grace-period")
	case lifecycle.StateGracePeriod:
		ends, err := time.Parse(time.RFC3339, operation.GraceEndsAt)
		if err != nil || engine.now().Before(ends) {
			return true, nil
		}
		return false, engine.move(ctx, current, lifecycle.StateRevoking, "revoke", "revoking")
	case lifecycle.StateRevoking:
		return engine.revoke(ctx, current, policy)
	case lifecycle.StateRetryable:
		return engine.retry(ctx, current, policy)
	case lifecycle.StateRollingBack:
		return engine.rollback(ctx, current)
	case lifecycle.StateRolledBack:
		return engine.quarantine(ctx, current)
	case lifecycle.StateReconciliationRequired, lifecycle.StateComplete, lifecycle.StateTerminalFailure, lifecycle.StateQuarantined:
		return true, nil
	}
	return true, fmt.Errorf("rotation operation is in unknown state %q", operation.State)
}

// interrupted resolves a mutation whose outcome an earlier run never
// recorded. Credential mutations cannot be replayed (a second mint or an
// unknown revoke), so they stop for reconciliation; deployment mutations are
// undone by rollback, which restores the previous deployment and quarantines
// the minted credential.
func (engine *Engine) interrupted(ctx context.Context, current *run) (bool, error) {
	switch current.operation.State {
	case lifecycle.StateStaging, lifecycle.StateActivating:
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "resume", "interrupted")
	}
	return true, engine.move(ctx, current, lifecycle.StateReconciliationRequired, "resume", "interrupted")
}

func (engine *Engine) acquire(ctx context.Context, current *run, policy lifecycle.AutomationPolicy) (bool, error) {
	operation := &current.operation
	if err := engine.authorize(policy, *operation, "create"); err != nil {
		return true, engine.fail(ctx, current, "acquire", "not-approved")
	}
	if err := engine.identity(ctx, *operation); err != nil {
		return true, engine.fail(ctx, current, "acquire", "identity-mismatch")
	}
	sink, err := lifecycle.NewSecretSink(engine.Records, operation.DestinationRecord)
	if err != nil {
		return true, err
	}
	evidence, err := engine.Credentials.Create(ctx, lifecycle.CredentialRequest{ProviderIdentity: operation.ProviderIdentity, CredentialType: operation.CredentialClass, DestinationRecord: operation.DestinationRecord, IdempotencyKey: operation.ID + ":create", Parameters: operation.CreateParameters}, sink)
	if err != nil {
		return engine.providerFailure(ctx, current, "acquire", err)
	}
	if evidence.CredentialID == "" || evidence.Receipt.Record != operation.DestinationRecord || evidence.Receipt.Revision <= operation.PreviousRecordRevision {
		// The provider may have minted a credential we cannot place.
		return true, engine.move(ctx, current, lifecycle.StateReconciliationRequired, "acquire", "invalid-evidence")
	}
	operation.NewCredentialID = evidence.CredentialID
	operation.NewRecordRevision = evidence.Receipt.Revision
	return false, engine.move(ctx, current, lifecycle.StateStored, "acquire", "stored")
}

func (engine *Engine) stage(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	evidence, err := engine.Deployer.Stage(ctx, engine.deployment(*operation))
	if err != nil {
		if retryClass(err) == provider.RetrySafe {
			return engine.retryable(ctx, current, "stage", "retryable")
		}
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "stage", "failed")
	}
	if evidence.DeploymentID == "" {
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "stage", "invalid-evidence")
	}
	operation.DeploymentID = evidence.DeploymentID
	return false, engine.move(ctx, current, lifecycle.StateStaged, "stage", "staged")
}

func (engine *Engine) activate(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	health, err := engine.Deployer.Activate(ctx, engine.deployment(*operation), operation.DeploymentID)
	if err != nil {
		if retryClass(err) == provider.RetrySafe {
			return engine.retryable(ctx, current, "activate", "retryable")
		}
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "activate", "failed")
	}
	if err := health.Validate(); err != nil {
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "activate", "unhealthy")
	}
	operation.HealthEvidenceDigest = digest(health)
	return false, engine.move(ctx, current, lifecycle.StateHealthy, "activate", "healthy")
}

func (engine *Engine) revoke(ctx context.Context, current *run, policy lifecycle.AutomationPolicy) (bool, error) {
	operation := &current.operation
	if err := operation.RevocationAllowed(binding(*operation, policy, "revoke"), operation.NewRecordRevision, operation.HealthEvidenceDigest, engine.now(), policy); err != nil {
		return true, engine.fail(ctx, current, "revoke", "not-approved")
	}
	if err := engine.identity(ctx, *operation); err != nil {
		return true, engine.fail(ctx, current, "revoke", "identity-mismatch")
	}
	if err := engine.Credentials.Revoke(ctx, operation.PreviousCredentialID); err != nil {
		return engine.providerFailure(ctx, current, "revoke", err)
	}
	return true, engine.move(ctx, current, lifecycle.StateComplete, "revoke", "complete")
}

// retry resumes the interrupted step while the policy's retry budget allows.
func (engine *Engine) retry(ctx context.Context, current *run, policy lifecycle.AutomationPolicy) (bool, error) {
	operation := &current.operation
	if operation.Attempts >= policy.RetryBudget {
		return engine.exhausted(ctx, current)
	}
	operation.Attempts++
	switch {
	case operation.NewRecordRevision == 0:
		return false, engine.move(ctx, current, lifecycle.StateAcquiring, "retry", "acquiring")
	case operation.DeploymentID == "":
		return false, engine.move(ctx, current, lifecycle.StateStaging, "retry", "staging")
	case operation.HealthEvidenceDigest == "":
		return false, engine.move(ctx, current, lifecycle.StateActivating, "retry", "activating")
	}
	return false, engine.move(ctx, current, lifecycle.StateRevoking, "retry", "revoking")
}

// exhausted ends retries along the path that cleans up whatever was already
// mutated: nothing minted ends terminally; a minted credential that never
// became healthy is rolled back and quarantined; an interrupted revocation
// needs reconciliation. The intermediate hop re-enters the failed step so the
// evidence names it.
func (engine *Engine) exhausted(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	switch {
	case operation.NewRecordRevision == 0:
		return true, engine.move(ctx, current, lifecycle.StateTerminalFailure, "retry", "budget-exhausted")
	case operation.DeploymentID == "":
		if err := engine.move(ctx, current, lifecycle.StateStaging, "retry", "budget-exhausted"); err != nil {
			return true, err
		}
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "stage", "budget-exhausted")
	case operation.HealthEvidenceDigest == "":
		if err := engine.move(ctx, current, lifecycle.StateActivating, "retry", "budget-exhausted"); err != nil {
			return true, err
		}
		return false, engine.move(ctx, current, lifecycle.StateRollingBack, "activate", "budget-exhausted")
	}
	if err := engine.move(ctx, current, lifecycle.StateRevoking, "retry", "budget-exhausted"); err != nil {
		return true, err
	}
	return true, engine.move(ctx, current, lifecycle.StateReconciliationRequired, "revoke", "budget-exhausted")
}

func (engine *Engine) rollback(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	policy, err := engine.policy(ctx, operation.PolicyID, operation.PolicyDigest)
	if err != nil {
		return true, err
	}
	if err := engine.authorize(policy, *operation, "rollback"); err != nil {
		return true, engine.move(ctx, current, lifecycle.StateTerminalFailure, "rollback", "not-approved")
	}
	if operation.DeploymentID != "" {
		if err := engine.Deployer.Rollback(ctx, engine.deployment(*operation), operation.DeploymentID); err != nil {
			return true, engine.fail(ctx, current, "rollback", "failed")
		}
	}
	return false, engine.move(ctx, current, lifecycle.StateRolledBack, "rollback", "rolled-back")
}

// quarantine retires the credential that never served traffic. If the
// provider refuses, the operation still ends quarantined with evidence that
// says so, because the old credential is live again and nothing else is
// pending.
func (engine *Engine) quarantine(ctx context.Context, current *run) (bool, error) {
	operation := &current.operation
	code := "revoked"
	if operation.NewCredentialID != "" {
		policy, err := engine.policy(ctx, operation.PolicyID, operation.PolicyDigest)
		switch {
		case err != nil || engine.authorize(policy, *operation, "revoke") != nil:
			code = "revoke-not-approved"
		case engine.Credentials.Revoke(ctx, operation.NewCredentialID) != nil:
			code = "revoke-failed"
		}
	}
	return true, engine.move(ctx, current, lifecycle.StateQuarantined, "quarantine", code)
}

func (engine *Engine) providerFailure(ctx context.Context, current *run, stage string, err error) (bool, error) {
	switch retryClass(err) {
	case provider.RetrySafe:
		return engine.retryable(ctx, current, stage, "retryable")
	case provider.RetryNever:
		return true, engine.fail(ctx, current, stage, "refused")
	}
	return true, engine.move(ctx, current, lifecycle.StateReconciliationRequired, stage, "ambiguous")
}

func (engine *Engine) retryable(ctx context.Context, current *run, stage, code string) (bool, error) {
	if err := engine.move(ctx, current, lifecycle.StateRetryable, stage, code); err != nil {
		return true, err
	}
	// Retry immediately within the same run; the budget stops loops.
	return false, nil
}

// fail stops the operation along the only exit its state allows: terminal
// failure where nothing was deployed, rollback where something was, and
// reconciliation where the old credential's fate is unknown.
func (engine *Engine) fail(ctx context.Context, current *run, stage, code string) error {
	for _, to := range []lifecycle.State{lifecycle.StateTerminalFailure, lifecycle.StateRollingBack, lifecycle.StateReconciliationRequired} {
		if lifecycle.CanTransition(current.operation.State, to) {
			return engine.move(ctx, current, to, stage, code)
		}
	}
	return fmt.Errorf("rotation operation cannot fail from state %q", current.operation.State)
}

// move persists a transition and its evidence. The operation is saved first:
// an unrecorded transition would let a resumed run repeat a mutation, while
// missing evidence is only a reporting gap.
func (engine *Engine) move(ctx context.Context, current *run, to lifecycle.State, stage, code string) error {
	if err := current.operation.Move(to, engine.now()); err != nil {
		return err
	}
	revision, err := engine.Store.SaveOperation(ctx, current.operation, current.revision)
	if err != nil {
		return fmt.Errorf("rotation transition to %s could not be recorded: %w", to, err)
	}
	current.revision = revision
	current.entered = to
	return engine.record(ctx, current, stage, code)
}

func (engine *Engine) record(ctx context.Context, current *run, stage, code string) error {
	evidence, err := lifecycle.NewEvidence(current.previous, current.operation.ID, stage, code, engine.DeviceID, engine.now(), engine.DevicePrivate)
	if err != nil {
		return err
	}
	if _, err := engine.Store.AppendEvidence(ctx, current.operation.ID, evidence, engine.PolicyKey); err != nil {
		return fmt.Errorf("rotation evidence could not be recorded: %w", err)
	}
	current.previous = &evidence
	return nil
}

// policy loads and fully verifies the automation policy: device signature
// from the trusted key, validity window, and the owner's separate approval.
func (engine *Engine) policy(ctx context.Context, id, expectedDigest string) (lifecycle.AutomationPolicy, error) {
	policy, _, err := engine.Store.LoadPolicy(ctx, id)
	if err != nil {
		return policy, fmt.Errorf("rotation policy unavailable: %w", err)
	}
	now := engine.now()
	if policy.ID != id || !strings.EqualFold(hex.EncodeToString(policy.PublicKey), hex.EncodeToString(engine.PolicyKey)) || policy.ApprovingDevice != engine.DeviceID || policy.VaultID != engine.VaultID || policy.Validate(now) != nil {
		return policy, ErrNotApproved
	}
	if expectedDigest != "" {
		digest, err := policy.Digest()
		if err != nil || digest != expectedDigest {
			return policy, ErrNotApproved
		}
	}
	if err := engine.OwnerVerify(policy, now); err != nil {
		return policy, ErrNotApproved
	}
	return policy, nil
}

func (engine *Engine) authorize(policy lifecycle.AutomationPolicy, operation lifecycle.Operation, action string) error {
	if operation.PolicyID != policy.ID {
		return ErrNotApproved
	}
	if err := policy.Authorizes(binding(operation, policy, action), engine.now()); err != nil {
		return ErrNotApproved
	}
	return nil
}

func (engine *Engine) identity(ctx context.Context, operation lifecycle.Operation) error {
	identity, err := engine.Credentials.Identify(ctx)
	if err != nil || identity.Provider != operation.Provider || identity.ID != operation.ProviderIdentity {
		return errors.New("provider identity does not match the operation")
	}
	return nil
}

func (engine *Engine) deployment(operation lifecycle.Operation) lifecycle.DeploymentRequest {
	return lifecycle.DeploymentRequest{OperationID: operation.ID, Target: provider.Target{ProjectID: operation.Target.ProjectID, EnvironmentID: operation.Target.EnvironmentID}, RecordRevisions: map[string]int64{operation.DestinationRecord: operation.NewRecordRevision}, PreviousRecordRevisions: map[string]int64{operation.DestinationRecord: operation.PreviousRecordRevision}}
}

func binding(operation lifecycle.Operation, policy lifecycle.AutomationPolicy, action string) lifecycle.AuthorizationBinding {
	return lifecycle.AuthorizationBinding{VaultID: operation.VaultID, Bundle: operation.Bundle, ManifestDigest: operation.ManifestDigest, Environment: policy.Environment, Provider: operation.Provider, ProviderIdentity: operation.ProviderIdentity, CredentialClass: operation.CredentialClass, Operation: action, Target: operation.Target}
}

// retryClass reads the provider's own classification. Untyped errors are
// ambiguous: nothing proves the mutation did not happen.
func retryClass(err error) provider.RetryClass {
	var typed provider.Error
	if errors.As(err, &typed) {
		return typed.Retry
	}
	var pointer *provider.Error
	if errors.As(err, &pointer) && pointer != nil {
		return pointer.Retry
	}
	return provider.RetryAmbiguous
}

func digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
