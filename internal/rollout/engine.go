package rollout

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

var ErrReconciliationRequired = errors.New("provider outcome requires explicit reconciliation")

type PlanInput struct {
	Bundle           string
	ManifestDigest   string
	SnapshotRevision int64
	Target           TargetBinding
	Kind             PlanKind
	Names            []PlannedName
	Actions          []Action
}

type Confirmation struct {
	Kind        string
	Provider    string
	Bundle      string
	ActionCount int
	Destructive bool
}

type ConfirmFunc func(context.Context, Confirmation) error

type Engine struct {
	Adapter provider.Adapter
	Store   Store
	Now     func() time.Time
	Random  func([]byte) error
}

// Plan performs metadata-only provider inspection, binds the immutable
// identity and target, and saves an encrypted short-lived plan. It never calls
// Write or Verify.
func (engine *Engine) Plan(ctx context.Context, input PlanInput) (ProviderPlan, error) {
	if err := engine.ready(); err != nil {
		return ProviderPlan{}, err
	}
	capabilities := engine.Adapter.Capabilities()
	if !capabilities.ReadMetadata {
		return ProviderPlan{}, errors.New("provider does not support metadata inspection")
	}
	identity, err := engine.Adapter.Identity(ctx)
	if err != nil {
		safe := provider.SanitizeError("identity", err)
		return ProviderPlan{}, safe
	}
	if identity.Provider == "" || identity.ID == "" {
		return ProviderPlan{}, errors.New("provider returned an invalid identity")
	}
	target := providerTarget(input.Target)
	metadata, err := engine.Adapter.Inspect(ctx, target)
	if err != nil {
		safe := provider.SanitizeError("inspect", err)
		return ProviderPlan{}, safe
	}
	if !sameProviderTarget(metadata.Target, target) {
		return ProviderPlan{}, errors.New("provider target identity does not match the requested binding")
	}
	if input.Kind == PlanKindBindingNames {
		for index := range input.Names {
			variable := metadata.Variables[input.Names[index].Service][input.Names[index].Name]
			if variable.Presence == provider.PresencePresent {
				input.Names[index].State = "present"
			} else {
				input.Names[index].State = "absent"
			}
		}
	}
	if err := actionsSupported(input.Actions, capabilities); err != nil {
		return ProviderPlan{}, err
	}
	now := engine.now()
	plan := ProviderPlan{
		Version: PlanVersion, Bundle: input.Bundle, ManifestDigest: input.ManifestDigest,
		SnapshotRevision: input.SnapshotRevision, Provider: identity.Provider,
		ProviderIdentity: identity.ID, ProviderRevision: metadata.Revision, Target: cloneBinding(input.Target),
		Kind: input.Kind, Names: append([]PlannedName(nil), input.Names...),
		Actions: append([]Action(nil), input.Actions...), CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(PlanTTL).Format(time.RFC3339),
	}
	plan.Digest, err = plan.ComputeDigest()
	if err != nil {
		return ProviderPlan{}, errors.New("provider plan could not be digested")
	}
	if err := plan.Validate(now); err != nil {
		return ProviderPlan{}, err
	}
	if err := engine.Store.ValidateSnapshot(ctx, plan); err != nil {
		return ProviderPlan{}, err
	}
	if _, err := engine.Store.SavePlan(ctx, plan, 0); err != nil {
		return ProviderPlan{}, fmt.Errorf("save encrypted provider plan: %w", err)
	}
	return plan, nil
}

// Apply validates every binding, obtains interactive confirmations, durably
// records the operation, and advances it through write and verification.
func (engine *Engine) Apply(ctx context.Context, planID string, confirm ConfirmFunc) (Operation, error) {
	if err := engine.ready(); err != nil {
		return Operation{}, err
	}
	plan, _, err := engine.Store.LoadPlan(ctx, planID)
	if err != nil {
		return Operation{}, err
	}
	if len(plan.Actions) == 0 {
		return Operation{}, errors.New("provider plan has no confirmed writes")
	}
	if err := engine.validatePlanContext(ctx, plan, true); err != nil {
		return Operation{}, err
	}
	if confirm == nil {
		return Operation{}, errors.New("interactive rollout confirmation is required")
	}
	destructive := hasDestructive(plan.Actions)
	if err := confirm(ctx, Confirmation{Kind: "apply", Provider: plan.Provider,
		Bundle: plan.Bundle, ActionCount: len(plan.Actions), Destructive: destructive}); err != nil {
		return Operation{}, errors.New("rollout cancelled before provider writes")
	}
	if destructive {
		if err := confirm(ctx, Confirmation{Kind: "destructive", Provider: plan.Provider,
			Bundle: plan.Bundle, ActionCount: destructiveCount(plan.Actions), Destructive: true}); err != nil {
			return Operation{}, errors.New("rollout cancelled before provider writes")
		}
	}
	operation, err := engine.newOperation(plan)
	if err != nil {
		return Operation{}, err
	}
	revision, err := engine.Store.SaveOperation(ctx, operation, 0)
	if err != nil {
		return Operation{}, fmt.Errorf("save confirmed rollout operation: %w", err)
	}
	return engine.advance(ctx, plan, operation, revision)
}

// Resume continues a confirmed operation without repeating confirmation or
// already proven writes. Ambiguous non-idempotent in-flight actions are
// inspected and stopped unless metadata proves committed or not committed.
func (engine *Engine) Resume(ctx context.Context, operationID string) (Operation, error) {
	if err := engine.ready(); err != nil {
		return Operation{}, err
	}
	operation, revision, err := engine.Store.LoadOperation(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if operation.Status == StatusReady || operation.Status == StatusLimited ||
		operation.Status == StatusPromoted || operation.Status == StatusRolledBack {
		return operation, nil
	}
	if operation.Status == StatusFailed {
		for _, item := range operation.Actions {
			if item.LastError != nil {
				return operation, *item.LastError
			}
		}
		return operation, errors.New("rollout operation failed")
	}
	plan, _, err := engine.Store.LoadPlan(ctx, operation.PlanID)
	if err != nil {
		return operation, err
	}
	if !operationMatchesPlan(operation, plan) {
		return operation, errors.New("rollout operation does not match its provider plan")
	}
	if err := engine.validatePlanContext(ctx, plan, false); err != nil {
		return operation, err
	}
	return engine.advance(ctx, plan, operation, revision)
}

func (engine *Engine) advance(ctx context.Context, plan ProviderPlan, operation Operation, revision int64) (Operation, error) {
	capabilities := engine.Adapter.Capabilities()
	metadata, err := engine.Adapter.Inspect(ctx, providerTarget(plan.Target))
	if err != nil {
		return operation, provider.SanitizeError("inspect", err)
	}
	if batch, ok := engine.Adapter.(provider.AtomicBatchAdapter); ok {
		var batchErr error
		operation, revision, batchErr = engine.advanceAtomicBatch(ctx, batch, plan, operation, revision)
		if batchErr != nil {
			return operation, batchErr
		}
	}
	for index := range operation.Actions {
		item := &operation.Actions[index]
		if item.Status == ActionVerified || item.Status == ActionLimited || item.Status == ActionCommitted {
			continue
		}
		if item.Status == ActionInFlight && !retriableWrite(capabilities) {
			resolved := reconcileAction(item, metadata, engine.nowString())
			if !resolved {
				operation.Status = StatusReconciliation
				operation.UpdatedAt = engine.nowString()
				revision, err = engine.Store.SaveOperation(ctx, operation, revision)
				_ = revision
				if err != nil {
					return operation, err
				}
				return operation, ErrReconciliationRequired
			}
			operation.UpdatedAt = engine.nowString()
			revision, err = engine.Store.SaveOperation(ctx, operation, revision)
			if err != nil {
				return operation, err
			}
			if item.Status == ActionCommitted {
				continue
			}
		}
		var value []byte
		if item.Action.Record != "" {
			value, err = engine.Store.LoadRecord(ctx, plan.Bundle, item.Action.Record,
				item.Action.ExpectedRecordRevision)
			if err != nil {
				return operation, err
			}
		} else {
			value = []byte(item.Action.PublicValue)
		}
		operation.Status = StatusWriting
		item.Status = ActionInFlight
		item.Attempts++
		item.LastAttemptAt = engine.nowString()
		item.LastError = nil
		operation.UpdatedAt = item.LastAttemptAt
		revision, err = engine.Store.SaveOperation(ctx, operation, revision)
		if err != nil {
			wipe(value)
			return operation, err
		}
		request := provider.NewWriteRequest(item.Action.Operation, providerTarget(plan.Target),
			item.Action.Service, item.Action.ServiceID, item.Action.Name, item.WriteKey, value)
		wipe(value)
		evidence, writeErr := engine.Adapter.Write(ctx, request)
		request.Destroy()
		if writeErr != nil {
			safe := provider.SanitizeError("write", writeErr)
			item.LastError = &safe
			if safe.Retry == provider.RetrySafe || safe.Retry == provider.RetryNever {
				item.Status = ActionPending
			} else {
				item.Status = ActionInFlight
			}
			if safe.Retry == provider.RetryNever {
				operation.Status = StatusFailed
			} else if safe.Retry == provider.RetryAmbiguous && !retriableWrite(capabilities) {
				operation.Status = StatusReconciliation
			} else {
				operation.Status = StatusRetryable
			}
			operation.UpdatedAt = engine.nowString()
			if _, err := engine.Store.SaveOperation(ctx, operation, revision); err != nil {
				return operation, err
			}
			return operation, safe
		}
		if evidence.CommittedAt == "" {
			evidence.CommittedAt = engine.nowString()
		}
		if evidence.Validate() != nil {
			return operation, errors.New("provider returned invalid write evidence")
		}
		item.WriteEvidence = &evidence
		item.Status = ActionCommitted
		operation.UpdatedAt = engine.nowString()
		revision, err = engine.Store.SaveOperation(ctx, operation, revision)
		if err != nil {
			return operation, err
		}
	}

	operation.Status = StatusWritten
	operation.UpdatedAt = engine.nowString()
	revision, err = engine.Store.SaveOperation(ctx, operation, revision)
	if err != nil {
		return operation, err
	}
	operation.Status = StatusVerifying
	operation.UpdatedAt = engine.nowString()
	revision, err = engine.Store.SaveOperation(ctx, operation, revision)
	if err != nil {
		return operation, err
	}
	limited := false
	for index := range operation.Actions {
		item := &operation.Actions[index]
		if item.Status == ActionVerified {
			continue
		}
		if !capabilities.Validate {
			evidence := provider.VerifyEvidence{Result: provider.VerificationLimited,
				Presence: provider.PresenceUnknown, VerifiedAt: engine.nowString(),
				Reason: "validation-unsupported"}
			item.VerifyEvidence = &evidence
			item.Status = ActionLimited
			limited = true
		} else {
			evidence, verifyErr := engine.Adapter.Verify(ctx, provider.VerifyRequest{
				Target: providerTarget(plan.Target), Service: item.Action.Service,
				ServiceID: item.Action.ServiceID, Name: item.Action.Name, WriteKey: item.WriteKey,
				ProviderOperationID: item.WriteEvidence.ProviderOperationID,
			})
			if verifyErr != nil {
				safe := provider.SanitizeError("verify", verifyErr)
				item.LastError = &safe
				if safe.Retry == provider.RetryNever {
					operation.Status = StatusFailed
				} else {
					operation.Status = StatusRetryable
				}
				operation.UpdatedAt = engine.nowString()
				if _, err := engine.Store.SaveOperation(ctx, operation, revision); err != nil {
					return operation, err
				}
				return operation, safe
			}
			if evidence.VerifiedAt == "" {
				evidence.VerifiedAt = engine.nowString()
			}
			if evidence.Validate() != nil {
				return operation, errors.New("provider returned invalid verification evidence")
			}
			item.VerifyEvidence = &evidence
			if evidence.Result == provider.VerificationVerified {
				item.Status = ActionVerified
			} else {
				item.Status = ActionLimited
				limited = true
			}
		}
		operation.UpdatedAt = engine.nowString()
		revision, err = engine.Store.SaveOperation(ctx, operation, revision)
		if err != nil {
			return operation, err
		}
	}
	operation.Status = StatusReady
	if limited {
		operation.Status = StatusLimited
	}
	operation.UpdatedAt = engine.nowString()
	if _, err := engine.Store.SaveOperation(ctx, operation, revision); err != nil {
		return operation, err
	}
	return operation, nil
}

func (engine *Engine) advanceAtomicBatch(ctx context.Context, adapter provider.AtomicBatchAdapter,
	plan ProviderPlan, operation Operation, revision int64) (Operation, int64, error) {
	pending := false
	for _, item := range operation.Actions {
		if item.Status != ActionCommitted && item.Status != ActionVerified && item.Status != ActionLimited {
			pending = true
		}
	}
	if !pending {
		return operation, revision, nil
	}
	for _, item := range operation.Actions {
		if item.Status == ActionCommitted || item.Status == ActionVerified || item.Status == ActionLimited {
			return operation, revision, errors.New("atomic rollout operation has partial commit evidence")
		}
	}
	requests := make([]provider.WriteRequest, 0, len(operation.Actions))
	defer func() {
		for index := range requests {
			requests[index].Destroy()
		}
	}()
	for index := range operation.Actions {
		item := &operation.Actions[index]
		var value []byte
		var err error
		if item.Action.Record != "" {
			value, err = engine.Store.LoadRecord(ctx, plan.Bundle, item.Action.Record,
				item.Action.ExpectedRecordRevision)
			if err != nil {
				return operation, revision, err
			}
		} else {
			value = []byte(item.Action.PublicValue)
		}
		requests = append(requests, provider.NewWriteRequest(item.Action.Operation,
			providerTarget(plan.Target), item.Action.Service, item.Action.ServiceID,
			item.Action.Name, item.WriteKey, value))
		wipe(value)
		item.Status = ActionInFlight
		item.Attempts++
		item.LastAttemptAt = engine.nowString()
		item.LastError = nil
	}
	operation.Status = StatusWriting
	operation.UpdatedAt = engine.nowString()
	var err error
	revision, err = engine.Store.SaveOperation(ctx, operation, revision)
	if err != nil {
		return operation, revision, err
	}
	evidence, stageErr := adapter.Stage(ctx, requests)
	if stageErr != nil {
		safe := provider.SanitizeError("stage", stageErr)
		for index := range operation.Actions {
			operation.Actions[index].LastError = &safe
			if safe.Retry == provider.RetrySafe || safe.Retry == provider.RetryNever {
				operation.Actions[index].Status = ActionPending
			}
		}
		operation.Status = StatusRetryable
		if safe.Retry == provider.RetryNever {
			operation.Status = StatusFailed
		} else if safe.Retry == provider.RetryAmbiguous {
			operation.Status = StatusReconciliation
		}
		operation.UpdatedAt = engine.nowString()
		revision, err = engine.Store.SaveOperation(ctx, operation, revision)
		if err != nil {
			return operation, revision, err
		}
		return operation, revision, safe
	}
	if evidence.CommittedAt == "" {
		evidence.CommittedAt = engine.nowString()
	}
	if evidence.ProviderOperationID == "" || evidence.Validate() != nil {
		return operation, revision, errors.New("provider returned invalid atomic stage evidence")
	}
	for index := range operation.Actions {
		copy := evidence
		operation.Actions[index].WriteEvidence = &copy
		operation.Actions[index].Status = ActionCommitted
	}
	operation.Status = StatusWritten
	operation.UpdatedAt = engine.nowString()
	revision, err = engine.Store.SaveOperation(ctx, operation, revision)
	return operation, revision, err
}

func (engine *Engine) validatePlanContext(ctx context.Context, plan ProviderPlan, enforceExpiry bool) error {
	validationTime := engine.now()
	if !enforceExpiry {
		created, err := time.Parse(time.RFC3339, plan.CreatedAt)
		if err != nil {
			return errors.New("provider plan creation time is invalid")
		}
		validationTime = created
	}
	if err := plan.Validate(validationTime); err != nil {
		return err
	}
	if err := engine.Store.ValidateSnapshot(ctx, plan); err != nil {
		return err
	}
	identity, err := engine.Adapter.Identity(ctx)
	if err != nil {
		return provider.SanitizeError("identity", err)
	}
	if identity.Provider != plan.Provider || identity.ID != plan.ProviderIdentity {
		return errors.New("provider identity does not match the plan")
	}
	metadata, err := engine.Adapter.Inspect(ctx, providerTarget(plan.Target))
	if err != nil {
		return provider.SanitizeError("inspect", err)
	}
	if !sameProviderTarget(metadata.Target, providerTarget(plan.Target)) {
		return errors.New("provider target does not match the plan")
	}
	if plan.ProviderRevision != "" && metadata.Revision != plan.ProviderRevision {
		return errors.New("provider deployed revision does not match the plan")
	}
	return actionsSupported(plan.Actions, engine.Adapter.Capabilities())
}

func (engine *Engine) newOperation(plan ProviderPlan) (Operation, error) {
	random := engine.Random
	if random == nil {
		random = func(destination []byte) error {
			_, err := rand.Read(destination)
			return err
		}
	}
	raw := make([]byte, 18)
	if err := random(raw); err != nil {
		return Operation{}, errors.New("rollout operation ID generation failed")
	}
	id := hex.EncodeToString(raw)
	now := engine.nowString()
	operation := Operation{Version: OperationVersion, ID: id, PlanID: plan.ID(), PlanDigest: plan.Digest,
		Bundle: plan.Bundle, ManifestDigest: plan.ManifestDigest, SnapshotRevision: plan.SnapshotRevision,
		Provider: plan.Provider, ProviderIdentity: plan.ProviderIdentity, Target: cloneBinding(plan.Target),
		ProviderRevision: plan.ProviderRevision,
		Status:           StatusConfirmed, CreatedAt: now, UpdatedAt: now,
		Actions: make([]OperationAction, len(plan.Actions))}
	for index, action := range plan.Actions {
		sum := sha256.Sum256([]byte("envbank.rollout.write.v1\x00" + id + "\x00" + action.ID))
		operation.Actions[index] = OperationAction{Action: action, Status: ActionPending,
			WriteKey: hex.EncodeToString(sum[:])}
	}
	return operation, operation.Validate()
}

func (engine *Engine) ready() error {
	if engine == nil || engine.Adapter == nil || engine.Store == nil {
		return errors.New("rollout engine is not configured")
	}
	return nil
}

func (engine *Engine) now() time.Time {
	now := time.Now()
	if engine.Now != nil {
		now = engine.Now()
	}
	return now.UTC().Truncate(time.Second)
}

func (engine *Engine) nowString() string { return engine.now().Format(time.RFC3339) }

func reconcileAction(item *OperationAction, metadata provider.MetadataState, now string) bool {
	service := metadata.Variables[item.Action.Service]
	variable, exists := service[item.Action.Name]
	if !exists {
		variable.Presence = provider.PresenceUnknown
	}
	if variable.LastWriteKey != "" && variable.LastWriteKey == item.WriteKey {
		if item.WriteEvidence == nil {
			item.WriteEvidence = &provider.WriteEvidence{}
		}
		item.WriteEvidence.CommittedAt = now
		item.Status = ActionCommitted
		return true
	}
	if item.Action.Operation == "revoke" && variable.Presence == provider.PresenceAbsent {
		item.WriteEvidence = &provider.WriteEvidence{CommittedAt: now}
		item.Status = ActionCommitted
		return true
	}
	if item.Action.Operation != "revoke" && variable.Presence == provider.PresenceAbsent {
		item.Status = ActionPending
		return true
	}
	return false
}

func actionsSupported(actions []Action, capabilities provider.Capabilities) error {
	for _, action := range actions {
		supported := false
		switch action.Operation {
		case "create":
			supported = capabilities.Create
		case "update":
			supported = capabilities.Update
		case "upsert":
			supported = capabilities.Create && capabilities.Update
		case "revoke":
			supported = capabilities.Revoke
		}
		if !supported {
			return fmt.Errorf("provider does not support action %s", action.ID)
		}
	}
	return nil
}

func retriableWrite(capabilities provider.Capabilities) bool {
	return capabilities.SupportsIdempotencyKey || capabilities.SupportsIdempotentWrite
}

func operationMatchesPlan(operation Operation, plan ProviderPlan) bool {
	if operation.PlanDigest != plan.Digest || operation.Bundle != plan.Bundle ||
		operation.ManifestDigest != plan.ManifestDigest || operation.SnapshotRevision != plan.SnapshotRevision ||
		operation.Provider != plan.Provider || operation.ProviderIdentity != plan.ProviderIdentity ||
		operation.ProviderRevision != plan.ProviderRevision ||
		!sameBinding(operation.Target, plan.Target) || len(operation.Actions) != len(plan.Actions) {
		return false
	}
	for index := range plan.Actions {
		if operation.Actions[index].Action != plan.Actions[index] {
			return false
		}
	}
	return true
}

// OperationMatchesPlan verifies every immutable operation binding against the
// encrypted plan that authorized it.
func OperationMatchesPlan(operation Operation, plan ProviderPlan) bool {
	return operationMatchesPlan(operation, plan)
}

func providerTarget(binding TargetBinding) provider.Target {
	return provider.Target{ProjectID: binding.ProjectID, EnvironmentID: binding.EnvironmentID,
		ServiceIDs: cloneStrings(binding.ServiceIDs)}
}

func sameProviderTarget(left, right provider.Target) bool {
	return left.ProjectID == right.ProjectID && left.EnvironmentID == right.EnvironmentID &&
		sameStrings(left.ServiceIDs, right.ServiceIDs)
}

func sameBinding(left, right TargetBinding) bool {
	return left.ProjectID == right.ProjectID && left.EnvironmentID == right.EnvironmentID &&
		sameStrings(left.ServiceIDs, right.ServiceIDs)
}

func sameStrings(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func cloneBinding(binding TargetBinding) TargetBinding {
	binding.ServiceIDs = cloneStrings(binding.ServiceIDs)
	return binding
}

func cloneStrings(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func hasDestructive(actions []Action) bool { return destructiveCount(actions) != 0 }
func destructiveCount(actions []Action) int {
	count := 0
	for _, action := range actions {
		if action.Operation == "revoke" {
			count++
		}
	}
	return count
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// StableActionOrder is useful to planners that build actions from maps.
func StableActionOrder(actions []Action) {
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Service == actions[j].Service {
			return actions[i].Name < actions[j].Name
		}
		return actions[i].Service < actions[j].Service
	})
}
