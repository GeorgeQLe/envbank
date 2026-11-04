package vercelworkflow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
)

// Disposable Production acceptance. It drives the SAME configured workflow
// (owner hardware approval, lease, journal, rollout engine, staged redeploy,
// health gate, promotion) and then the SAME signed rollback path, against a
// second owner-created, clearly marked disposable Production project whose
// only domain is its default PROJECT_NAME.vercel.app alias.
//
// It qualifies "provider Production API promotion/rollback" only. It does not
// qualify physical Secure Enclave user presence, browser/owner observation or
// the external computer-use controller. It never approves, imports, creates,
// deletes, revokes or changes project settings, and never retries an
// uncertain provider mutation (lost responses are reconciled read-only).
const (
	ProductionAcceptanceLevel = "provider-production"
	productionTargetPrefix    = "disposable-production:"
	productionReconcilePolls  = 12
	productionGuardDenied     = "ACCEPTANCE_GUARD_DENIED"
)

// ProductionAcceptanceTarget is the operator's out-of-band restatement of the
// exact disposable Production project. Production has no branch scoping.
type ProductionAcceptanceTarget struct {
	TeamID, ProjectID, ProjectName string
}

// ParseProductionAcceptanceTarget parses
// "disposable-production:TEAM_ID/PROJECT_ID/PROJECT_NAME". The Preview form
// ("disposable:...@branch") is refused, so the two modes cannot be confused.
func ParseProductionAcceptanceTarget(raw string) (ProductionAcceptanceTarget, error) {
	invalid := errors.New("production acceptance target must be disposable-production:team_ID/prj_ID/envbank-acceptance-NAME")
	rest, ok := strings.CutPrefix(raw, productionTargetPrefix)
	if !ok || strings.ContainsAny(rest, "@:?#% \t\r\n") {
		return ProductionAcceptanceTarget{}, invalid
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return ProductionAcceptanceTarget{}, invalid
	}
	target := ProductionAcceptanceTarget{TeamID: parts[0], ProjectID: parts[1], ProjectName: parts[2]}
	scope := vercel.Scope{TeamID: target.TeamID, ProjectID: target.ProjectID, Environment: vercel.EnvironmentProduction}
	if scope.Validate() != nil || !acceptanceProjectName.MatchString(target.ProjectName) {
		return ProductionAcceptanceTarget{}, invalid
	}
	return target, nil
}

// CheckProductionAcceptanceManifest requires a manifest that can only write
// the single dedicated, GENERATED fixture record into the exact Production
// environment of the disposable project. It is separate from the Preview-only
// CheckAcceptanceManifest, which stays unchanged.
func CheckProductionAcceptanceManifest(document *contract.Document, target ProductionAcceptanceTarget) error {
	invalid := errors.New("production acceptance manifest is not the dedicated disposable fixture")
	if document == nil || len(document.Manifest.Targets) != 1 {
		return invalid
	}
	t, ok := document.Manifest.Targets["vercel"]
	if !ok || t.TeamID != target.TeamID || t.ProjectID != target.ProjectID || t.Project != target.ProjectName || t.Environment != vercel.EnvironmentProduction || t.GitBranch != "" || t.CustomEnvironmentID != "" || len(t.Services) != 1 {
		return invalid
	}
	service, ok := t.Services["environment"]
	if !ok || len(service.Variables) != 1 || len(service.Absent) != 0 {
		return invalid
	}
	variable, ok := service.Variables[AcceptanceRecordName]
	if !ok || variable.Source != "record" || variable.Value != "" || variable.Record == "" {
		return invalid
	}
	record, ok := document.Manifest.Records[variable.Record]
	if !ok || record.Source != "generate" {
		return invalid
	}
	return nil
}

// ProductionAcceptanceGuard is implemented by the configured *vercel.Adapter
// with the same token, scope and safe-error handling. It is read-only.
type ProductionAcceptanceGuard interface {
	VerifyDisposableProductionProject(context.Context, string) error
}

// productionGuardAdapter forwards every provider method to the configured
// adapter and admits each mutation (variable write, redeploy, promote,
// rollback) only after a FRESH disposable-project guard, both immediately
// before invoking the adapter and again at HTTP send time through the
// composed (never replaced) mutation-authorization hook. The workflow's
// signed-policy check runs before and after the last guard. Concurrent external writers can still
// race the last read; Vercel offers no compare-and-swap.
type productionGuardAdapter struct {
	Adapter
	guard      ProductionAcceptanceGuard
	name       string
	lastDenied *string
}

func (a productionGuardAdapter) check(ctx context.Context) error {
	if e := a.guard.VerifyDisposableProductionProject(ctx, a.name); e != nil {
		*a.lastDenied = guardCode(e)
		return errors.New("disposable production guard denied")
	}
	return nil
}

func (a productionGuardAdapter) admit(ctx context.Context) (context.Context, error) {
	if e := a.check(ctx); e != nil {
		return ctx, e
	}
	return vercel.WithAdditionalMutationAuthorization(ctx, a.check), nil
}

func (a productionGuardAdapter) Write(ctx context.Context, request provider.WriteRequest) (provider.WriteEvidence, error) {
	guarded, e := a.admit(ctx)
	if e != nil {
		return provider.WriteEvidence{}, provider.NewError("write", 0, productionGuardDenied, provider.RetrySafe)
	}
	return a.Adapter.Write(guarded, request)
}

func (a productionGuardAdapter) Redeploy(ctx context.Context, sourceID, operationID string) (vercel.Deployment, error) {
	guarded, e := a.admit(ctx)
	if e != nil {
		return vercel.Deployment{}, vercel.RefusedBeforeSend("redeploy", productionGuardDenied)
	}
	return a.Adapter.Redeploy(guarded, sourceID, operationID)
}

func (a productionGuardAdapter) Promote(ctx context.Context, id string) error {
	guarded, e := a.admit(ctx)
	if e != nil {
		return vercel.RefusedBeforeSend("promote", productionGuardDenied)
	}
	return a.Adapter.Promote(guarded, id)
}

func (a productionGuardAdapter) Rollback(ctx context.Context, id string) error {
	guarded, e := a.admit(ctx)
	if e != nil {
		return vercel.RefusedBeforeSend("rollback", productionGuardDenied)
	}
	return a.Adapter.Rollback(guarded, id)
}

func guardCode(e error) string {
	var safe provider.Error
	if errors.As(e, &safe) && safe.Code != "" {
		return safe.Code
	}
	return "GUARD_UNAVAILABLE"
}

// ProductionFixtureEvidence holds status integers only. Health statuses are
// 200 when the health probe succeeded and 0 otherwise.
type ProductionFixtureEvidence struct {
	SourceHealthStatus    int `json:"source_health_status"`
	SourceStatus          int `json:"source_status"`
	DeploymentStatus      int `json:"deployment_status"`
	NegativeControlStatus int `json:"negative_control_status"`
	RollbackHealthStatus  int `json:"rollback_health_status"`
	RollbackStatus        int `json:"rollback_status"`
}

// ProductionAcceptanceReceipt contains fixed codes, opaque IDs and status
// integers only: never a value, HMAC, challenge or hash.
type ProductionAcceptanceReceipt struct {
	Result               string                    `json:"result"`
	Blocker              string                    `json:"blocker,omitempty"`
	GuardCode            string                    `json:"guard_code,omitempty"`
	Level                string                    `json:"acceptance_level"`
	APIPromotionRollback string                    `json:"api_promotion_rollback"`
	FullWorkflow         string                    `json:"full_workflow"`
	FullWorkflowBlockers []string                  `json:"full_workflow_blockers"`
	TeamID               string                    `json:"team_id"`
	ProjectID            string                    `json:"project_id"`
	Environment          string                    `json:"environment"`
	PlanID               string                    `json:"plan_id,omitempty"`
	OperationID          string                    `json:"operation_id,omitempty"`
	RolloutID            string                    `json:"rollout_id,omitempty"`
	SourceDeploymentID   string                    `json:"source_deployment_id,omitempty"`
	DeploymentID         string                    `json:"deployment_id,omitempty"`
	CurrentDeploymentID  string                    `json:"current_deployment_id,omitempty"`
	Stage                string                    `json:"stage,omitempty"`
	VariableState        string                    `json:"variable_state"`
	VariablesReverted    bool                      `json:"variables_reverted"`
	VariableNote         string                    `json:"variable_note"`
	HealthChecks         int                       `json:"health_checks"`
	OwnerApprovalKeyID   string                    `json:"owner_approval_key_id,omitempty"`
	Fixture              ProductionFixtureEvidence `json:"fixture"`
	Recovery             []string                  `json:"recovery,omitempty"`
	Cleanup              []string                  `json:"cleanup,omitempty"`
}

type ProductionAcceptanceRunner struct {
	Backend *Backend
	Target  ProductionAcceptanceTarget
	// Probe is the status-only fixture probe (see NewAcceptanceProbe).
	Probe AcceptanceProbe
	// Health is a status-only health probe; nil uses Backend.Probe or
	// ProbeHealth, exactly like the workflow health gate.
	Health func(context.Context, vercel.Deployment, string) (bool, error)
	Random io.Reader
}

const (
	variableNotStarted = "deployment rollback never reverts Vercel project variables; no fixture variable was written by this run"
	variableApplied    = "deployment rollback does not revert Vercel project variables: " + AcceptanceRecordName + " remains applied to this project's production environment until the owner deletes it"
)

func (runner ProductionAcceptanceRunner) health(ctx context.Context, d vercel.Deployment) int {
	probe := runner.Health
	if probe == nil {
		probe = runner.Backend.Probe
	}
	if probe == nil {
		probe = ProbeHealth
	}
	if ok, e := probe(ctx, d, AcceptanceHealthPath); e == nil && ok {
		return http.StatusOK
	}
	return 0
}

// finish records final operation evidence read-only from the journal, never
// erasing it, and offers owner-run recovery commands scoped to the operation.
func (runner ProductionAcceptanceRunner) finish(ctx context.Context, receipt ProductionAcceptanceReceipt, code string) ProductionAcceptanceReceipt {
	if code != "" {
		receipt.Result, receipt.Blocker = "BLOCKED", code
	} else {
		receipt.Result, receipt.Blocker = "PASS", ""
	}
	b := runner.Backend
	checkpoint, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer stop()
	if receipt.PlanID != "" && digestID.MatchString(receipt.PlanID) {
		if state, _, e := b.Store.LoadDeployment(checkpoint, OperationID(receipt.PlanID)); e == nil && b.bindState(checkpoint, state) == nil {
			r := result(state)
			receipt.OperationID, receipt.RolloutID, receipt.Stage, receipt.VariableState = r.OperationID, r.RolloutID, r.Stage, r.VariableState
			if state.DeploymentID != "" {
				receipt.DeploymentID = state.DeploymentID
			}
		}
	}
	receipt.VariablesReverted = false
	receipt.VariableNote = variableNotStarted
	if receipt.VariableState == "applied-not-reverted" {
		receipt.VariableNote = variableApplied
	} else if receipt.VariableState != "" && receipt.VariableState != "not-started" {
		receipt.VariableNote = "project variables may be partially applied; deployment rollback does not revert them; reconcile the recorded rollout before restoring or deleting anything"
	}
	if receipt.VariableState == "" {
		receipt.VariableState = "not-started"
	}
	if receipt.OperationID == "" {
		return receipt
	}
	scope := b.Adapter.Scope()
	receipt.Cleanup = []string{
		"delete Secret variable " + AcceptanceRecordName + " scoped to production in project " + scope.ProjectID + ", or delete the disposable project itself",
		"revoke the dedicated acceptance API token and any dedicated protection-bypass credential",
	}
	if receipt.DeploymentID != "" {
		receipt.Cleanup = append([]string{"after production is confirmed on " + receipt.SourceDeploymentID + ", delete acceptance deployment " + receipt.DeploymentID + " in project " + scope.ProjectID}, receipt.Cleanup...)
	}
	if code == "" {
		return receipt
	}
	if current, e := b.Adapter.CurrentDeployment(checkpoint); e == nil {
		receipt.CurrentDeploymentID = current.ID
	}
	receipt.Recovery = []string{"inspect read-only: envbank vercel status --manifest MANIFEST --operation " + receipt.OperationID}
	if code == "PROMOTION_REQUEST_NOT_SENT" && receipt.CurrentDeploymentID == receipt.SourceDeploymentID && receipt.SourceDeploymentID != "" {
		receipt.Recovery = append(receipt.Recovery, "this attempt was not promoted by the workflow and the fresh target read is the approved source; resolve the domain guard and review before resuming: envbank vercel resume --manifest MANIFEST --operation "+receipt.OperationID)
		return receipt
	}
	activationMayHaveStarted := receipt.Stage == "promoting" || receipt.Stage == "complete" || receipt.Stage == "unexpected-promotion" || receipt.Stage == "rollback-pending" || receipt.Stage == "rolling-back"
	if activationMayHaveStarted || receipt.DeploymentID != "" && receipt.CurrentDeploymentID == receipt.DeploymentID {
		receipt.Recovery = append(receipt.Recovery, "check the current target and disposable-domain guard before owner-run scoped rollback to "+receipt.SourceDeploymentID+" with the existing signed authority: envbank vercel rollback --manifest MANIFEST --operation "+receipt.OperationID)
	} else if receipt.Stage == "failed" {
		receipt.Recovery = append(receipt.Recovery, "inspect the target and failed rollout; reconcile values and create a new reviewed plan if needed; no rollback request is inferred from this failed stage")
	} else {
		receipt.Recovery = append(receipt.Recovery, "activation status is unproven; inspect the target and resume only after review: envbank vercel resume --manifest MANIFEST --operation "+receipt.OperationID)
	}
	return receipt
}

func (receipt *ProductionAcceptanceReceipt) capture(r mcpserver.Result) {
	receipt.OperationID, receipt.RolloutID, receipt.Stage, receipt.VariableState = r.OperationID, r.RolloutID, r.Stage, r.VariableState
	if len(r.Health) > 0 {
		receipt.HealthChecks = r.Health[0].SuccessfulChecks
	}
}

// Run never approves, imports, creates or deletes. It refuses unless the
// owner already approved this exact plan (stage, verify, activate AND
// rollback) with the pinned hardware key.
func (runner ProductionAcceptanceRunner) Run(ctx context.Context, planID string) ProductionAcceptanceReceipt {
	receipt := ProductionAcceptanceReceipt{Result: "BLOCKED", Level: ProductionAcceptanceLevel, APIPromotionRollback: "not-qualified", FullWorkflow: "not-qualified",
		FullWorkflowBlockers: []string{"PHYSICAL_SECURE_ENCLAVE_PRESENCE_NOT_OBSERVED_BY_HARNESS", "OWNER_BROWSER_OBSERVATION_NOT_QUALIFIED", "EXTERNAL_OBSERVATION_CONTROLLER_UNQUALIFIED"},
		TeamID:               runner.Target.TeamID, ProjectID: runner.Target.ProjectID, Environment: vercel.EnvironmentProduction, VariableState: "not-started", VariableNote: variableNotStarted}
	plain := func(code string) ProductionAcceptanceReceipt {
		receipt.Result, receipt.Blocker = "BLOCKED", code
		return receipt
	}
	b := runner.Backend
	if b.ready() != nil || runner.Probe == nil {
		return plain("VERCEL_BACKEND_UNAVAILABLE")
	}
	scope := b.Adapter.Scope()
	if scope.Environment != vercel.EnvironmentProduction {
		return plain("ACCEPTANCE_PRODUCTION_ONLY")
	}
	if scope.TeamID != runner.Target.TeamID || scope.ProjectID != runner.Target.ProjectID || scope.GitBranch != "" || scope.CustomEnvironmentID != "" {
		return plain("ACCEPTANCE_TARGET_MISMATCH")
	}
	if CheckProductionAcceptanceManifest(b.Document, runner.Target) != nil {
		return plain("ACCEPTANCE_MANIFEST_NOT_DISPOSABLE")
	}
	guard, ok := b.Adapter.(ProductionAcceptanceGuard)
	if !ok {
		return plain("ACCEPTANCE_PROJECT_NOT_MARKED")
	}
	// Fresh read-only guard BEFORE any plan, record or deployment read.
	if e := guard.VerifyDisposableProductionProject(ctx, runner.Target.ProjectName); e != nil {
		receipt.GuardCode = guardCode(e)
		return plain("ACCEPTANCE_PRODUCTION_PROJECT_NOT_DISPOSABLE")
	}
	if !ownerapproval.ValidPublicKey(b.OwnerApprovalKey) {
		return plain("OWNER_APPROVAL_KEY_NOT_PINNED")
	}
	if !digestID.MatchString(planID) {
		return plain("ACCEPTANCE_PLAN_INVALID")
	}
	receipt.PlanID = planID
	plan, _, e := b.Store.LoadPlan(ctx, planID)
	if e != nil || b.bindPlan(plan) != nil {
		return plain("ACCEPTANCE_PLAN_INVALID")
	}
	// Promotion is never started without already-signed rollback authority.
	policy, e := b.policy(ctx, plan, "stage")
	for _, verb := range []string{"verify", "activate", "rollback"} {
		if e == nil {
			_, e = b.policy(ctx, plan, verb)
		}
	}
	if e != nil {
		return plain("OWNER_APPROVAL_REQUIRED")
	}
	receipt.OwnerApprovalKeyID = policy.OwnerApproval.KeyID
	receipt.SourceDeploymentID = policy.DeploymentSourceID
	if policy.DeploymentHealthPath != AcceptanceHealthPath {
		return plain("ACCEPTANCE_HEALTH_PATH_MISMATCH")
	}
	record, revision := "", int64(0)
	for _, action := range plan.Actions {
		if action.Name == AcceptanceRecordName {
			record, revision = action.Record, action.ExpectedRecordRevision
		}
	}
	if record == "" || revision < 1 || len(plan.Actions) != 1 {
		return plain("ACCEPTANCE_PLAN_INVALID")
	}
	if _, _, e := b.Store.LoadDeployment(ctx, OperationID(planID)); e == nil {
		return runner.finish(ctx, receipt, "ACCEPTANCE_OPERATION_ALREADY_STARTED")
	} else if !errors.Is(e, ErrNotFound) {
		return plain("ACCEPTANCE_JOURNAL_UNAVAILABLE")
	}

	// Source: the current, READY, owned Production deployment.
	source, e := b.Adapter.Deployment(ctx, policy.DeploymentSourceID)
	if e != nil || source.ID != policy.DeploymentSourceID || source.ReadyState != "READY" || source.Environment != vercel.EnvironmentProduction || source.CommitSHA == "" || source.Prebuilt {
		return plain("ACCEPTANCE_SOURCE_UNAVAILABLE")
	}
	current, e := b.Adapter.CurrentDeployment(ctx)
	if e != nil || current.ID != source.ID {
		return plain("ACCEPTANCE_SOURCE_NOT_CURRENT_PRODUCTION")
	}
	// Rollback baseline must be healthy before anything is changed.
	receipt.Fixture.SourceHealthStatus = runner.health(ctx, source)
	if receipt.Fixture.SourceHealthStatus != http.StatusOK {
		return plain("ACCEPTANCE_BASELINE_UNHEALTHY")
	}

	challenger := AcceptanceRunner{Random: runner.Random}
	sourceChallenge, e1 := challenger.challenge()
	deploymentChallenge, e2 := challenger.challenge()
	rollbackChallenge, e3 := challenger.challenge()
	controlChallenge, e4 := challenger.challenge()
	controlProof, e5 := challenger.challenge()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return plain("ACCEPTANCE_RANDOM_UNAVAILABLE")
	}
	snapshot, snapshotRevision, snapshotErr := b.Store.Snapshot(ctx, plan.Bundle)
	if snapshotErr != nil || snapshot.Validate() != nil || snapshotRevision != plan.SnapshotRevision || snapshot.ManifestDigest != plan.ManifestDigest || snapshot.Bundle != plan.Bundle || snapshot.RecordRevisions[record] != revision || snapshot.Sources[record].Source != "generate" || snapshot.Sources[record].Status != "ready" {
		return plain("ACCEPTANCE_GENERATED_FIXTURE_REQUIRED")
	}
	currentPolicy, authErr := b.policy(ctx, plan, "stage")
	if ctx.Err() != nil || authErr != nil || !sameApproval(policy, currentPolicy) {
		return plain("OWNER_APPROVAL_REQUIRED")
	}
	value, e := b.Store.LoadRecord(ctx, plan.Bundle, record, revision)
	if e != nil {
		return plain("ACCEPTANCE_FIXTURE_RECORD_UNAVAILABLE")
	}
	if len(value) < acceptanceMinSecretBytes {
		wipeBytes(value)
		return plain("ACCEPTANCE_FIXTURE_TOO_SHORT")
	}
	sourceProof := AcceptanceProof(value, sourceChallenge)
	deploymentProof := AcceptanceProof(value, deploymentChallenge)
	rollbackProof := AcceptanceProof(value, rollbackChallenge)
	wipeBytes(value)

	// Baseline: the source must already hold an OLDER generated value (409).
	// 204 means the new value is already live; 424 means no rollback baseline.
	status, e := runner.Probe(ctx, source, map[string]string{AcceptanceChallengeHeader: sourceChallenge, AcceptanceProofHeader: sourceProof})
	receipt.Fixture.SourceStatus = status
	switch {
	case e != nil:
		return plain("ACCEPTANCE_FIXTURE_UNREACHABLE")
	case status == FixtureMatch:
		return plain("ACCEPTANCE_FIXTURE_NOT_FRESH")
	case status == FixtureAbsent:
		return plain("ACCEPTANCE_BASELINE_FIXTURE_ABSENT")
	case status != FixtureMismatch:
		return plain("ACCEPTANCE_FIXTURE_UNREACHABLE")
	}

	// Same Backend, but every mutation is freshly admitted by the guard.
	denied := ""
	guarded := *b
	guarded.Adapter = productionGuardAdapter{Adapter: b.Adapter, guard: guard, name: runner.Target.ProjectName, lastDenied: &denied}
	blockedWith := func(code string) ProductionAcceptanceReceipt {
		if denied != "" {
			receipt.GuardCode = denied
		}
		return runner.finish(ctx, receipt, code)
	}

	result, e := guarded.Call(ctx, "envbank_workflow_start", mcpserver.Request{PlanID: planID})
	polls := 0
	for calls := 1; ; calls++ {
		if e != nil {
			return blockedWith("ACCEPTANCE_WORKFLOW_CALL_FAILED")
		}
		receipt.capture(result)
		if result.BlockerCode != "" {
			// A lost/queued promotion response is reconciled read-only: resume in
			// "promoting" only re-reads aliases and never re-sends the promote.
			reconcilable := result.Stage == "promoting" && (result.BlockerCode == "ALIAS_RECONCILIATION_REQUIRED" || result.BlockerCode == "PROMOTION_RECONCILIATION_REQUIRED")
			if !reconcilable || polls >= productionReconcilePolls || result.OperationID == "" {
				return blockedWith(result.BlockerCode)
			}
			polls++
			if b.wait(ctx, 5*time.Second) != nil {
				return blockedWith(result.BlockerCode)
			}
			result, e = guarded.Call(ctx, "envbank_workflow_resume", mcpserver.Request{OperationID: result.OperationID})
			continue
		}
		if result.Stage == "complete" {
			break
		}
		if result.Stage == "failed" || calls >= acceptanceMaxCalls || result.OperationID == "" {
			return blockedWith("ACCEPTANCE_WORKFLOW_INCOMPLETE")
		}
		if result.Stage == "building" && b.wait(ctx, 10*time.Second) != nil {
			return blockedWith("ACCEPTANCE_WORKFLOW_INCOMPLETE")
		}
		result, e = guarded.Call(ctx, "envbank_workflow_resume", mcpserver.Request{OperationID: result.OperationID})
	}

	state, _, e := b.Store.LoadDeployment(ctx, OperationID(planID))
	if e != nil || state.Stage != "complete" || state.DeploymentID == "" || state.SourceDeploymentID != source.ID {
		return blockedWith("ACCEPTANCE_DEPLOYMENT_UNPROVEN")
	}
	receipt.DeploymentID = state.DeploymentID
	promoted, e := b.Adapter.CurrentDeployment(ctx)
	if e != nil || promoted.ID != state.DeploymentID {
		return blockedWith("ACCEPTANCE_PROMOTION_UNPROVEN")
	}
	receipt.CurrentDeploymentID = promoted.ID
	status, e = runner.Probe(ctx, promoted, map[string]string{AcceptanceChallengeHeader: deploymentChallenge, AcceptanceProofHeader: deploymentProof})
	receipt.Fixture.DeploymentStatus = status
	if e != nil {
		return blockedWith("ACCEPTANCE_FIXTURE_UNREACHABLE")
	}
	if status != FixtureMatch {
		return blockedWith("ACCEPTANCE_FRESH_VALUE_NOT_CONSUMED")
	}
	status, e = runner.Probe(ctx, promoted, map[string]string{AcceptanceChallengeHeader: controlChallenge, AcceptanceProofHeader: controlProof})
	receipt.Fixture.NegativeControlStatus = status
	if e != nil || status != FixtureMismatch {
		return blockedWith("ACCEPTANCE_FIXTURE_CONTROL_FAILED")
	}

	// Rollback through the configured signed rollback path.
	result, e = guarded.Rollback(ctx, state.ID)
	polls = 0
	for {
		if e != nil {
			return blockedWith("ACCEPTANCE_ROLLBACK_CALL_FAILED")
		}
		receipt.capture(result)
		if result.BlockerCode == "" && result.Stage == "rolled-back" {
			break
		}
		reconcilable := result.Stage == "rolling-back" && (result.BlockerCode == "ALIAS_RECONCILIATION_REQUIRED" || result.BlockerCode == "ROLLBACK_RECONCILIATION_REQUIRED")
		if !reconcilable || polls >= productionReconcilePolls {
			code := result.BlockerCode
			if code == "" {
				code = "ACCEPTANCE_ROLLBACK_INCOMPLETE"
			}
			return blockedWith(code)
		}
		polls++
		if b.wait(ctx, 5*time.Second) != nil {
			return blockedWith(result.BlockerCode)
		}
		// Stage "rolling-back" only re-reads aliases; it never re-sends.
		result, e = guarded.Rollback(ctx, state.ID)
	}
	restored, e := b.Adapter.CurrentDeployment(ctx)
	if e != nil || restored.ID != source.ID {
		return blockedWith("ACCEPTANCE_ROLLBACK_UNPROVEN")
	}
	receipt.CurrentDeploymentID = restored.ID
	receipt.Fixture.RollbackHealthStatus = runner.health(ctx, restored)
	if receipt.Fixture.RollbackHealthStatus != http.StatusOK {
		return blockedWith("ACCEPTANCE_ROLLBACK_UNHEALTHY")
	}
	status, e = runner.Probe(ctx, restored, map[string]string{AcceptanceChallengeHeader: rollbackChallenge, AcceptanceProofHeader: rollbackProof})
	receipt.Fixture.RollbackStatus = status
	switch {
	case e != nil:
		return blockedWith("ACCEPTANCE_FIXTURE_UNREACHABLE")
	case status == FixtureMatch:
		return blockedWith("ACCEPTANCE_ROLLBACK_SERVES_NEW_VALUE")
	case status != FixtureMismatch:
		return blockedWith("ACCEPTANCE_ROLLBACK_FIXTURE_UNEXPECTED")
	}
	receipt.APIPromotionRollback = "pass"
	return runner.finish(ctx, receipt, "")
}
