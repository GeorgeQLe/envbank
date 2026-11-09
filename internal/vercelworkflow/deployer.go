package vercelworkflow

import (
	"context"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/rotation"
)

// RotationDeployer adapts the Vercel workflow to rotation.Deployer. Stage
// plans the current snapshot and drives it to the promotion gate (or to
// completion for non-production scopes); Activate promotes and returns the
// deployment's health evidence; Rollback restores the previous production
// deployment. Every step goes through Backend.Call, so the approval, lease,
// durable-intent and reconciliation rules are the backend's own.
//
// The deployment ID the rotation engine records is the workflow operation
// ID, not a Vercel deployment ID, so Activate and Rollback can find the
// durable state again.
type RotationDeployer struct {
	Backend *Backend
	// SourceDeploymentID is the deployment to rebuild for non-production
	// scopes under a standing approval. Production resolves its own source.
	SourceDeploymentID string
	// MaxCalls bounds the resume loop of one Stage, Activate or Rollback call.
	MaxCalls int
	// PollInterval separates resume calls while Vercel is building.
	PollInterval time.Duration
}

var _ rotation.Deployer = (*RotationDeployer)(nil)

var terminalStages = map[string]bool{"failed": true, "rolled-back": true, "unexpected-promotion": true, "reconciliation-required": true}

func (deployer *RotationDeployer) ready(operation string) error {
	if deployer == nil || deployer.Backend == nil {
		return provider.NewError(operation, 0, "DEPLOYER_UNAVAILABLE", provider.RetryNever)
	}
	return deployer.Backend.ready()
}

func (deployer *RotationDeployer) production() bool {
	return deployer.Backend.Adapter.Scope().Environment == "production"
}

// Stage writes the record revisions the engine just stored and builds the
// deployment that consumes them. The snapshot must already carry exactly
// those revisions: a stale snapshot would deploy the retired credential.
func (deployer *RotationDeployer) Stage(ctx context.Context, request lifecycle.DeploymentRequest) (lifecycle.DeploymentEvidence, error) {
	if err := deployer.ready("stage"); err != nil {
		return lifecycle.DeploymentEvidence{}, provider.SanitizeError("stage", err)
	}
	backend := deployer.Backend
	snapshot, revision, err := backend.Store.Snapshot(ctx, backend.Document.Manifest.Bundle)
	if err != nil {
		return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "SNAPSHOT_UNAVAILABLE", provider.RetrySafe)
	}
	if len(request.RecordRevisions) == 0 {
		return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "SNAPSHOT_STALE", provider.RetryNever)
	}
	for record, want := range request.RecordRevisions {
		if snapshot.RecordRevisions[record] != want {
			return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "SNAPSHOT_STALE", provider.RetryNever)
		}
	}
	input, err := PlanInput(backend.Document, snapshot, revision)
	if err != nil {
		return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "INVALID_MANIFEST", provider.RetryNever)
	}
	plan, err := backend.engine().Plan(ctx, input)
	if err != nil {
		return lifecycle.DeploymentEvidence{}, provider.NewError("stage", 0, "PLAN_FAILED", provider.RetrySafe)
	}
	goal := "complete"
	if deployer.production() {
		goal = "promote-pending"
	}
	result, err := backend.Call(ctx, "envbank_workflow_start", mcpserver.Request{PlanID: plan.ID(), SourceDeploymentID: deployer.SourceDeploymentID})
	result, err = deployer.drive(ctx, "stage", result, err, goal)
	if err != nil {
		return lifecycle.DeploymentEvidence{}, err
	}
	return lifecycle.DeploymentEvidence{DeploymentID: result.OperationID, Status: result.Stage, At: backend.now().Format(time.RFC3339)}, nil
}

// Activate promotes a production deployment, or confirms a non-production
// one completed, and returns the health evidence the backend collected on
// the new deployment.
func (deployer *RotationDeployer) Activate(ctx context.Context, _ lifecycle.DeploymentRequest, deploymentID string) (lifecycle.HealthEvidence, error) {
	if err := deployer.ready("activate"); err != nil {
		return lifecycle.HealthEvidence{}, provider.SanitizeError("activate", err)
	}
	backend := deployer.Backend
	state, _, err := backend.Store.LoadDeployment(ctx, deploymentID)
	if err != nil {
		return lifecycle.HealthEvidence{}, provider.NewError("activate", 0, "DEPLOYMENT_UNKNOWN", provider.RetryAmbiguous)
	}
	if deployer.production() && state.Stage != "complete" {
		result, err := backend.Call(ctx, "envbank_workflow_resume", mcpserver.Request{OperationID: deploymentID})
		if _, err = deployer.drive(ctx, "activate", result, err, "complete"); err != nil {
			return lifecycle.HealthEvidence{}, err
		}
		if state, _, err = backend.Store.LoadDeployment(ctx, deploymentID); err != nil {
			return lifecycle.HealthEvidence{}, provider.NewError("activate", 0, "DEPLOYMENT_UNKNOWN", provider.RetryAmbiguous)
		}
	}
	if state.Stage != "complete" {
		return lifecycle.HealthEvidence{}, provider.NewError("activate", 0, "DEPLOYMENT_INCOMPLETE", provider.RetryNever)
	}
	if err := state.Health.Validate(); err != nil {
		return lifecycle.HealthEvidence{}, provider.NewError("activate", 0, "DEPLOYMENT_HEALTH_FAILED", provider.RetryNever)
	}
	return state.Health, nil
}

// Rollback restores the previous production deployment. Non-production
// scopes have nothing promoted to restore: the new deployment simply stops
// being used once the engine quarantines its credential.
func (deployer *RotationDeployer) Rollback(ctx context.Context, _ lifecycle.DeploymentRequest, deploymentID string) error {
	if err := deployer.ready("rollback"); err != nil {
		return provider.SanitizeError("rollback", err)
	}
	if !deployer.production() {
		return nil
	}
	result, err := deployer.Backend.Rollback(ctx, deploymentID)
	_, err = deployer.drive(ctx, "rollback", result, err, "rolled-back")
	return err
}

// drive resumes the workflow until it reaches goal, blocks, or fails.
// Blockers become typed provider errors so the rotation engine can decide
// between retry, rollback and reconciliation.
func (deployer *RotationDeployer) drive(ctx context.Context, operation string, result mcpserver.Result, err error, goal string) (mcpserver.Result, error) {
	backend := deployer.Backend
	calls := deployer.MaxCalls
	if calls <= 0 {
		calls = 40
	}
	interval := deployer.PollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	for attempt := 0; ; attempt++ {
		if err != nil {
			return result, provider.NewError(operation, 0, "WORKFLOW_ERROR", provider.RetryAmbiguous)
		}
		if result.BlockerCode != "" {
			return result, provider.NewError(operation, 0, result.BlockerCode, blockerRetry(result.BlockerCode))
		}
		if result.Stage == goal || goal == "promote-pending" && result.Stage == "complete" {
			return result, nil
		}
		if terminalStages[result.Stage] {
			return result, provider.NewError(operation, 0, "WORKFLOW_"+strings.ToUpper(strings.ReplaceAll(result.Stage, "-", "_")), provider.RetryNever)
		}
		if attempt >= calls {
			return result, provider.NewError(operation, 0, "WORKFLOW_TIMEOUT", provider.RetrySafe)
		}
		if result.OperationID == "" {
			return result, provider.NewError(operation, 0, "WORKFLOW_ERROR", provider.RetryAmbiguous)
		}
		previous := result.Stage
		result, err = backend.Call(ctx, "envbank_workflow_resume", mcpserver.Request{OperationID: result.OperationID})
		if err == nil && result.Stage == previous && result.BlockerCode == "" {
			// Vercel is still building; give it time before asking again.
			if waitErr := backend.wait(ctx, interval); waitErr != nil {
				return result, provider.NewError(operation, 0, "WORKFLOW_TIMEOUT", provider.RetrySafe)
			}
		}
	}
}

// blockerRetry maps the backend's blocker codes to retry classes. Anything
// that names reconciliation or an unexpected upstream state is ambiguous;
// transient waits are safe; everything else needs a different decision.
func blockerRetry(code string) provider.RetryClass {
	switch {
	case strings.Contains(code, "RECONCILIATION") || strings.Contains(code, "UNEXPECTED"):
		return provider.RetryAmbiguous
	case code == "VERCEL_OPERATION_BUSY" || code == "DEPLOYMENT_NOT_READY" || code == "DEPLOYMENT_HEALTH_REQUIRED" || strings.HasSuffix(code, "_REQUEST_NOT_SENT"):
		return provider.RetrySafe
	}
	return provider.RetryNever
}
