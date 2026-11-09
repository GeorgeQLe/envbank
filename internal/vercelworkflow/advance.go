package vercelworkflow

import (
	"context"
	"errors"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

func (backend *Backend) authorizeState(ctx context.Context, state State, verb string) error {
	if ctx.Err() != nil {
		return errors.New("deployment operation cancelled")
	}
	plan, _, e := backend.Store.LoadPlan(ctx, state.PlanID)
	if e != nil {
		return errors.New("deployment plan unavailable")
	}
	p, e := backend.policy(ctx, plan, verb)
	if e != nil {
		return e
	}
	if p.DeploymentSourceID != "" && p.DeploymentSourceID != state.SourceDeploymentID || p.DeploymentHealthPath != state.HealthPath {
		return errors.New("deployment approval changed target")
	}
	digest, e := state.Approval.Digest()
	expires, parseErr := time.Parse(time.RFC3339, state.Approval.ExpiresAt)
	if e != nil || digest != state.PolicyDigest || parseErr != nil || state.Approval.Validate(expires.Add(-time.Second)) != nil || !sameApproval(p, state.Approval) {
		return errors.New("deployment approval changed authority")
	}
	return nil
}
func (backend *Backend) save(ctx context.Context, state *State, revision *int64, stage string) error {
	state.Stage = stage
	state.UpdatedAt = backend.now().Format(time.RFC3339)
	next, e := backend.Store.SaveDeployment(ctx, *state, *revision)
	if e == nil {
		*revision = next
	}
	return e
}
func blocked(state State, code string) (mcpserver.Result, error) {
	r := result(state)
	r.BlockerCode = code
	return r, nil
}

// Every mutation is preceded by a durable stage. A restart in an in-flight
// stage performs read-only reconciliation and never blindly repeats a request.
func (backend *Backend) advance(ctx context.Context, state State, revision int64) (mcpserver.Result, error) {
	if state.Stage == "complete" || state.Stage == "rolled-back" || state.Stage == "failed" {
		return result(state), nil
	}
	verb := "stage"
	switch state.Stage {
	case "promote-pending", "promoting":
		verb = "activate"
	case "health":
		verb = "verify"
	case "rollback-pending", "rolling-back":
		verb = "rollback"
	}
	if e := backend.authorizeState(ctx, state, verb); e != nil {
		return blocked(state, "VERCEL_APPROVAL_REQUIRED")
	}
	ctx = vercel.WithMutationAuthorization(ctx, func(c context.Context) error {
		if e := backend.authorizeState(c, state, verb); e != nil {
			return e
		}
		if verb == "activate" && !backend.freshHealth(state.Health) {
			return errors.New("health evidence stale")
		}
		return nil
	})
	switch state.Stage {
	case "prepared":
		op, e := backend.approvedEngine(&state, &revision).Prepare(ctx, state.PlanID, func(_ context.Context, c rollout.Confirmation) error {
			if c.Provider != "vercel" || c.Destructive || c.ActionCount < 1 {
				return errors.New("Vercel writes outside approval")
			}
			return backend.authorizeState(ctx, state, "stage")
		})
		if e != nil {
			return blocked(state, "VERCEL_VARIABLE_PREPARE_FAILED")
		}
		state.RolloutID = op.ID
		if e = backend.save(ctx, &state, &revision, "writing"); e != nil {
			return mcpserver.Result{}, e
		}
	case "writing":
		if state.RolloutID == "" {
			return blocked(state, "VERCEL_JOURNAL_INVALID")
		}
		op, e := backend.approvedEngine(&state, &revision).Resume(ctx, state.RolloutID)
		if e != nil || op.Status != rollout.StatusReady && op.Status != rollout.StatusLimited {
			if op.Status == rollout.StatusReconciliation {
				if err := backend.save(ctx, &state, &revision, "reconciliation-required"); err != nil {
					return mcpserver.Result{}, err
				}
				return blocked(state, "VERCEL_VARIABLE_RECONCILIATION_REQUIRED")
			}
			if op.Status == rollout.StatusFailed {
				if err := backend.save(ctx, &state, &revision, "failed"); err != nil {
					return mcpserver.Result{}, err
				}
			}
			return blocked(state, "VERCEL_VARIABLE_WRITE_INCOMPLETE")
		}
		if e = backend.save(ctx, &state, &revision, "deployment-pending"); e != nil {
			return mcpserver.Result{}, e
		}
	case "deployment-pending":
		metadata, e := backend.Adapter.Inspect(ctx, backend.Adapter.Scope().Target())
		if e != nil || metadata.Revision != state.ProviderRevision {
			return blocked(state, "VERCEL_METADATA_DRIFT")
		}
		if e := backend.save(ctx, &state, &revision, "deploying"); e != nil {
			return mcpserver.Result{}, e
		}
		deployment, e := backend.Adapter.Redeploy(ctx, state.SourceDeploymentID, state.ID)
		if e != nil {
			if vercel.MutationNotSent(e) && !providerCode(e, "OPERATION_ALREADY_EXISTS") {
				if err := backend.save(ctx, &state, &revision, "deployment-pending"); err != nil {
					return mcpserver.Result{}, err
				}
				return blocked(state, "DEPLOYMENT_REQUEST_NOT_SENT")
			}
			return blocked(state, "DEPLOYMENT_RECONCILIATION_REQUIRED")
		}
		state.DeploymentID = deployment.ID
		if e = backend.save(ctx, &state, &revision, "building"); e != nil {
			return mcpserver.Result{}, e
		}
	case "deploying":
		deployment, e := backend.Adapter.FindDeployment(ctx, state.ID)
		if e != nil {
			return blocked(state, "DEPLOYMENT_RECONCILIATION_REQUIRED")
		}
		candidateID := deployment.ID
		deployment, e = backend.Adapter.ProveDeployment(ctx, candidateID, state.SourceDeploymentID, state.ID)
		if e != nil {
			if providerCode(e, "UNEXPECTED_PROMOTION") {
				return backend.unexpectedPromotion(ctx, state, revision, candidateID)
			}
			return blocked(state, "APPROVED_SOURCE_UNVERIFIED")
		}
		state.DeploymentID = deployment.ID
		if e = backend.save(ctx, &state, &revision, "building"); e != nil {
			return mcpserver.Result{}, e
		}
	case "building":
		deployment, e := backend.Adapter.ProveDeployment(ctx, state.DeploymentID, state.SourceDeploymentID, state.ID)
		if e != nil {
			if providerCode(e, "UNEXPECTED_PROMOTION") {
				return backend.unexpectedPromotion(ctx, state, revision, state.DeploymentID)
			}
			return blocked(state, "DEPLOYMENT_INSPECTION_FAILED")
		}
		switch deployment.ReadyState {
		case "READY":
			metadata, err := backend.Adapter.Inspect(ctx, backend.Adapter.Scope().Target())
			if err != nil || metadata.Revision != state.ProviderRevision {
				return blocked(state, "VERCEL_METADATA_DRIFT")
			}
			if e = backend.save(ctx, &state, &revision, "health"); e != nil {
				return mcpserver.Result{}, e
			}
		case "ERROR", "CANCELED":
			if e = backend.save(ctx, &state, &revision, "failed"); e != nil {
				return mcpserver.Result{}, e
			}
			return blocked(state, "DEPLOYMENT_BUILD_FAILED")
		default:
			return result(state), nil
		}
	case "health":
		deployment, e := backend.Adapter.ProveDeployment(ctx, state.DeploymentID, state.SourceDeploymentID, state.ID)
		if providerCode(e, "UNEXPECTED_PROMOTION") {
			return backend.unexpectedPromotion(ctx, state, revision, state.DeploymentID)
		}
		if e != nil || deployment.ReadyState != "READY" {
			return blocked(state, "DEPLOYMENT_NOT_READY")
		}
		probe := backend.Probe
		if probe == nil {
			probe = ProbeHealth
		}
		if !backend.freshHealth(state.Health) {
			state.Health = lifecycle.HealthEvidence{}
		}
		for state.Health.Validate() != nil {
			if e = backend.authorizeState(ctx, state, "verify"); e != nil {
				return blocked(state, "VERCEL_APPROVAL_REQUIRED")
			}
			ok, probeErr := probe(ctx, deployment, state.HealthPath)
			if probeErr != nil || !ok {
				state.Health = lifecycle.HealthEvidence{}
				if e = backend.save(ctx, &state, &revision, "failed"); e != nil {
					return mcpserver.Result{}, e
				}
				return blocked(state, "DEPLOYMENT_HEALTH_FAILED")
			}
			now := backend.now().Format(time.RFC3339)
			if state.Health.FirstSuccessAt == "" {
				state.Health.FirstSuccessAt = now
			}
			state.Health.LastSuccessAt = now
			state.Health.SuccessfulChecks++
			state.Health.Healthy = true
			if e = backend.save(ctx, &state, &revision, "health"); e != nil {
				return mcpserver.Result{}, e
			}
			if state.Health.Validate() != nil {
				if e = backend.wait(ctx, 15*time.Second); e != nil {
					return result(state), nil
				}
			}
		}
		if e = backend.save(ctx, &state, &revision, "promote-pending"); e != nil {
			return mcpserver.Result{}, e
		}
	case "promote-pending":
		if !backend.freshHealth(state.Health) {
			state.Health = lifecycle.HealthEvidence{}
			if e := backend.save(ctx, &state, &revision, "health"); e != nil {
				return mcpserver.Result{}, e
			}
			return blocked(state, "DEPLOYMENT_HEALTH_REQUIRED")
		}
		if backend.Adapter.Scope().Environment != "production" {
			if e := backend.save(ctx, &state, &revision, "complete"); e != nil {
				return mcpserver.Result{}, e
			}
			return result(state), nil
		}
		current, e := backend.Adapter.CurrentDeployment(ctx)
		if e == nil && current.ID == state.DeploymentID {
			return backend.unexpectedPromotion(ctx, state, revision, state.DeploymentID)
		}
		if e != nil || current.ID != state.SourceDeploymentID {
			return blocked(state, "PRODUCTION_DEPLOYMENT_DRIFT")
		}
		if e = backend.save(ctx, &state, &revision, "promoting"); e != nil {
			return mcpserver.Result{}, e
		}
		if e = backend.Adapter.Promote(ctx, state.DeploymentID); e != nil {
			if vercel.MutationNotSent(e) {
				if err := backend.save(ctx, &state, &revision, "promote-pending"); err != nil {
					return mcpserver.Result{}, err
				}
				return blocked(state, "PROMOTION_REQUEST_NOT_SENT")
			}
			return blocked(state, "PROMOTION_RECONCILIATION_REQUIRED")
		}
		return backend.reconcileAlias(ctx, state, revision, false)
	case "promoting":
		return backend.reconcileAlias(ctx, state, revision, false)
	case "rollback-pending":
		current, e := backend.Adapter.CurrentDeployment(ctx)
		if e != nil {
			return blocked(state, "ROLLBACK_RECONCILIATION_REQUIRED")
		}
		if current.ID == state.SourceDeploymentID {
			return backend.reconcileAlias(ctx, state, revision, true)
		}
		if current.ID != state.DeploymentID {
			return blocked(state, "PRODUCTION_DEPLOYMENT_DRIFT")
		}
		if e = backend.save(ctx, &state, &revision, "rolling-back"); e != nil {
			return mcpserver.Result{}, e
		}
		if e = backend.Adapter.Rollback(ctx, state.SourceDeploymentID); e != nil {
			if vercel.MutationNotSent(e) {
				if err := backend.save(ctx, &state, &revision, "rollback-pending"); err != nil {
					return mcpserver.Result{}, err
				}
				return blocked(state, "ROLLBACK_REQUEST_NOT_SENT")
			}
			return blocked(state, "ROLLBACK_RECONCILIATION_REQUIRED")
		}
		return backend.reconcileAlias(ctx, state, revision, true)
	case "rolling-back":
		return backend.reconcileAlias(ctx, state, revision, true)
	case "reconciliation-required":
		return blocked(state, "VERCEL_VARIABLE_RECONCILIATION_REQUIRED")
	case "unexpected-promotion":
		return blocked(state, "UNEXPECTED_PROMOTION_ROLLBACK_REQUIRED")
	}
	return result(state), nil
}

func (backend *Backend) reconcileAlias(ctx context.Context, state State, revision int64, rollback bool) (mcpserver.Result, error) {
	current, e := backend.Adapter.CurrentDeployment(ctx)
	if e != nil {
		return blocked(state, "ALIAS_RECONCILIATION_REQUIRED")
	}
	expected, stage := state.DeploymentID, "complete"
	if rollback {
		expected, stage = state.SourceDeploymentID, "rolled-back"
	}
	if current.ID != expected {
		return blocked(state, "ALIAS_RECONCILIATION_REQUIRED")
	}
	if e = backend.save(ctx, &state, &revision, stage); e != nil {
		return mcpserver.Result{}, e
	}
	return result(state), nil
}

// Rollback restores the approved prior production deployment. It never claims
// to recover unknown prior values of Vercel's write-only project variables.
func (backend *Backend) Rollback(ctx context.Context, id string) (mcpserver.Result, error) {
	if e := backend.ready(); e != nil {
		return mcpserver.Result{}, e
	}
	if backend.Adapter.Scope().Environment != "production" {
		return mcpserver.Result{BlockerCode: "PRODUCTION_ROLLBACK_ONLY"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	scope := backend.Adapter.Scope()
	lease, rev, e := backend.Store.AcquireLease(ctx, "vercel:"+scope.TeamID+":"+scope.ProjectID, backend.DeviceID, 3*time.Minute)
	if e != nil {
		return mcpserver.Result{BlockerCode: "VERCEL_OPERATION_BUSY"}, nil
	}
	defer backend.Store.ReleaseLease(context.Background(), lease, rev)
	state, revision, e := backend.Store.LoadDeployment(ctx, id)
	if e != nil {
		return mcpserver.Result{}, e
	}
	if e = backend.bindState(ctx, state); e != nil {
		return mcpserver.Result{}, e
	}
	if e = backend.authorizeState(ctx, state, "rollback"); e != nil {
		return blocked(state, "VERCEL_APPROVAL_REQUIRED")
	}
	if state.Stage == "rolled-back" {
		return result(state), nil
	}
	if state.DeploymentID != "" && (state.Stage == "complete" || state.Stage == "promoting" || state.Stage == "promote-pending" || state.Stage == "unexpected-promotion" || state.Stage == "failed" || state.Stage == "building" || state.Stage == "health") {
		if e = backend.save(ctx, &state, &revision, "rollback-pending"); e != nil {
			return mcpserver.Result{}, e
		}
	} else if state.Stage != "rollback-pending" && state.Stage != "rolling-back" {
		return blocked(state, "DEPLOYMENT_NOT_ROLLBACK_READY")
	}
	return backend.advance(ctx, state, revision)
}

func providerCode(err error, code string) bool {
	var safe provider.Error
	return errors.As(err, &safe) && safe.Code == code
}
func (backend *Backend) freshHealth(h lifecycle.HealthEvidence) bool {
	if h.Validate() != nil {
		return false
	}
	first, e1 := time.Parse(time.RFC3339, h.FirstSuccessAt)
	last, e2 := time.Parse(time.RFC3339, h.LastSuccessAt)
	now := backend.now()
	return e1 == nil && e2 == nil && !now.Before(last) && now.Sub(last) <= 2*time.Minute && now.Sub(first) <= 2*time.Minute
}
func (backend *Backend) unexpectedPromotion(ctx context.Context, state State, revision int64, id string) (mcpserver.Result, error) {
	if id != "" {
		state.DeploymentID = id
	}
	if e := backend.save(ctx, &state, &revision, "unexpected-promotion"); e != nil {
		return mcpserver.Result{}, e
	}
	return blocked(state, "UNEXPECTED_PROMOTION_ROLLBACK_REQUIRED")
}
