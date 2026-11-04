package vercelworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"time"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var deploymentID = regexp.MustCompile(`^dpl_[A-Za-z0-9]{1,64}$`)

type Adapter interface {
	provider.Adapter
	Scope() vercel.Scope
	Deployment(context.Context, string) (vercel.Deployment, error)
	CurrentDeployment(context.Context) (vercel.Deployment, error)
	Redeploy(context.Context, string, string) (vercel.Deployment, error)
	FindDeployment(context.Context, string) (vercel.Deployment, error)
	ProveDeployment(context.Context, string, string, string) (vercel.Deployment, error)
	Promote(context.Context, string) error
	Rollback(context.Context, string) error
}

type State struct {
	Version            int                        `json:"version"`
	ID                 string                     `json:"id"`
	PlanID             string                     `json:"plan_id"`
	PolicyID           string                     `json:"policy_id"`
	PolicyDigest       string                     `json:"policy_digest"`
	Approval           lifecycle.AutomationPolicy `json:"approval"`
	ScopeFingerprint   string                     `json:"scope_fingerprint"`
	SourceDeploymentID string                     `json:"source_deployment_id"`
	DeploymentID       string                     `json:"deployment_id,omitempty"`
	RolloutID          string                     `json:"rollout_id,omitempty"`
	ProviderRevision   string                     `json:"provider_revision,omitempty"`
	HealthPath         string                     `json:"health_path"`
	Stage              string                     `json:"stage"`
	CreatedAt          string                     `json:"created_at"`
	UpdatedAt          string                     `json:"updated_at"`
	Health             lifecycle.HealthEvidence   `json:"health"`
}

func PolicyID(planID string) string    { return "vercel-" + planID }
func OperationID(planID string) string { return "vd-" + planID }
func ValidHealthPath(path string) bool {
	u, e := url.Parse(path)
	return e == nil && len(path) <= 256 && len(path) > 0 && path[0] == '/' && (len(path) < 2 || path[1] != '/') && !u.IsAbs() && u.Host == "" && u.RawQuery == "" && u.Fragment == "" && u.Path == path
}
func (state State) Validate() error {
	if state.Version != 1 || !digestID.MatchString(state.PlanID) || state.ID != OperationID(state.PlanID) || state.PolicyID != PolicyID(state.PlanID) || !digestID.MatchString(state.PolicyDigest) || !digestID.MatchString(state.ScopeFingerprint) || !deploymentID.MatchString(state.SourceDeploymentID) || !ValidHealthPath(state.HealthPath) {
		return errors.New("deployment state binding invalid")
	}
	if state.DeploymentID != "" && !deploymentID.MatchString(state.DeploymentID) {
		return errors.New("deployment state identity invalid")
	}
	if state.ProviderRevision != "" && !digestID.MatchString(state.ProviderRevision) {
		return errors.New("deployment metadata revision invalid")
	}
	for _, timestamp := range []string{state.CreatedAt, state.UpdatedAt} {
		t, e := time.Parse(time.RFC3339, timestamp)
		if e != nil || t.UTC().Format(time.RFC3339) != timestamp {
			return errors.New("deployment state time invalid")
		}
	}
	switch state.Stage {
	case "prepared", "writing", "deployment-pending", "deploying", "building", "health", "promote-pending", "promoting", "complete", "rollback-pending", "rolling-back", "rolled-back", "failed", "reconciliation-required", "unexpected-promotion":
		return nil
	}
	return errors.New("deployment state stage invalid")
}

type Backend struct {
	Document          *contract.Document
	Adapter           Adapter
	Store             Store
	VaultID, DeviceID string
	TrustedPolicyKey  ed25519.PublicKey
	// Probe must return only status, never response bodies. The default is a
	// credential-free, no-redirect GET to the owned deployment's HTTPS URL.
	Probe func(context.Context, vercel.Deployment, string) (bool, error)
	Now   func() time.Time
	Wait  func(context.Context, time.Duration) error
}

func (backend *Backend) now() time.Time {
	if backend.Now != nil {
		return backend.Now().UTC()
	}
	return time.Now().UTC()
}
func (backend *Backend) wait(ctx context.Context, d time.Duration) error {
	if backend.Wait != nil {
		return backend.Wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (backend *Backend) ready() error {
	if backend == nil || backend.Adapter == nil || backend.Store == nil || backend.VaultID == "" || backend.DeviceID == "" || len(backend.TrustedPolicyKey) != ed25519.PublicKeySize {
		return errors.New("Vercel backend unavailable")
	}
	scope, e := ScopeForManifest(backend.Document)
	if e != nil || scope != backend.Adapter.Scope() {
		return errors.New("Vercel backend scope mismatch")
	}
	return nil
}
func (backend *Backend) engine() *rollout.Engine {
	return &rollout.Engine{Adapter: backend.Adapter, Store: backend.Store, Now: backend.now}
}
func (backend *Backend) policy(ctx context.Context, plan rollout.ProviderPlan, operation string) (lifecycle.AutomationPolicy, error) {
	p, _, e := backend.Store.LoadPolicy(ctx, PolicyID(plan.ID()))
	if e != nil {
		return p, errors.New("Vercel approval unavailable")
	}
	scope := backend.Adapter.Scope()
	if p.ID != PolicyID(plan.ID()) || p.DeploymentPlanID != plan.ID() || p.DeploymentScopeFingerprint != scope.Fingerprint() || !deploymentID.MatchString(p.DeploymentSourceID) || !ValidHealthPath(p.DeploymentHealthPath) || p.ApprovingDevice != backend.DeviceID || !bytes.Equal(p.PublicKey, backend.TrustedPolicyKey) {
		return p, errors.New("Vercel approval binding invalid")
	}
	environment := "staging"
	if scope.Environment == "production" {
		environment = "production"
	}
	e = p.Authorizes(lifecycle.AuthorizationBinding{VaultID: backend.VaultID, Bundle: plan.Bundle, ManifestDigest: plan.ManifestDigest, Environment: environment, Provider: "vercel", ProviderIdentity: scope.TeamID + ":" + scope.ProjectID, CredentialClass: "vercel-environment-secret", Operation: operation, Target: lifecycle.TargetPolicy{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, backend.now())
	if e != nil {
		return p, errors.New("Vercel operation not approved")
	}
	return p, nil
}

func (backend *Backend) Call(ctx context.Context, name string, request mcpserver.Request) (mcpserver.Result, error) {
	if e := backend.ready(); e != nil {
		return mcpserver.Result{BlockerCode: "VERCEL_BACKEND_UNAVAILABLE"}, nil
	}
	if request.VaultID != "" && request.VaultID != backend.VaultID || request.Bundle != "" && request.Bundle != backend.Document.Manifest.Bundle || request.ManifestDigest != "" && request.ManifestDigest != backend.Document.Digest || request.Provider != "" && request.Provider != "vercel" || request.Environment != "" && request.Environment != backend.Adapter.Scope().Environment {
		return mcpserver.Result{BlockerCode: "POLICY_BINDING_MISMATCH"}, nil
	}
	if name == "envbank_capabilities" {
		return mcpserver.Result{Stage: "configured", Capability: "vercel:vault-to-secret=implemented,vercel:redeploy=implemented,vercel:production-promote=policy-gated,vercel:live-acceptance=pending"}, nil
	}
	if name == "envbank_setup_plan" {
		snapshot, revision, e := backend.Store.Snapshot(ctx, backend.Document.Manifest.Bundle)
		if e != nil {
			return mcpserver.Result{}, e
		}
		input, e := PlanInput(backend.Document, snapshot, revision)
		if e != nil {
			return mcpserver.Result{}, e
		}
		plan, e := backend.engine().Plan(ctx, input)
		return mcpserver.Result{PlanID: plan.ID(), Stage: "planned", Provider: "vercel"}, e
	}
	if name == "envbank_workflow_status" || name == "envbank_operation_evidence" {
		state, _, e := backend.Store.LoadDeployment(ctx, request.OperationID)
		if e != nil {
			return mcpserver.Result{}, e
		}
		if e = backend.bindState(ctx, state); e != nil {
			return mcpserver.Result{}, e
		}
		return result(state), nil
	}
	if name == "envbank_policy_status" {
		if !digestID.MatchString(request.PlanID) || request.PolicyID != "" && request.PolicyID != PolicyID(request.PlanID) {
			return mcpserver.Result{BlockerCode: "POLICY_BINDING_MISMATCH"}, nil
		}
		plan, _, e := backend.Store.LoadPlan(ctx, request.PlanID)
		if e != nil {
			return mcpserver.Result{}, e
		}
		if e = backend.bindPlan(plan); e != nil {
			return mcpserver.Result{}, e
		}
		if _, e = backend.policy(ctx, plan, "stage"); e != nil {
			return mcpserver.Result{BlockerCode: "VERCEL_APPROVAL_REQUIRED"}, nil
		}
		return mcpserver.Result{PlanID: plan.ID(), Stage: "approved"}, nil
	}
	if name == "envbank_deployment_rollback" {
		return backend.Rollback(ctx, request.OperationID)
	}
	if name != "envbank_workflow_start" && name != "envbank_workflow_resume" {
		return mcpserver.Result{BlockerCode: "PROVIDER_ROTATION_UNAVAILABLE"}, nil
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx = bounded
	// Lease outlives the entire bounded call and serializes all EnvBank writes
	// for this project, including different bundles and branches.
	scope := backend.Adapter.Scope()
	lease, leaseRevision, e := backend.Store.AcquireLease(ctx, "vercel:"+scope.TeamID+":"+scope.ProjectID, backend.DeviceID, 3*time.Minute)
	if e != nil {
		return mcpserver.Result{BlockerCode: "VERCEL_OPERATION_BUSY"}, nil
	}
	defer backend.Store.ReleaseLease(context.Background(), lease, leaseRevision)
	var state State
	var revision int64
	if name == "envbank_workflow_start" {
		if !digestID.MatchString(request.PlanID) || request.PolicyID != "" && request.PolicyID != PolicyID(request.PlanID) {
			return mcpserver.Result{BlockerCode: "POLICY_BINDING_MISMATCH"}, nil
		}
		state, revision, e = backend.Store.LoadDeployment(ctx, OperationID(request.PlanID))
		if errors.Is(e, ErrNotFound) {
			plan, _, loadErr := backend.Store.LoadPlan(ctx, request.PlanID)
			if loadErr != nil {
				return mcpserver.Result{}, loadErr
			}
			if e = backend.bindPlan(plan); e != nil {
				return mcpserver.Result{}, e
			}
			p, authErr := backend.policy(ctx, plan, "stage")
			if authErr != nil {
				return mcpserver.Result{BlockerCode: "VERCEL_APPROVAL_REQUIRED"}, nil
			}
			if plan.Validate(backend.now()) != nil {
				return mcpserver.Result{BlockerCode: "PLAN_EXPIRED"}, nil
			}
			source, sourceErr := backend.Adapter.Deployment(ctx, p.DeploymentSourceID)
			if sourceErr != nil || source.ReadyState != "READY" || source.CommitSHA == "" || source.Prebuilt {
				return mcpserver.Result{BlockerCode: "SOURCE_DEPLOYMENT_UNAVAILABLE"}, nil
			}
			if scope.Environment == "production" {
				current, err := backend.Adapter.CurrentDeployment(ctx)
				if err != nil || current.ID != source.ID {
					return mcpserver.Result{BlockerCode: "PRODUCTION_DEPLOYMENT_DRIFT"}, nil
				}
			}
			pd, _ := p.Digest()
			now := backend.now().Format(time.RFC3339)
			state = State{Version: 1, ID: OperationID(plan.ID()), PlanID: plan.ID(), PolicyID: p.ID, PolicyDigest: pd, Approval: p, ScopeFingerprint: scope.Fingerprint(), SourceDeploymentID: source.ID, HealthPath: p.DeploymentHealthPath, Stage: "prepared", CreatedAt: now, UpdatedAt: now, ProviderRevision: plan.ProviderRevision}
			revision, e = backend.Store.SaveDeployment(ctx, state, 0)
		}
	} else {
		state, revision, e = backend.Store.LoadDeployment(ctx, request.OperationID)
	}
	if e != nil {
		return mcpserver.Result{}, e
	}
	if e = backend.bindState(ctx, state); e != nil {
		return mcpserver.Result{}, e
	}
	return backend.advance(ctx, state, revision)
}

func (backend *Backend) bindPlan(plan rollout.ProviderPlan) error {
	scope := backend.Adapter.Scope()
	target := scope.Target()
	if plan.Provider != "vercel" || plan.ProviderIdentity != scope.TeamID+":"+scope.ProjectID || plan.Bundle != backend.Document.Manifest.Bundle || plan.ManifestDigest != backend.Document.Digest || plan.Target.ProjectID != target.ProjectID || plan.Target.EnvironmentID != target.EnvironmentID || len(plan.Target.ServiceIDs) != 1 || plan.Target.ServiceIDs["environment"] != scope.Fingerprint() {
		return errors.New("Vercel plan scope changed")
	}
	variables := backend.Document.Manifest.Targets["vercel"].Services["environment"].Variables
	if plan.Kind != rollout.PlanKindBindingNames || len(plan.Actions) != len(variables) || len(plan.Names) != len(variables) {
		return errors.New("Vercel plan variable set changed")
	}
	seen := map[string]bool{}
	for _, name := range plan.Names {
		variable, ok := variables[name.Name]
		if !ok || seen[name.Name] || name.Record != variable.Record || name.Desired != "present" || name.Service != "environment" || name.ServiceID != scope.Fingerprint() {
			return errors.New("Vercel plan names changed")
		}
		seen[name.Name] = true
	}
	clear(seen)
	for _, action := range plan.Actions {
		variable, ok := variables[action.Name]
		if !ok || seen[action.Name] || action.Operation != "upsert" || action.Service != "environment" || action.ServiceID != scope.Fingerprint() || action.Record != variable.Record || action.ValueSource != "" || action.PublicValue != "" {
			return errors.New("Vercel plan variable binding changed")
		}
		seen[action.Name] = true
	}
	return nil
}

// ValidatePlan exposes the fixed manifest/scope binding to the owner approval
// command without authorizing or executing any mutation.
func (backend *Backend) ValidatePlan(plan rollout.ProviderPlan) error { return backend.bindPlan(plan) }
func (backend *Backend) bindState(ctx context.Context, state State) error {
	if state.Validate() != nil || state.ScopeFingerprint != backend.Adapter.Scope().Fingerprint() {
		return errors.New("Vercel operation scope changed")
	}
	plan, _, e := backend.Store.LoadPlan(ctx, state.PlanID)
	if e != nil {
		return errors.New("Vercel operation plan unavailable")
	}
	return backend.bindPlan(plan)
}
func result(state State) mcpserver.Result {
	ids := []string{state.SourceDeploymentID}
	if state.DeploymentID != "" {
		ids = append(ids, state.DeploymentID)
	}
	variables := "not-started"
	if state.RolloutID != "" {
		variables = "possibly-partially-applied-not-reverted"
	}
	switch state.Stage {
	case "deployment-pending", "deploying", "building", "health", "promote-pending", "promoting", "complete", "rollback-pending", "rolling-back", "rolled-back", "unexpected-promotion":
		variables = "applied-not-reverted"
	}
	return mcpserver.Result{PlanID: state.PlanID, OperationID: state.ID, RolloutID: state.RolloutID, VariableState: variables, Provider: "vercel", Stage: state.Stage, ResourceIDs: ids, Health: []mcpserver.HealthEvidence{{CheckID: "approved-deployment-health", SuccessfulChecks: state.Health.SuccessfulChecks, Healthy: state.Health.Healthy}}}
}

// Renewal can extend expiry only. Preserve every other signed binding from
// the initial approval, including operations, key and recovery policy.
func sameApproval(a, b lifecycle.AutomationPolicy) bool {
	a.ExpiresAt, b.ExpiresAt = "", ""
	a.Signature, b.Signature = nil, nil
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}
