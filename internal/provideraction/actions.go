package provideraction

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// Action IDs (v1).
const (
	ActionNeonProjectCreate   = "neon.project.create"
	ActionNeonProjectDelete   = "neon.project.delete"
	ActionNeonRotate          = "neon.rotate"
	ActionNeonRolesPrepare    = "neon.roles.prepare"
	ActionVercelProjectCreate = "vercel.project.create"
	ActionVercelProjectDelete = "vercel.project.delete"
	ActionVercelEnvPush       = "vercel.env.push"
	ActionVercelRedeploy      = "vercel.redeploy"
	ActionStripeWebhookCreate = "stripe.webhook.create"
	ActionStripeWebhookRotate = "stripe.webhook.rotate"
	ActionStripeWebhookDelete = "stripe.webhook.delete"
	ActionBindingAllow        = "binding.allow"
)

// Step codes. A failed operation reports the step it failed in.
const (
	StepControl             = "control"
	StepNeonCreateProject   = "neon.create_project"
	StepNeonDeleteProject   = "neon.delete_project"
	StepNeonPrepareRoles    = "neon.prepare_roles"
	StepNeonCheckRoles      = "neon.check_roles"
	StepNeonCheckRoleState  = "neon.check_role_state"
	StepNeonResetActive     = "neon.reset_active_role"
	StepNeonResetNewRole    = "neon.reset_new_role"
	StepNeonInvalidateOld   = "neon.invalidate_old_role"
	StepVaultReadRevisions  = "vault.read_revisions"
	StepVaultMoveCurrent    = "vault.move_current"
	StepVercelCreateProject = "vercel.create_project"
	StepVercelDeleteProject = "vercel.delete_project"
	StepVercelEnvPush       = "vercel.env_push"
	StepVercelCurrent       = "vercel.current_deployment"
	StepVercelRedeploy      = "vercel.redeploy"
	StepVercelWaitReady     = "vercel.wait_ready"
	StepHealth              = "health"
	// Production releases (production.go).
	StepVercelPromote           = "vercel.promote"
	StepVercelVerifyProduction  = "vercel.verify_production"
	StepHealthProduction        = "health.production"
	StepVercelConfirmProduction = "vercel.confirm_production"
	StepVercelRollback          = "vercel.rollback"
	StepStripeReadEndpoint      = "stripe.read_endpoint"
	StepStripeCreate            = "stripe.create_endpoint"
	StepStripeDeleteOld         = "stripe.delete_old_endpoint"
	StepStripeDelete            = "stripe.delete_endpoint"
	StepBindingCheck            = "vault.check_bindings"
	StepBindingSave             = "vault.save_bindings"
	StepBindingRevoke           = "vault.revoke_bindings"
	StepBindingAllow            = "vault.allow_destination"
	StepProvenanceSave          = "vault.save_provenance"
	StepBindingDeployed         = "vault.record_deployments"
	StepBindingFinish           = "vault.finish_rotation"
	StepBindingForget           = "vault.forget_deployments"
)

// Fixed codes: refusals before any prompt, and failure codes of an
// operation. None carries caller input or provider text.
const (
	CodeUnavailable      = "PROVIDER_UNAVAILABLE"
	CodeUnknownOperation = "UNKNOWN_OPERATION"
	CodeRecordExists     = "RECORD_EXISTS"
	CodeControlMissing   = "CONTROL_CREDENTIAL_MISSING"
	CodeControlRefused   = "CONTROL_CREDENTIAL_REFUSED"
	CodeProviderFailed   = "PROVIDER_FAILED"
	CodeProviderResponse = "PROVIDER_RESPONSE_INVALID"
	CodeHealthFailed     = "HEALTH_CHECK_FAILED"
	CodeCancelled        = "CANCELLED"
	CodeTimedOut         = "TIMED_OUT"
	// CodeRolesNotPrepared: neon.rotate found the rotation roles not set up
	// (run neon.roles.prepare first). Nothing was changed.
	CodeRolesNotPrepared = "NEON_ROLES_NOT_PREPARED"
	// CodeRecordNotBound: a record has no live binding (none, revoked, or
	// its value was written by something other than this broker since).
	// Provider actions never push or overwrite it.
	CodeRecordNotBound = "RECORD_NOT_BOUND"
	// CodeDestinationNotAllowed: a bound record is not allowed to be
	// deployed to that Vercel project (see binding.allow).
	CodeDestinationNotAllowed = "DESTINATION_NOT_ALLOWED"
	// CodeBindingMismatch: a rotation names a record bound to another
	// provider resource or with another kind.
	CodeBindingMismatch = "BINDING_MISMATCH"
	// CodeBindingLimit: a binding already allows MaxAllowedDestinations.
	CodeBindingLimit = "BINDING_LIMIT"
	// CodeProductionDrift: production was not served by the deployment this
	// operation expected (before the promote: the one it read at the start;
	// after it: the promoted one). Nothing old was invalidated.
	CodeProductionDrift = "PRODUCTION_DEPLOYMENT_DRIFT"
	// CodeProductionNotServing: after the promote, Vercel's aliases were
	// never proven to serve the new deployment within the polling bound.
	CodeProductionNotServing = "PRODUCTION_NOT_SERVING"
	// CodeRotationScopeIncomplete: a rotated record was deployed (by this
	// broker) to a Vercel scope the rotation does not name; invalidating the
	// old credential would break it. Name every scope in the binding's
	// deployed_to.
	CodeRotationScopeIncomplete = "ROTATION_SCOPE_INCOMPLETE"
	// CodeNeonActiveRoleMismatch: the records' bindings do not determine the
	// active rotation role (missing or inconsistent role state), or params
	// roles assert another order than the bindings.
	CodeNeonActiveRoleMismatch = "NEON_ACTIVE_ROLE_MISMATCH"
	// CodeNeonOwnerRoleMismatch: owner_role is not the role Neon reports as
	// the database's owner, or a rotation role is that owner.
	CodeNeonOwnerRoleMismatch = "NEON_OWNER_ROLE_MISMATCH"
	// CodeNeonRoleExists: neon.roles.prepare names a role that already
	// exists and that this broker did not create; set adopt_existing_roles
	// to make it a rotation role anyway.
	CodeNeonRoleExists = "NEON_ROLE_EXISTS"
	// CodeNotCreatedByBroker: a delete names a Neon project, Vercel project
	// or Stripe endpoint this broker did not create (v1 deletes only its own).
	CodeNotCreatedByBroker = "NOT_CREATED_BY_BROKER"
	// CodeStripeOrphanEndpoint: previous_record is bound to an endpoint that
	// still exists (an earlier rotation did not finish). Rotating now would
	// overwrite a secret that may still be in use; the refusal names the
	// endpoint (orphan_endpoint_id) for cleanup.
	CodeStripeOrphanEndpoint = "STRIPE_ORPHAN_ENDPOINT"
)

// Rollback outcomes (Result.Rollback), set when a production release failed
// at or after its promote step.
const (
	// RollbackDone: a rollback was requested and production was then proven
	// to serve previous_deployment_id again (rolled_back is true).
	RollbackDone = "rolled_back"
	// RollbackNotNeeded: production was proven still to serve
	// previous_deployment_id, so no rollback was sent.
	RollbackNotNeeded = "not_needed"
	// RollbackFailed: production could not be proven to serve
	// previous_deployment_id (request refused, aliases unreadable, or the
	// operation was cancelled). Both credentials stay valid.
	RollbackFailed = "failed"
	// RollbackDrift: production serves a deployment this operation neither
	// read nor created; it was left alone.
	RollbackDrift = "drift"
)

// Result is an operation's value-free outcome: validated IDs, record names
// and revisions, env var names and health counts only.
type Result struct {
	TeamID            string            `json:"team_id,omitempty"`
	ProjectID         string            `json:"project_id,omitempty"`
	BranchID          string            `json:"branch_id,omitempty"`
	Role              string            `json:"role,omitempty"`
	Database          string            `json:"database,omitempty"`
	ActiveRole        string            `json:"active_role,omitempty"`
	InvalidatedRole   string            `json:"invalidated_role,omitempty"`
	PreparedRoles     []string          `json:"prepared_roles,omitempty"`
	DeploymentID      string            `json:"deployment_id,omitempty"`
	EndpointID        string            `json:"endpoint_id,omitempty"`
	DeletedEndpointID string            `json:"deleted_endpoint_id,omitempty"`
	Records           map[string]int64  `json:"records,omitempty"`
	Variables         map[string]string `json:"variables,omitempty"`
	Health            *HealthResult     `json:"health,omitempty"`
	Deleted           bool              `json:"deleted,omitempty"`
	// Production releases (production.go). PreviousDeploymentID is the
	// deployment that served production when the operation started (the
	// rollback target); Health is then the staged deployment's checks and
	// ProductionHealth the checks after production was proven to serve it.
	PreviousDeploymentID string        `json:"previous_deployment_id,omitempty"`
	Promoted             bool          `json:"promoted,omitempty"`
	ProductionVerified   bool          `json:"production_verified,omitempty"`
	ProductionHealth     *HealthResult `json:"production_health,omitempty"`
	RolledBack           bool          `json:"rolled_back,omitempty"`
	Rollback             string        `json:"rollback,omitempty"`
	// RevokedBindings names the records whose bindings a delete revoked
	// (the records stay in the vault).
	RevokedBindings []string `json:"revoked_bindings,omitempty"`
	// Redeployed lists every Vercel scope a rotation or redeploy rebuilt
	// and health-checked, in order.
	Redeployed []Redeployed `json:"redeployed,omitempty"`
	// Resumed: neon.rotate completed an interrupted rotation (no password
	// was reset; the stored URIs were deployed and the retiring role
	// invalidated).
	Resumed bool `json:"resumed,omitempty"`
	// ForgottenDeployments names the records whose deployed_to entries a
	// vercel.project.delete removed.
	ForgottenDeployments []string `json:"forgotten_deployments,omitempty"`
	// OrphanEndpointID is set only on a STRIPE_ORPHAN_ENDPOINT refusal: the
	// endpoint previous_record is bound to, which still exists.
	OrphanEndpointID string `json:"orphan_endpoint_id,omitempty"`
}

// Redeployed is one rebuilt Vercel scope.
type Redeployed struct {
	DeployTarget
	DeploymentID string        `json:"deployment_id"`
	Health       *HealthResult `json:"health,omitempty"`
}

// HealthResult summarizes the passed health checks.
type HealthResult struct {
	Checks        int `json:"checks"`
	WindowSeconds int `json:"window_s"`
}

func (r Result) clone() Result {
	c := r
	if r.Records != nil {
		c.Records = make(map[string]int64, len(r.Records))
		for k, v := range r.Records {
			c.Records[k] = v
		}
	}
	if r.Variables != nil {
		c.Variables = make(map[string]string, len(r.Variables))
		for k, v := range r.Variables {
			c.Variables[k] = v
		}
	}
	if r.PreparedRoles != nil {
		c.PreparedRoles = append([]string(nil), r.PreparedRoles...)
	}
	if r.RevokedBindings != nil {
		c.RevokedBindings = append([]string(nil), r.RevokedBindings...)
	}
	if r.ForgottenDeployments != nil {
		c.ForgottenDeployments = append([]string(nil), r.ForgottenDeployments...)
	}
	if r.Redeployed != nil {
		c.Redeployed = make([]Redeployed, len(r.Redeployed))
		for i, d := range r.Redeployed {
			c.Redeployed[i] = d
			if d.Health != nil {
				h := *d.Health
				c.Redeployed[i].Health = &h
			}
		}
	}
	if r.Health != nil {
		h := *r.Health
		c.Health = &h
	}
	if r.ProductionHealth != nil {
		h := *r.ProductionHealth
		c.ProductionHealth = &h
	}
	return c
}

func (r *Result) record(name string, rev int64) {
	if r.Records == nil {
		r.Records = map[string]int64{}
	}
	r.Records[name] = rev
}

// plan is one validated action.
type plan interface {
	// summary is the deterministic, authoritative description for the Touch
	// ID prompt, built only from validated params.
	summary() string
	// controls are the control-credential records the action needs.
	controls() []string
	// precheck refuses, before any prompt, what cannot succeed (code "" ok).
	precheck(ctx context.Context, v Vault) string
	// resources are the lock keys of what the action changes (locks.go).
	resources(ctx context.Context, v Vault) []string
	execute(r *run) error
}

type parser func(json.RawMessage) (plan, bool)

func parse[T any, P interface {
	*T
	validate() bool
	plan
}](raw json.RawMessage) (plan, bool) {
	p := P(new(T))
	if decodeStrict(raw, p) != nil || !p.validate() {
		return nil, false
	}
	return p, true
}

var registry = map[string]parser{
	ActionNeonProjectCreate:   parse[neonProjectCreate],
	ActionNeonProjectDelete:   parse[neonProjectDelete],
	ActionNeonRotate:          parse[neonRotate],
	ActionNeonRolesPrepare:    parse[neonRolesPrepare],
	ActionVercelProjectCreate: parse[vercelProjectCreate],
	ActionVercelProjectDelete: parse[vercelProjectDelete],
	ActionVercelEnvPush:       parse[vercelEnvPush],
	ActionVercelRedeploy:      parse[vercelRedeploy],
	ActionStripeWebhookCreate: parse[stripeWebhookCreate],
	ActionStripeWebhookRotate: parse[stripeWebhookRotate],
	ActionStripeWebhookDelete: parse[stripeWebhookDelete],
	ActionBindingAllow:        parse[bindingAllow],
}

// ValidAction reports whether id is a v1 action.
func ValidAction(id string) bool { _, ok := registry[id]; return ok }

// Actions lists every v1 action ID, sorted.
func Actions() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Parse validates params for action strictly and returns its plan text.
// It is exported for tests and the gate's own checks; Service.Prepare is the
// path that can start an operation.
func Parse(action string, params json.RawMessage) (summary string, ok bool) {
	p, ok := parsePlan(action, params)
	if !ok {
		return "", false
	}
	return p.summary(), true
}

func parsePlan(action string, params json.RawMessage) (plan, bool) {
	f, ok := registry[action]
	if !ok {
		return nil, false
	}
	return f(params)
}

// ---- shared prechecks ----

func mustNotExist(ctx context.Context, v Vault, names ...string) string {
	for _, n := range names {
		ok, err := v.Exists(ctx, n)
		if err != nil {
			return agentbroker.CodeVaultFailed
		}
		if ok {
			return CodeRecordExists
		}
	}
	return ""
}

func mustExist(ctx context.Context, v Vault, names ...string) string {
	for _, n := range names {
		ok, err := v.Exists(ctx, n)
		if err != nil {
			return agentbroker.CodeVaultFailed
		}
		if !ok {
			return agentbroker.CodeUnknownSecret
		}
	}
	return ""
}

func noCheck(context.Context, Vault) string { return "" }

// ---- shared steps ----

// push writes each env var from the exact record revision stored earlier in
// this operation (r.res.Records): the destination never sees a value the
// vault does not durably hold.
func (r *run) push(env VercelEnv, vars map[string]string) error {
	names := make([]string, 0, len(vars))
	for n := range vars {
		names = append(names, n)
	}
	sort.Strings(names)
	return r.step(StepVercelEnvPush, CodeProviderFailed, func() error {
		for _, name := range names {
			rec := vars[name]
			rev, ok := r.res.Records[rec]
			if !ok || rev < 1 {
				return fail(agentbroker.CodeVaultFailed)
			}
			src, err := lifecycle.NewSecretSource(r.vault, rec, rev)
			if err != nil {
				return fail(agentbroker.CodeVaultFailed)
			}
			if err := r.vercel.UpsertSensitiveEnv(r.ctx, env, name, src); err != nil {
				return err
			}
			if r.res.Variables == nil {
				r.res.Variables = map[string]string{}
			}
			r.res.Variables[name] = "upserted"
		}
		return nil
	})
}

// redeployAndCheck redeploys and checks health. For production it is the
// whole release (production.go): staged redeploy from the source (default:
// the deployment productionBaseline read), health on the staged deployment,
// promote, proof that production serves it, health again and a final proof;
// a failure at or after the promote rolls production back.
func (r *run) redeployAndCheck(ref VercelRef, healthPath string) error {
	production := ref.Target == TargetProduction
	source := ref.Deployment
	if production {
		if r.prod == nil {
			return &failure{step: StepVercelCurrent, code: CodeProviderFailed}
		}
		if source == "" {
			source = r.prod.previous
		}
	} else if source == "" {
		if err := r.step(StepVercelCurrent, CodeProviderFailed, func() error {
			// Branch-scoped preview: the newest deployment of that branch,
			// proven by the port.
			id, err := r.vercel.CurrentDeployment(r.ctx, ref.env())
			if err != nil {
				return err
			}
			if !vercelDeploymentRe.MatchString(id) {
				return fail(CodeProviderResponse)
			}
			source = id
			return nil
		}); err != nil {
			return err
		}
	}
	var deployment, deploymentURL string
	if err := r.step(StepVercelRedeploy, CodeProviderFailed, func() error {
		id, err := r.vercel.Redeploy(r.ctx, ref.env(), source)
		if err != nil {
			return err
		}
		if !vercelDeploymentRe.MatchString(id) || id == source || (production && id == r.prod.previous) {
			return fail(CodeProviderResponse)
		}
		deployment, r.res.DeploymentID = id, id
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepVercelWaitReady, CodeProviderFailed, func() error {
		u, err := r.vercel.WaitReady(r.ctx, ref.TeamID, deployment)
		if err != nil {
			return err
		}
		if !validHTTPSURL(u) {
			return fail(CodeProviderResponse)
		}
		deploymentURL = u
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepHealth, CodeHealthFailed, func() error { return r.checkHealth(deploymentURL, healthPath, &r.res.Health) }); err != nil {
		return err
	}
	done := Redeployed{DeployTarget: ref.deployTarget(), DeploymentID: deployment}
	if production {
		if err := r.promoteAndVerify(ref, deployment, deploymentURL, healthPath); err != nil {
			return err
		}
		done.Health = r.res.ProductionHealth
	} else {
		done.Health = r.res.Health
	}
	if done.Health != nil {
		h := *done.Health
		done.Health = &h
	}
	r.res.Redeployed = append(r.res.Redeployed, done)
	return nil
}
