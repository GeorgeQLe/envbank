package provideraction

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

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
	StepStripeReadEndpoint  = "stripe.read_endpoint"
	StepStripeCreate        = "stripe.create_endpoint"
	StepStripeDeleteOld     = "stripe.delete_old_endpoint"
	StepStripeDelete        = "stripe.delete_endpoint"
	StepBindingCheck        = "vault.check_bindings"
	StepBindingSave         = "vault.save_bindings"
	StepBindingRevoke       = "vault.revoke_bindings"
	StepBindingAllow        = "vault.allow_destination"
	StepProvenanceSave      = "vault.save_provenance"
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
	// RevokedBindings names the records whose bindings a delete revoked
	// (the records stay in the vault).
	RevokedBindings []string `json:"revoked_bindings,omitempty"`
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
	if r.Health != nil {
		h := *r.Health
		c.Health = &h
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

// ---- neon.project.create ----

func (p *neonProjectCreate) roles() [2]string { r, _ := rotationRoles(p.Roles, ""); return r }

func (p *neonProjectCreate) summary() string {
	roles := p.roles()
	s := "CREATE Neon project " + p.Name
	if p.RegionID != "" {
		s += " in region " + p.RegionID
	}
	if p.PGVersion != 0 {
		s += " (Postgres " + strconv.Itoa(p.PGVersion) + ")"
	}
	return s + ", prepare rotation roles " + roles[0] + ", " + roles[1] + " under group role " + NeonGroupRole +
		", and store " + roles[0] + "'s connection URIs in new records " + p.Records.Pooled + " (pooled) and " + p.Records.Direct + " (direct)" +
		", bound to the new project with no deploy destination"
}
func (p *neonProjectCreate) controls() []string { return []string{ControlNeon} }
func (p *neonProjectCreate) precheck(ctx context.Context, v Vault) string {
	return mustNotExist(ctx, v, p.Records.Pooled, p.Records.Direct)
}

// execute creates the project, prepares the rotation roles as the owner
// role, then stores the first rotation role's URIs. The owner URIs the
// adapter returns on create go to discarding sinks and are never stored. A
// failure after create leaves project_id in the result for cleanup.
func (p *neonProjectCreate) execute(r *run) error {
	roles := p.roles()
	var info NeonProject
	if err := r.step(StepNeonCreateProject, CodeProviderFailed, func() error {
		var err error
		info, err = r.neon.CreateProject(r.ctx, NeonProjectSpec{Name: p.Name, RegionID: p.RegionID, PGVersion: p.PGVersion}, discardSink(), discardSink())
		if neonProjectRe.MatchString(info.ProjectID) {
			r.res.ProjectID = info.ProjectID // reported even on a later failure, for cleanup
		}
		if err != nil {
			return err
		}
		if !neonProjectRe.MatchString(info.ProjectID) || !neonBranchRe.MatchString(info.BranchID) || !pgIdentRe.MatchString(info.Role) || !pgIdentRe.MatchString(info.Database) {
			return fail(CodeProviderResponse)
		}
		// The app records must never hold the owner's credentials.
		for _, role := range roles {
			if strings.EqualFold(role, info.Role) {
				return fail(CodeProviderResponse)
			}
		}
		r.res.BranchID, r.res.Role, r.res.Database = info.BranchID, info.Role, info.Database
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepNeonPrepareRoles, CodeProviderFailed, func() error {
		if err := r.neon.PrepareRotationRoles(r.ctx, info.ProjectID, info.BranchID, info.Database, info.Role, roles, false); err != nil {
			return err
		}
		r.res.PreparedRoles = []string{roles[0], roles[1]}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepNeonResetActive, CodeProviderFailed, func() error {
		w := r.recorder()
		if err := r.neon.ResetRolePassword(r.ctx, info.ProjectID, info.BranchID, roles[0], info.Database, w.sink(p.Records.Pooled), w.sink(p.Records.Direct)); err != nil {
			return err
		}
		return w.require(r.res, p.Records.Pooled, p.Records.Direct)
	}); err != nil {
		return err
	}
	r.res.ActiveRole = roles[0]
	return r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		res := BindingResource{ProjectID: info.ProjectID, BranchID: info.BranchID}
		if err := replaceBinding(r.ctx, r.vault, newBinding(p.Records.Pooled, ProviderNeon, KindNeonPooled, res, r.res.Records[p.Records.Pooled])); err != nil {
			return err
		}
		return replaceBinding(r.ctx, r.vault, newBinding(p.Records.Direct, ProviderNeon, KindNeonDirect, res, r.res.Records[p.Records.Direct]))
	})
}

// ---- neon.roles.prepare ----

func (p *neonRolesPrepare) roles() [2]string { r, _ := rotationRoles(p.Roles, p.OwnerRole); return r }

func (p *neonRolesPrepare) summary() string {
	roles := p.roles()
	s := "PREPARE Neon rotation roles " + roles[0] + ", " + roles[1] + " in project " + p.ProjectID + " branch " + p.BranchID + " database " + p.Database +
		", connected as owner role " + p.OwnerRole + ": create them and no-login group role " + NeonGroupRole +
		" if missing, make both members acting as it, and transfer ownership of the public schema to it"
	if p.Adopt {
		return s + ", and CHANGE OWNERSHIP of all existing public-schema objects to " + NeonGroupRole
	}
	return s + " (existing public-schema objects keep their owners)"
}
func (p *neonRolesPrepare) controls() []string                           { return []string{ControlNeon} }
func (p *neonRolesPrepare) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *neonRolesPrepare) execute(r *run) error {
	roles := p.roles()
	return r.step(StepNeonPrepareRoles, CodeProviderFailed, func() error {
		if err := r.neon.PrepareRotationRoles(r.ctx, p.ProjectID, p.BranchID, p.Database, p.OwnerRole, roles, p.Adopt); err != nil {
			return err
		}
		r.res.PreparedRoles = []string{roles[0], roles[1]}
		return nil
	})
}

// ---- neon.project.delete ----

func (p *neonProjectDelete) summary() string {
	return "DELETE Neon project " + p.ProjectID + " and all its data, and revoke the bindings of its records (the records stay in the vault)"
}
func (p *neonProjectDelete) controls() []string                           { return []string{ControlNeon} }
func (p *neonProjectDelete) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *neonProjectDelete) execute(r *run) error {
	err := r.step(StepNeonDeleteProject, CodeProviderFailed, func() error { return r.neon.DeleteProject(r.ctx, p.ProjectID) })
	r.res.Deleted = err == nil
	if err != nil {
		return err
	}
	return r.step(StepBindingRevoke, agentbroker.CodeVaultFailed, func() error {
		names, err := revokeBindings(r.ctx, r.vault, func(b Binding) bool {
			return b.Provider == ProviderNeon && b.Resource.ProjectID == p.ProjectID
		})
		r.res.RevokedBindings = names
		return err
	})
}

// ---- neon.rotate ----

func (p *neonRotate) summary() string {
	old, next := p.Roles[0], p.Roles[1]
	return "ROTATE Neon role " + next + " to active in project " + p.ProjectID + " branch " + p.BranchID + " database " + p.Database +
		" (rotation roles checked as owner role " + p.OwnerRole + "): reset its password, store its URIs in bound records " + p.Records.Pooled + ", " + p.Records.Direct + ", push them to " + p.Vercel.text() +
		", redeploy" + fromDeployment(p.Vercel.Deployment) + ", check health at " + p.HealthPath + ", then invalidate role " + old
}
func (p *neonRotate) controls() []string { return []string{ControlNeon, ControlVercel} }

// check: both records are bound to this exact project and branch with the
// matching kinds, and may be deployed to the target project.
func (p *neonRotate) check(ctx context.Context, v Vault) (pooled, direct bound, code string) {
	if pooled, code = boundToNeon(ctx, v, p.Records.Pooled, KindNeonPooled, p.ProjectID, p.BranchID); code != "" {
		return
	}
	if direct, code = boundToNeon(ctx, v, p.Records.Direct, KindNeonDirect, p.ProjectID, p.BranchID); code != "" {
		return
	}
	if _, code = boundForPush(ctx, v, p.Vercel.dest(), p.Records.Pooled, p.Records.Direct); code != "" {
		return
	}
	return pooled, direct, ""
}
func (p *neonRotate) precheck(ctx context.Context, v Vault) string {
	_, _, code := p.check(ctx, v)
	return code
}

// execute is the zero-downtime dual-role rotation. The role the deployment
// uses (Roles[0]) keeps working until the new role's URIs are stored,
// pushed, deployed and healthy; only then is its password reset.
func (p *neonRotate) execute(r *run) error {
	old, next := p.Roles[0], p.Roles[1]
	var pooled, direct bound
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if pooled, direct, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
	// Read-only: both roles must already act as the group owner, or the new
	// role could not use the old role's tables. Not ready fails with no
	// side effects.
	if err := r.step(StepNeonCheckRoles, CodeProviderFailed, func() error {
		ready, err := r.neon.RotationRolesReady(r.ctx, p.ProjectID, p.BranchID, p.Database, p.OwnerRole, [2]string{old, next})
		if err != nil {
			return err
		}
		if !ready {
			return fail(CodeRolesNotPrepared)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepNeonResetNewRole, CodeProviderFailed, func() error {
		w := r.recorder()
		if err := r.neon.ResetRolePassword(r.ctx, p.ProjectID, p.BranchID, next, p.Database, w.sink(p.Records.Pooled), w.sink(p.Records.Direct)); err != nil {
			return err
		}
		return w.require(r.res, p.Records.Pooled, p.Records.Direct) // stored durably before any destination is written
	}); err != nil {
		return err
	}
	// The bindings follow the new values (same project, same destinations).
	if err := r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		for _, lb := range []bound{pooled, direct} {
			b := lb.b.clone()
			b.RecordRevision = r.res.Records[b.Record]
			if err := saveBinding(r.ctx, r.vault, b, lb.objRev); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.push(p.Vercel.env(), map[string]string{p.Records.Pooled: p.Records.Pooled, p.Records.Direct: p.Records.Direct}); err != nil {
		return err
	}
	if err := r.redeployAndCheck(p.Vercel, p.HealthPath); err != nil {
		return err
	}
	r.res.ActiveRole = next
	// Only after health passed: the old role's password is reset and discarded.
	if err := r.step(StepNeonInvalidateOld, CodeProviderFailed, func() error {
		return r.neon.ResetRolePassword(r.ctx, p.ProjectID, p.BranchID, old, p.Database, nil, nil)
	}); err != nil {
		return err
	}
	r.res.InvalidatedRole = old
	return nil
}

func fromDeployment(d string) string {
	if d == "" {
		return " from the current deployment"
	}
	return " from " + d
}

// ---- vercel.project.create / delete ----

func (p *vercelProjectCreate) summary() string {
	s := "CREATE Vercel project " + p.Name + " in " + p.TeamID
	if p.GitRepo != "" {
		s += " linked to git repo " + p.GitRepo
	}
	if p.Framework != "" {
		s += " (framework " + p.Framework + ")"
	}
	return s + " (no vault record may be deployed to it until binding.allow)"
}
func (p *vercelProjectCreate) controls() []string                           { return []string{ControlVercel} }
func (p *vercelProjectCreate) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *vercelProjectCreate) execute(r *run) error {
	if err := r.step(StepVercelCreateProject, CodeProviderFailed, func() error {
		id, err := r.vercel.CreateProject(r.ctx, p.TeamID, p.Name, p.GitRepo, p.Framework)
		if err != nil {
			return err
		}
		if !vercelProjectRe.MatchString(id) {
			return fail(CodeProviderResponse)
		}
		r.res.TeamID, r.res.ProjectID = p.TeamID, id
		return nil
	}); err != nil {
		return err
	}
	// Provenance only: it allows no record to be deployed there.
	return r.step(StepProvenanceSave, agentbroker.CodeVaultFailed, func() error {
		if err := r.vault.SaveVercelProject(r.ctx, VercelProject{V: BindingVersion, TeamID: p.TeamID, ProjectID: r.res.ProjectID, Name: p.Name}); err != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
		return nil
	})
}

func (p *vercelProjectDelete) summary() string {
	return "DELETE Vercel project " + p.ProjectID + " in " + p.TeamID + " with its deployments and env vars"
}
func (p *vercelProjectDelete) controls() []string                           { return []string{ControlVercel} }
func (p *vercelProjectDelete) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *vercelProjectDelete) execute(r *run) error {
	err := r.step(StepVercelDeleteProject, CodeProviderFailed, func() error { return r.vercel.DeleteProject(r.ctx, p.TeamID, p.ProjectID) })
	r.res.Deleted = err == nil
	return err
}

// ---- vercel.env.push ----

func (p *vercelEnvPush) summary() string {
	var parts []string
	for _, env := range p.envNames() {
		parts = append(parts, env+" from record "+p.Variables[env])
	}
	return "PUSH vault records to " + p.ref().text() + " as sensitive env vars: " + strings.Join(parts, ", ")
}
func (p *vercelEnvPush) controls() []string { return []string{ControlVercel} }
func (p *vercelEnvPush) recordNames() []string {
	var recs []string
	for _, env := range p.envNames() {
		recs = append(recs, p.Variables[env])
	}
	return recs
}

// precheck: every record exists, has a live binding, and may be deployed
// to this project. Unbound records (owner-entered secrets) are never pushed.
func (p *vercelEnvPush) precheck(ctx context.Context, v Vault) string {
	if code := mustExist(ctx, v, p.recordNames()...); code != "" {
		return code
	}
	_, code := boundForPush(ctx, v, p.ref().dest(), p.recordNames()...)
	return code
}
func (p *vercelEnvPush) execute(r *run) error {
	if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
		checked, code := boundForPush(r.ctx, r.vault, p.ref().dest(), p.recordNames()...)
		if code != "" {
			return fail(code)
		}
		// Each push reads exactly the bound revision.
		for rec, lb := range checked {
			r.res.record(rec, lb.b.RecordRevision)
		}
		return nil
	}); err != nil {
		return err
	}
	return r.push(p.ref().env(), p.Variables)
}

// ---- vercel.redeploy ----

func (p *vercelRedeploy) healthPath() string {
	if p.HealthPath == "" {
		return "/"
	}
	return p.HealthPath
}
func (p *vercelRedeploy) summary() string {
	return "REDEPLOY " + p.ref().text() + fromDeployment(p.Deployment) + ", then check health at " + p.healthPath()
}
func (p *vercelRedeploy) controls() []string                           { return []string{ControlVercel} }
func (p *vercelRedeploy) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *vercelRedeploy) execute(r *run) error {
	return r.redeployAndCheck(p.ref(), p.healthPath())
}

// ---- stripe.webhook.create / delete ----

func (p *stripeWebhookCreate) summary() string {
	return "CREATE Stripe test-mode webhook endpoint for " + p.URL + " with " + strconv.Itoa(len(p.Events)) + " event(s) " +
		strings.Join(p.Events, ", ") + " and store its signing secret in new record " + p.Record + ", bound to the new endpoint with no deploy destination"
}
func (p *stripeWebhookCreate) controls() []string { return []string{ControlStripe} }
func (p *stripeWebhookCreate) precheck(ctx context.Context, v Vault) string {
	return mustNotExist(ctx, v, p.Record)
}
func (p *stripeWebhookCreate) execute(r *run) error {
	if err := r.step(StepStripeCreate, CodeProviderFailed, func() error {
		w := r.recorder()
		id, err := r.stripe.CreateWebhook(r.ctx, p.URL, append([]string(nil), p.Events...), w.sink(p.Record))
		if stripeEndpointRe.MatchString(id) {
			r.res.EndpointID = id // reported even on a later failure, for cleanup
		}
		if err != nil {
			return err
		}
		if !stripeEndpointRe.MatchString(id) {
			return fail(CodeProviderResponse)
		}
		return w.require(r.res, p.Record)
	}); err != nil {
		return err
	}
	return r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		id := r.res.EndpointID
		return replaceBinding(r.ctx, r.vault, newBinding(p.Record, ProviderStripe, KindStripeWebhookSecret, BindingResource{EndpointID: id, Lineage: id}, r.res.Records[p.Record]))
	})
}

func (p *stripeWebhookDelete) summary() string {
	return "DELETE Stripe webhook endpoint " + p.EndpointID + ", and revoke the bindings of its records (the records stay in the vault)"
}
func (p *stripeWebhookDelete) controls() []string                           { return []string{ControlStripe} }
func (p *stripeWebhookDelete) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *stripeWebhookDelete) execute(r *run) error {
	err := r.step(StepStripeDelete, CodeProviderFailed, func() error { return r.stripe.DeleteWebhook(r.ctx, p.EndpointID) })
	r.res.Deleted = err == nil
	if err != nil {
		return err
	}
	// The endpoint's bindings are revoked; deleting a lineage's current
	// endpoint also revokes the rest of that lineage (previous_record).
	return r.step(StepBindingRevoke, agentbroker.CodeVaultFailed, func() error {
		all, err := r.vault.ListBindings(r.ctx)
		if err != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
		ended := map[string]bool{}
		for _, sb := range all {
			b := sb.Binding
			if !b.Revoked && b.Provider == ProviderStripe && b.Kind == KindStripeWebhookSecret && b.Resource.EndpointID == p.EndpointID {
				ended[b.Resource.Lineage] = true
			}
		}
		names, err := revokeBindings(r.ctx, r.vault, func(b Binding) bool {
			return b.Provider == ProviderStripe && (b.Resource.EndpointID == p.EndpointID || ended[b.Resource.Lineage])
		})
		r.res.RevokedBindings = names
		return err
	})
}

// ---- stripe.webhook.rotate ----

func (p *stripeWebhookRotate) summary() string {
	return "ROTATE Stripe webhook " + p.EndpointID + ": create a new endpoint with the same URL and events, copy bound record " + p.Record +
		" to " + p.PreviousRecord + " (bound as previous), store the new signing secret in " + p.Record + ", push both to " + p.Vercel.text() +
		", redeploy" + fromDeployment(p.Vercel.Deployment) + ", check health at " + p.HealthPath + ", then delete " + p.EndpointID
}
func (p *stripeWebhookRotate) controls() []string { return []string{ControlStripe, ControlVercel} }

// stripeChecked is a rotation's checked bindings. prevRev is the object
// revision of previous_record's binding (0 when none); prevAbsent means
// previous_record does not exist yet and will be created and bound.
type stripeChecked struct {
	cur        bound
	prevRev    int64
	prevAbsent bool
}

// check: record is bound to this endpoint (its lineage's current one) and
// may be deployed to the target; previous_record is either absent or bound
// as the previous secret of the same lineage.
func (p *stripeWebhookRotate) check(ctx context.Context, v Vault) (stripeChecked, string) {
	var c stripeChecked
	if code := mustExist(ctx, v, p.Record); code != "" {
		return c, code
	}
	cur, code := liveBinding(ctx, v, p.Record)
	if code != "" {
		return c, code
	}
	if cur.b.Provider != ProviderStripe || cur.b.Kind != KindStripeWebhookSecret || cur.b.Resource.EndpointID != p.EndpointID {
		return c, CodeBindingMismatch
	}
	if !cur.b.allows(p.Vercel.dest()) {
		return c, CodeDestinationNotAllowed
	}
	c.cur = cur
	exists, err := v.Exists(ctx, p.PreviousRecord)
	if err != nil {
		return c, agentbroker.CodeVaultFailed
	}
	if !exists {
		c.prevAbsent = true
		_, rev, err := v.LoadBinding(ctx, p.PreviousRecord)
		switch {
		case errors.Is(err, ErrMissing):
		case err != nil:
			return c, agentbroker.CodeVaultFailed
		default:
			c.prevRev = rev // a stale object for an absent record is replaced
		}
		return c, ""
	}
	prev, code := liveBinding(ctx, v, p.PreviousRecord)
	if code != "" {
		return c, code
	}
	if prev.b.Provider != ProviderStripe || prev.b.Kind != KindStripeWebhookSecretPrevious || prev.b.Resource.Lineage != cur.b.Resource.Lineage {
		return c, CodeBindingMismatch
	}
	c.prevRev = prev.objRev
	return c, ""
}
func (p *stripeWebhookRotate) precheck(ctx context.Context, v Vault) string {
	_, code := p.check(ctx, v)
	return code
}

// execute keeps the old endpoint (and its secret, now also in
// PreviousRecord) valid until the new secret is stored, pushed, deployed
// and healthy; only then is the old endpoint deleted.
func (p *stripeWebhookRotate) execute(r *run) error {
	var checked stripeChecked
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if checked, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
	cur := checked.cur.b
	var hook StripeWebhook
	if err := r.step(StepStripeReadEndpoint, CodeProviderFailed, func() error {
		var err error
		if hook, err = r.stripe.Webhook(r.ctx, p.EndpointID); err != nil {
			return err
		}
		if !validHTTPSURL(hook.URL) || !validEvents(hook.Events) {
			return fail(CodeProviderResponse)
		}
		return nil
	}); err != nil {
		return err
	}
	// The current secret is copied to PreviousRecord before the new one is
	// stored over it, so the vault never loses the secret in use.
	if err := r.step(StepVaultMoveCurrent, agentbroker.CodeVaultFailed, func() error {
		var current []byte
		defer func() { wipe(current) }()
		// Exactly the bound revision: anything else was not checked.
		if err := r.vault.ReadSecret(r.ctx, p.Record, cur.RecordRevision, func(v []byte) error {
			current = append([]byte(nil), v...)
			return nil
		}); err != nil || len(current) == 0 {
			return fail(agentbroker.CodeVaultFailed)
		}
		rev, err := r.vault.StoreSecret(r.ctx, p.PreviousRecord, func(consume func([]byte) error) error {
			view := append([]byte(nil), current...)
			defer wipe(view)
			return consume(view)
		})
		if err != nil || rev < 1 {
			return fail(agentbroker.CodeVaultFailed)
		}
		r.res.record(p.PreviousRecord, rev)
		// previous_record holds the value record held, so it inherits its
		// lineage and allowed destinations.
		prev := cur.clone()
		prev.Record, prev.Kind, prev.RecordRevision, prev.Revoked = p.PreviousRecord, KindStripeWebhookSecretPrevious, rev, false
		return saveBinding(r.ctx, r.vault, prev, checked.prevRev)
	}); err != nil {
		return err
	}
	if err := r.step(StepStripeCreate, CodeProviderFailed, func() error {
		w := r.recorder()
		id, err := r.stripe.CreateWebhook(r.ctx, hook.URL, append([]string(nil), hook.Events...), w.sink(p.Record))
		if stripeEndpointRe.MatchString(id) {
			r.res.EndpointID = id
		}
		if err != nil {
			return err
		}
		if !stripeEndpointRe.MatchString(id) || id == p.EndpointID {
			return fail(CodeProviderResponse)
		}
		return w.require(r.res, p.Record)
	}); err != nil {
		return err
	}
	// The record's binding moves to the new endpoint (same lineage).
	if err := r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		b := cur.clone()
		b.Resource.EndpointID, b.RecordRevision = r.res.EndpointID, r.res.Records[p.Record]
		return saveBinding(r.ctx, r.vault, b, checked.cur.objRev)
	}); err != nil {
		return err
	}
	if err := r.push(p.Vercel.env(), map[string]string{p.Record: p.Record, p.PreviousRecord: p.PreviousRecord}); err != nil {
		return err
	}
	if err := r.redeployAndCheck(p.Vercel, p.HealthPath); err != nil {
		return err
	}
	if err := r.step(StepStripeDeleteOld, CodeProviderFailed, func() error {
		return r.stripe.DeleteWebhook(r.ctx, p.EndpointID)
	}); err != nil {
		return err
	}
	r.res.DeletedEndpointID = p.EndpointID
	return nil
}

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

func (r *run) redeployAndCheck(ref VercelRef, healthPath string) error {
	source := ref.Deployment
	if source == "" {
		if err := r.step(StepVercelCurrent, CodeProviderFailed, func() error {
			id, err := r.vercel.CurrentDeployment(r.ctx, ref.TeamID, ref.ProjectID, ref.Target)
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
		id, err := r.vercel.Redeploy(r.ctx, ref.TeamID, ref.ProjectID, ref.Target, source)
		if err != nil {
			return err
		}
		if !vercelDeploymentRe.MatchString(id) || id == source {
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
	return r.step(StepHealth, CodeHealthFailed, func() error { return r.checkHealth(deploymentURL, healthPath) })
}
