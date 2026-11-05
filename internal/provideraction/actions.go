package provideraction

import (
	"context"
	"encoding/json"
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
)

// Result is an operation's value-free outcome: validated IDs, record names
// and revisions, env var names and health counts only.
type Result struct {
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
		", and store " + roles[0] + "'s connection URIs in new records " + p.Records.Pooled + " (pooled) and " + p.Records.Direct + " (direct)"
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
	return nil
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
	return "DELETE Neon project " + p.ProjectID + " and all its data"
}
func (p *neonProjectDelete) controls() []string                           { return []string{ControlNeon} }
func (p *neonProjectDelete) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *neonProjectDelete) execute(r *run) error {
	err := r.step(StepNeonDeleteProject, CodeProviderFailed, func() error { return r.neon.DeleteProject(r.ctx, p.ProjectID) })
	r.res.Deleted = err == nil
	return err
}

// ---- neon.rotate ----

func (p *neonRotate) summary() string {
	old, next := p.Roles[0], p.Roles[1]
	return "ROTATE Neon role " + next + " to active in project " + p.ProjectID + " branch " + p.BranchID + " database " + p.Database +
		" (rotation roles checked as owner role " + p.OwnerRole + "): reset its password, store its URIs in " + p.Records.Pooled + ", " + p.Records.Direct + ", push them to " + p.Vercel.text() +
		", redeploy" + fromDeployment(p.Vercel.Deployment) + ", check health at " + p.HealthPath + ", then invalidate role " + old
}
func (p *neonRotate) controls() []string                           { return []string{ControlNeon, ControlVercel} }
func (p *neonRotate) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }

// execute is the zero-downtime dual-role rotation. The role the deployment
// uses (Roles[0]) keeps working until the new role's URIs are stored,
// pushed, deployed and healthy; only then is its password reset.
func (p *neonRotate) execute(r *run) error {
	old, next := p.Roles[0], p.Roles[1]
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
	return s
}
func (p *vercelProjectCreate) controls() []string                           { return []string{ControlVercel} }
func (p *vercelProjectCreate) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *vercelProjectCreate) execute(r *run) error {
	return r.step(StepVercelCreateProject, CodeProviderFailed, func() error {
		id, err := r.vercel.CreateProject(r.ctx, p.TeamID, p.Name, p.GitRepo, p.Framework)
		if err != nil {
			return err
		}
		if !vercelProjectRe.MatchString(id) {
			return fail(CodeProviderResponse)
		}
		r.res.ProjectID = id
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
func (p *vercelEnvPush) precheck(ctx context.Context, v Vault) string {
	var recs []string
	for _, env := range p.envNames() {
		recs = append(recs, p.Variables[env])
	}
	return mustExist(ctx, v, recs...)
}
func (p *vercelEnvPush) execute(r *run) error {
	if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
		for _, env := range p.envNames() {
			rec := p.Variables[env]
			rev, err := r.vault.Latest(r.ctx, rec, func([]byte) error { return nil })
			if err != nil || rev < 1 {
				return fail(agentbroker.CodeVaultFailed)
			}
			r.res.record(rec, rev)
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
		strings.Join(p.Events, ", ") + " and store its signing secret in new record " + p.Record
}
func (p *stripeWebhookCreate) controls() []string { return []string{ControlStripe} }
func (p *stripeWebhookCreate) precheck(ctx context.Context, v Vault) string {
	return mustNotExist(ctx, v, p.Record)
}
func (p *stripeWebhookCreate) execute(r *run) error {
	return r.step(StepStripeCreate, CodeProviderFailed, func() error {
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
	})
}

func (p *stripeWebhookDelete) summary() string {
	return "DELETE Stripe webhook endpoint " + p.EndpointID
}
func (p *stripeWebhookDelete) controls() []string                           { return []string{ControlStripe} }
func (p *stripeWebhookDelete) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *stripeWebhookDelete) execute(r *run) error {
	err := r.step(StepStripeDelete, CodeProviderFailed, func() error { return r.stripe.DeleteWebhook(r.ctx, p.EndpointID) })
	r.res.Deleted = err == nil
	return err
}

// ---- stripe.webhook.rotate ----

func (p *stripeWebhookRotate) summary() string {
	return "ROTATE Stripe webhook " + p.EndpointID + ": create a new endpoint with the same URL and events, copy record " + p.Record +
		" to " + p.PreviousRecord + ", store the new signing secret in " + p.Record + ", push both to " + p.Vercel.text() +
		", redeploy" + fromDeployment(p.Vercel.Deployment) + ", check health at " + p.HealthPath + ", then delete " + p.EndpointID
}
func (p *stripeWebhookRotate) controls() []string { return []string{ControlStripe, ControlVercel} }
func (p *stripeWebhookRotate) precheck(ctx context.Context, v Vault) string {
	return mustExist(ctx, v, p.Record)
}

// execute keeps the old endpoint (and its secret, now also in
// PreviousRecord) valid until the new secret is stored, pushed, deployed
// and healthy; only then is the old endpoint deleted.
func (p *stripeWebhookRotate) execute(r *run) error {
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
		if _, err := r.vault.Latest(r.ctx, p.Record, func(v []byte) error {
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
		return nil
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
