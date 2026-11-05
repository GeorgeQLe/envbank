package provideraction

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

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
	what := "Vercel project " + p.ProjectID + " in " + p.TeamID
	if p.name != "" {
		what = "Vercel project " + p.name + " (" + p.ProjectID + ") in " + p.TeamID + ", created by this broker,"
	}
	return "DELETE " + what + " with its deployments and env vars"
}
func (p *vercelProjectDelete) controls() []string { return []string{ControlVercel} }

// precheck: v1 deletes only projects this broker created.
func (p *vercelProjectDelete) precheck(ctx context.Context, v Vault) string {
	prov, err := v.LoadVercelProject(ctx, p.TeamID, p.ProjectID)
	switch {
	case errors.Is(err, ErrMissing):
		return CodeNotCreatedByBroker
	case err != nil || prov.TeamID != p.TeamID || prov.ProjectID != p.ProjectID:
		return agentbroker.CodeVaultFailed
	}
	p.name = prov.Name
	return ""
}
func (p *vercelProjectDelete) execute(r *run) error {
	err := r.step(StepVercelDeleteProject, CodeProviderFailed, func() error { return r.vercel.DeleteProject(r.ctx, p.TeamID, p.ProjectID) })
	r.res.Deleted = err == nil
	if err != nil {
		return err
	}
	// The project's env vars are gone: rotations no longer need to rewrite
	// them. (Allowed destinations stay: project IDs are never reused.)
	return r.step(StepBindingForget, agentbroker.CodeVaultFailed, func() error {
		all, err := r.vault.ListBindings(r.ctx)
		if err != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
		dest := Destination{TeamID: p.TeamID, ProjectID: p.ProjectID}
		var names []string
		for _, sb := range all {
			b := sb.Binding.clone()
			kept := b.DeployedTo[:0]
			for _, d := range b.DeployedTo {
				if d.dest() != dest {
					kept = append(kept, d)
				}
			}
			if len(kept) == len(b.DeployedTo) {
				continue
			}
			b.DeployedTo = kept
			if len(b.DeployedTo) == 0 {
				b.DeployedTo = nil
			}
			if err := saveBinding(r.ctx, r.vault, b, sb.Revision); err != nil {
				return err
			}
			names = append(names, b.Record)
		}
		sort.Strings(names)
		r.res.ForgottenDeployments = names
		return nil
	})
}

// ---- vercel.env.push ----

func (p *vercelEnvPush) summary() string {
	var parts []string
	for _, env := range p.envNames() {
		parts = append(parts, env+" from record "+p.Variables[env])
	}
	s := "PUSH vault records to " + p.ref().text() + " as sensitive env vars: " + strings.Join(parts, ", ")
	for _, env := range p.replacedEnvs() {
		owners := p.replaced[env]
		if len(owners) == 1 {
			s += "; REPLACES record " + owners[0] + "'s value in " + env
		} else {
			s += "; REPLACES records " + strings.Join(owners, ", ") + "' values in " + env
		}
	}
	if len(p.foreign) > 0 {
		s += "; REPLACES a value NOT written by this broker in " + strings.Join(p.foreign, ", ")
	}
	return s
}
func (p *vercelEnvPush) controls() []string     { return []string{ControlVercel} }
func (p *vercelEnvPush) liveControls() []string { return []string{ControlVercel} }
func (p *vercelEnvPush) recordNames() []string {
	seen := map[string]bool{}
	var recs []string
	for _, env := range p.envNames() {
		if rec := p.Variables[env]; !seen[rec] {
			seen[rec] = true
			recs = append(recs, rec)
		}
	}
	return recs
}

// replacedEnvs are the env names (sorted) whose current claimants the push
// replaces.
func (p *vercelEnvPush) replacedEnvs() []string {
	out := make([]string, 0, len(p.replaced))
	for env := range p.replaced {
		out = append(out, env)
	}
	sort.Strings(out)
	return out
}

// deployed lists the entries this push writes record to.
func (p *vercelEnvPush) deployed(record string) []Deployed {
	var out []Deployed
	for _, env := range p.envNames() {
		if p.Variables[env] == record {
			out = append(out, Deployed{DeployTarget: p.ref().deployTarget(), Env: env})
		}
	}
	return out
}

// pushChecked is what check found: the pushed records' live bindings, the
// other records claiming each env var (replaced), and the env vars no
// binding claims (fresh, sorted).
type pushChecked struct {
	bound    map[string]bound
	replaced map[string][]string
	fresh    []string
}

// check: every record exists, has a live binding, may be deployed to this
// project, and has room to record this push in deployed_to, and after the
// push every record can still be rotated (rotatable: no interrupted Neon
// rotation, branch-scoped previews, at most max_rotation_targets scopes, a
// rotation approval that fits the prompt). An env var other records'
// bindings claim in this scope (envClaims, revoked included) is taken over
// only with replace_existing; replaced maps it to those records.
func (p *vercelEnvPush) check(ctx context.Context, v Vault) (pushChecked, string) {
	var c pushChecked
	if code := mustExist(ctx, v, p.recordNames()...); code != "" {
		return c, code
	}
	checked, code := boundForPush(ctx, v, p.ref().dest(), p.recordNames()...)
	if code != "" {
		return c, code
	}
	after := map[string]Binding{}
	for rec, lb := range checked {
		b, ok := lb.b.withDeployed(p.deployed(rec)...)
		if !ok {
			return c, CodeBindingLimit
		}
		after[rec] = b
	}
	if code := rotatable(ctx, v, after); code != "" {
		return c, code
	}
	claims, code := envClaims(ctx, v)
	if code != "" {
		return c, code
	}
	c.bound, c.replaced = checked, map[string][]string{}
	for _, env := range p.envNames() {
		d := Deployed{DeployTarget: p.ref().deployTarget(), Env: env}
		if others := othersClaiming(claims, d, p.Variables[env]); len(others) > 0 {
			c.replaced[env] = others
		}
		if len(claims[d]) == 0 {
			c.fresh = append(c.fresh, env)
		}
	}
	if len(c.replaced) > 0 && !p.ReplaceExisting {
		return c, CodeEnvNameTaken
	}
	return c, ""
}

// precheck: unbound records (owner-entered secrets) are never pushed.
func (p *vercelEnvPush) precheck(ctx context.Context, v Vault) string {
	c, code := p.check(ctx, v)
	p.replaced, p.fresh = c.replaced, c.fresh
	return code
}

// liveCheck: an env var no binding claims must not exist in Vercel yet (the
// owner, or something else, set it), unless replace_existing, and then the
// approval names it.
func (p *vercelEnvPush) liveCheck(ctx context.Context, ps *ports) (string, *Result) {
	found, code := foreignEnvs(ctx, ps.vercel, p.ref().env(), p.fresh)
	if code != "" {
		return code, nil
	}
	if len(found) > 0 && !p.ReplaceExisting {
		return CodeEnvNameTaken, nil
	}
	p.foreign = found
	return "", nil
}

func (p *vercelEnvPush) execute(r *run) error {
	var c pushChecked
	if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
		var code string
		if c, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		if !sameClaims(c.replaced, p.replaced) || strings.Join(c.fresh, ",") != strings.Join(p.fresh, ",") {
			return fail(CodeEnvNameTaken) // changed since the owner approved
		}
		// Each push reads exactly the bound revision.
		for rec, lb := range c.bound {
			r.res.record(rec, lb.b.RecordRevision)
		}
		return nil
	}); err != nil {
		return err
	}
	// Where each record goes is recorded before it is written, so a later
	// rotation knows every scope it must rewrite. (If the push or the
	// release below fails, an env var may stay claimed by two records:
	// rotations and env.remove then refuse it until an env.push with
	// replace_existing takes it over.)
	if err := r.step(StepBindingDeployed, agentbroker.CodeVaultFailed, func() error {
		for _, rec := range p.recordNames() {
			lb := c.bound[rec]
			b, ok := lb.b.withDeployed(p.deployed(rec)...)
			if !ok {
				return fail(CodeBindingLimit)
			}
			if len(b.DeployedTo) == len(lb.b.DeployedTo) {
				continue // already recorded
			}
			if err := saveBinding(r.ctx, r.vault, b, lb.objRev); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	approved := map[string]bool{}
	for _, env := range p.foreign {
		approved[env] = true
	}
	if err := r.push(p.ref().env(), p.Variables, p.fresh, approved); err != nil {
		return err
	}
	if len(p.replaced) == 0 {
		return nil
	}
	// The replaced records no longer live there: their rotations must not
	// rewrite (and so clobber) these env vars. Every other claimant is
	// released, so the pushed record is the sole owner again.
	return r.step(StepBindingRelease, agentbroker.CodeVaultFailed, func() error {
		drop := map[string][]Deployed{}
		for _, env := range p.replacedEnvs() {
			for _, owner := range p.replaced[env] {
				drop[owner] = append(drop[owner], Deployed{DeployTarget: p.ref().deployTarget(), Env: env})
			}
		}
		owners := make([]string, 0, len(drop))
		for owner := range drop {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		for _, owner := range owners {
			b, objRev, err := r.vault.LoadBinding(r.ctx, owner)
			if err != nil {
				return fail(agentbroker.CodeVaultFailed)
			}
			if err := saveBinding(r.ctx, r.vault, b.without(drop[owner]...), objRev); err != nil {
				return err
			}
			r.res.ReplacedRecords = append(r.res.ReplacedRecords, owner)
		}
		return nil
	})
}

func sameClaims(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(b[k], ",") != strings.Join(v, ",") {
			return false
		}
	}
	return true
}

// ---- vercel.env.remove ----

func (p *vercelEnvRemove) ref() VercelRef {
	return VercelRef{TeamID: p.TeamID, ProjectID: p.ProjectID, Target: p.Target, Production: p.Production, GitBranch: p.GitBranch}
}

func (p *vercelEnvRemove) deployed() Deployed {
	return Deployed{DeployTarget: p.ref().deployTarget(), Env: p.Env}
}

func (p *vercelEnvRemove) summary() string {
	return "REMOVE env var " + p.Env + " (record " + p.Record + "'s value) from " + p.ref().text() +
		"; deployments built with it keep it until redeployed; the record stays in the vault"
}
func (p *vercelEnvRemove) controls() []string { return []string{ControlVercel} }

// check: record has a binding (live, stale or revoked: this broker wrote
// the value) that lists exactly this env var in this scope, and no other
// record's binding claims it (ENV_NAME_TAKEN: the value there may be the
// other record's; take it over with env.push replace_existing first).
func (p *vercelEnvRemove) check(ctx context.Context, v Vault) (bound, string) {
	b, objRev, err := v.LoadBinding(ctx, p.Record)
	if errors.Is(err, ErrMissing) {
		return bound{}, CodeRecordNotBound
	}
	if err != nil || b.Record != p.Record || !b.Valid() {
		return bound{}, agentbroker.CodeVaultFailed
	}
	listed := false
	for _, d := range b.DeployedTo {
		listed = listed || d == p.deployed()
	}
	if !listed {
		return bound{}, CodeNotDeployed
	}
	claims, code := envClaims(ctx, v)
	if code != "" {
		return bound{}, code
	}
	if len(othersClaiming(claims, p.deployed(), p.Record)) > 0 {
		return bound{}, CodeEnvNameTaken
	}
	return bound{b: b, objRev: objRev}, ""
}
func (p *vercelEnvRemove) precheck(ctx context.Context, v Vault) string {
	_, code := p.check(ctx, v)
	return code
}
func (p *vercelEnvRemove) execute(r *run) error {
	var lb bound
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if lb, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
	r.res.TeamID, r.res.ProjectID = p.TeamID, p.ProjectID
	if err := r.step(StepVercelEnvRemove, CodeProviderFailed, func() error {
		if err := r.vercel.DeleteEnv(r.ctx, p.ref().env(), p.Env); err != nil {
			return err
		}
		r.res.Variables = map[string]string{p.Env: "removed"}
		return nil
	}); err != nil {
		return err
	}
	// Only once it is gone: a rotation no longer needs to rewrite it.
	return r.step(StepBindingForget, agentbroker.CodeVaultFailed, func() error {
		if err := saveBinding(r.ctx, r.vault, lb.b.without(p.deployed()), lb.objRev); err != nil {
			return err
		}
		r.res.ForgottenDeployments = []string{p.Record}
		return nil
	})
}

// ---- vercel.redeploy ----

func (p *vercelRedeploy) healthPath() string {
	if p.HealthPath == "" {
		return "/"
	}
	return p.HealthPath
}
func (p *vercelRedeploy) summary() string {
	if p.Target == TargetProduction {
		from := " from the deployment serving production now"
		if p.Deployment != "" {
			from += " (must be " + p.Deployment + ")"
		}
		return "REDEPLOY " + p.ref().text() + from + " as STAGED, check health at " + p.healthPath() +
			"; then PROMOTE, verify production serves it and recheck, auto ROLL BACK on failure"
	}
	return "REDEPLOY " + p.ref().text() + fromDeployment(p.Deployment) + ", then check health at " + p.healthPath()
}
func (p *vercelRedeploy) controls() []string                           { return []string{ControlVercel} }
func (p *vercelRedeploy) precheck(ctx context.Context, v Vault) string { return noCheck(ctx, v) }
func (p *vercelRedeploy) execute(r *run) error {
	if err := r.productionBaseline(p.ref()); err != nil {
		return err
	}
	return r.redeployAndCheck(p.ref(), p.healthPath())
}
