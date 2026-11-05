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
		s += "; REPLACES record " + p.replaced[env] + "'s value in " + env
	}
	return s
}
func (p *vercelEnvPush) controls() []string { return []string{ControlVercel} }
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

// replacedEnvs are the env names (sorted) whose current owner the push
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

// check: every record exists, has a live binding, may be deployed to this
// project, and has room to record this push in deployed_to, without
// spreading over more scopes than one rotation can rewrite. An env var
// another record's binding owns in this scope (envClaims) is replaced only
// with replace_existing; replaced maps it to that record.
func (p *vercelEnvPush) check(ctx context.Context, v Vault) (map[string]bound, map[string]string, string) {
	if code := mustExist(ctx, v, p.recordNames()...); code != "" {
		return nil, nil, code
	}
	checked, code := boundForPush(ctx, v, p.ref().dest(), p.recordNames()...)
	if code != "" {
		return nil, nil, code
	}
	for rec, lb := range checked {
		b, ok := lb.b.withDeployed(p.deployed(rec)...)
		if !ok {
			return nil, nil, CodeBindingLimit
		}
		if len(b.deployedScopes()) > maxRotationTargets {
			return nil, nil, CodeRotationScopeLimit
		}
	}
	claims, code := envClaims(ctx, v)
	if code != "" {
		return nil, nil, code
	}
	replaced := map[string]string{}
	for _, env := range p.envNames() {
		owner, ok := claims[Deployed{DeployTarget: p.ref().deployTarget(), Env: env}]
		if ok && owner != p.Variables[env] {
			replaced[env] = owner
		}
	}
	if len(replaced) > 0 && !p.ReplaceExisting {
		return nil, nil, CodeEnvNameTaken
	}
	return checked, replaced, ""
}

// precheck: unbound records (owner-entered secrets) are never pushed.
func (p *vercelEnvPush) precheck(ctx context.Context, v Vault) string {
	_, replaced, code := p.check(ctx, v)
	p.replaced = replaced
	return code
}
func (p *vercelEnvPush) execute(r *run) error {
	var checked map[string]bound
	if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
		var code string
		var replaced map[string]string
		if checked, replaced, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		if !sameStrings(replaced, p.replaced) {
			return fail(CodeEnvNameTaken) // changed since the owner approved
		}
		// Each push reads exactly the bound revision.
		for rec, lb := range checked {
			r.res.record(rec, lb.b.RecordRevision)
		}
		return nil
	}); err != nil {
		return err
	}
	// Where each record goes is recorded before it is written, so a later
	// rotation knows every scope it must rewrite.
	if err := r.step(StepBindingDeployed, agentbroker.CodeVaultFailed, func() error {
		for _, rec := range p.recordNames() {
			lb := checked[rec]
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
	if err := r.push(p.ref().env(), p.Variables); err != nil {
		return err
	}
	if len(p.replaced) == 0 {
		return nil
	}
	// The replaced records no longer live there: their rotations must not
	// rewrite (and so clobber) these env vars.
	return r.step(StepBindingRelease, agentbroker.CodeVaultFailed, func() error {
		drop := map[string][]Deployed{}
		for _, env := range p.replacedEnvs() {
			owner := p.replaced[env]
			drop[owner] = append(drop[owner], Deployed{DeployTarget: p.ref().deployTarget(), Env: env})
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
		}
		r.res.ReplacedRecords = owners
		return nil
	})
}

func sameStrings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
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
// the value) that lists exactly this env var in this scope.
func (p *vercelEnvRemove) check(ctx context.Context, v Vault) (bound, string) {
	b, objRev, err := v.LoadBinding(ctx, p.Record)
	if errors.Is(err, ErrMissing) {
		return bound{}, CodeRecordNotBound
	}
	if err != nil || b.Record != p.Record || !b.Valid() {
		return bound{}, agentbroker.CodeVaultFailed
	}
	for _, d := range b.DeployedTo {
		if d == p.deployed() {
			return bound{b: b, objRev: objRev}, ""
		}
	}
	return bound{}, CodeNotDeployed
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
