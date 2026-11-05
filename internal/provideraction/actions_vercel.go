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
	return "PUSH vault records to " + p.ref().text() + " as sensitive env vars: " + strings.Join(parts, ", ")
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
// project, and has room to record this push in deployed_to.
func (p *vercelEnvPush) check(ctx context.Context, v Vault) (map[string]bound, string) {
	if code := mustExist(ctx, v, p.recordNames()...); code != "" {
		return nil, code
	}
	checked, code := boundForPush(ctx, v, p.ref().dest(), p.recordNames()...)
	if code != "" {
		return nil, code
	}
	for rec, lb := range checked {
		if _, ok := lb.b.withDeployed(p.deployed(rec)...); !ok {
			return nil, CodeBindingLimit
		}
	}
	return checked, ""
}

// precheck: unbound records (owner-entered secrets) are never pushed.
func (p *vercelEnvPush) precheck(ctx context.Context, v Vault) string {
	_, code := p.check(ctx, v)
	return code
}
func (p *vercelEnvPush) execute(r *run) error {
	var checked map[string]bound
	if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
		var code string
		if checked, code = p.check(r.ctx, r.vault); code != "" {
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
	if p.Target == TargetProduction {
		return "REDEPLOY " + p.ref().text() + fromDeployment(p.Deployment) + " as STAGED, check health at " + p.healthPath() + productionText
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
