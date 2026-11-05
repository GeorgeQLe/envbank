package provideraction

import (
	"sort"
	"strings"
)

// Rotation scope. A binding allows a record on every target of up to
// MaxAllowedDestinations projects, and deployed_to lists where this broker
// actually wrote it. A rotation invalidates the old credential at the end,
// so it must first rewrite and redeploy every one of those scopes: a
// preview-only rotation would otherwise break production. v1 supports
// exactly that: the rotation names its scopes (params vercel, a list) and
// is refused before the prompt (ROTATION_SCOPE_INCOMPLETE) unless they
// cover every deployed_to entry of the records it rotates.

// scoped is one record a rotation pushes. b is its live binding (nil for a
// record the rotation creates); cover requires b's deployed_to to be
// covered by the rotation's scopes.
type scoped struct {
	record string
	b      *Binding
	cover  bool
}

// scopePlan is what a rotation pushes where: per scope, env var → record.
type scopePlan struct {
	refs []VercelRef // rotation order (production last)
	vars map[DeployTarget]map[string]string
}

// planScope checks a rotation's scopes against its records' bindings: every
// scope must be allowed for every bound record, and every deployed_to entry
// of a covered record must be one of the scopes. A record is pushed under
// the env names it was deployed with in that scope, or under its own name
// where it was not deployed yet.
func planScope(refs VercelRefs, items []scoped) (scopePlan, string) {
	named := map[DeployTarget]bool{}
	for _, ref := range refs {
		named[ref.deployTarget()] = true
	}
	for _, it := range items {
		if it.b == nil {
			continue
		}
		for _, ref := range refs {
			if !it.b.allows(ref.dest()) {
				return scopePlan{}, CodeDestinationNotAllowed
			}
		}
		if it.cover {
			for _, d := range it.b.DeployedTo {
				if !named[d.DeployTarget] {
					return scopePlan{}, CodeRotationScopeIncomplete
				}
			}
		}
	}
	plan := scopePlan{refs: refs.ordered(), vars: map[DeployTarget]map[string]string{}}
	for _, ref := range plan.refs {
		t := ref.deployTarget()
		vars := map[string]string{}
		for _, it := range items {
			var envs []string
			if it.b != nil && it.cover {
				envs = it.b.deployedAt(t)
			}
			if len(envs) == 0 {
				envs = []string{it.record}
			}
			for _, env := range envs {
				if other, dup := vars[env]; dup && other != it.record {
					return scopePlan{}, CodeBindingMismatch // two records under one env name
				}
				vars[env] = it.record
			}
		}
		if len(vars) > maxVariables {
			return scopePlan{}, CodeBindingLimit
		}
		plan.vars[t] = vars
	}
	return plan, ""
}

// deployed lists the entries plan writes record to.
func (sp scopePlan) deployed(record string) []Deployed {
	var out []Deployed
	for _, ref := range sp.refs {
		t := ref.deployTarget()
		envs := make([]string, 0, len(sp.vars[t]))
		for env, rec := range sp.vars[t] {
			if rec == record {
				envs = append(envs, env)
			}
		}
		sort.Strings(envs)
		for _, env := range envs {
			out = append(out, Deployed{DeployTarget: t, Env: env})
		}
	}
	return out
}

// fits reports whether b can also list everything plan writes to record.
func (sp scopePlan) fits(b Binding, record string) bool {
	_, ok := b.withDeployed(sp.deployed(record)...)
	return ok
}

// rotationText is a composite action's push-and-redeploy wording: " to
// <scope>, redeploy …" for one scope, or every scope in rotation order. It
// is terse because the whole plan must fit the 600-byte Touch ID prompt.
func rotationText(refs VercelRefs, healthPath string) string {
	if len(refs) == 1 {
		return " to " + refs[0].text() + deployText(refs[0], healthPath)
	}
	var parts []string
	prod := false
	for _, ref := range refs.ordered() {
		t := ref.text()
		if ref.Target == TargetProduction {
			prod = true
			t += " (STAGED, last)"
		}
		if ref.Deployment != "" {
			t += " from " + ref.Deployment
		}
		parts = append(parts, t)
	}
	s := " to, and redeploy, each of " + strings.Join(parts, "; ") + ", check health at " + healthPath
	if prod {
		s += productionText
	}
	return s
}

// rotateScopes pushes and redeploys every scope of plan, in order
// (production last, through the production release).
func (r *run) rotateScopes(plan scopePlan, healthPath string) error {
	for _, ref := range plan.refs {
		if err := r.push(ref.env(), plan.vars[ref.deployTarget()]); err != nil {
			return err
		}
		if err := r.redeployAndCheck(ref, healthPath); err != nil {
			return err
		}
	}
	return nil
}

// deployText is one scope's redeploy wording: for production, the staged
// redeploy, the promote and the automatic rollback.
func deployText(ref VercelRef, healthPath string) string {
	if ref.Target == TargetProduction {
		from := ""
		if ref.Deployment != "" {
			from = " from " + ref.Deployment
		}
		return ", STAGED redeploy" + from + ", check health at " + healthPath + productionText
	}
	return ", redeploy" + fromDeployment(ref.Deployment) + ", check health at " + healthPath
}

// productionText follows a production release's staged health check.
const productionText = ", PROMOTE, verify production serves it and recheck, auto ROLL BACK on failure"

func fromDeployment(d string) string {
	if d == "" {
		return " from the current deployment"
	}
	return " from " + d
}
