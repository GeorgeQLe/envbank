package provideraction

import (
	"context"
	"sort"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
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

// envClaims maps every env var a live-or-stale (not revoked) binding lists
// in deployed_to to that binding's record: the record whose value the broker
// last wrote there. One (scope, env name) has one owner.
func envClaims(ctx context.Context, v Vault) (map[Deployed]string, string) {
	all, err := v.ListBindings(ctx)
	if err != nil {
		return nil, agentbroker.CodeVaultFailed
	}
	out := map[Deployed]string{}
	for _, sb := range all {
		if sb.Binding.Revoked {
			continue
		}
		for _, d := range sb.Binding.DeployedTo {
			out[d] = sb.Binding.Record
		}
	}
	return out, ""
}

// planScope checks a rotation's scopes against its records' bindings: every
// scope must be allowed for every bound record, and every deployed_to entry
// of a covered record must be one of the scopes. A record is pushed under
// the env names it was deployed with in that scope, or under its own name
// where it was not deployed yet. claims (envClaims) refuses an env var
// another record's binding owns.
//
// Preview scopes must name a git branch (ROTATION_UNSCOPED_PREVIEW): an
// all-branches preview env var is used by every preview deployment, but a
// rotation can redeploy and health-check only one of them, so invalidating
// the old credential would break the rest.
func planScope(refs VercelRefs, items []scoped, claims map[Deployed]string) (scopePlan, string) {
	named := map[DeployTarget]bool{}
	for _, ref := range refs {
		if ref.Target == TargetPreview && ref.GitBranch == "" {
			return scopePlan{}, CodeRotationUnscopedPreview
		}
		named[ref.deployTarget()] = true
	}
	ours := map[string]bool{}
	for _, it := range items {
		ours[it.record] = true
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
				if d.Target == TargetPreview && d.GitBranch == "" {
					return scopePlan{}, CodeRotationUnscopedPreview
				}
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
				if owner, ok := claims[Deployed{DeployTarget: t, Env: env}]; ok && !ours[owner] {
					return scopePlan{}, CodeEnvNameTaken // another record's value lives there
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

// rotationText is a composite action's push-and-redeploy wording, naming
// every scope once, grouped by team and project (scopesText). It is terse
// because the whole plan must fit the 600-byte Touch ID prompt
// (docs/provider-actions.md, "Approval text budget").
func rotationText(refs VercelRefs, healthPath string) string {
	s := "; push, redeploy, health " + healthPath + " on " + scopesText(refs)
	if _, ok := refs.production(); ok {
		s += productionText
	}
	return s
}

// scopesText names each team once, then each of its projects once with its
// scopes: "Vercel team_a: prj_x preview@main+PRODUCTION, prj_y
// preview@feat and team_b: prj_z PRODUCTION". A preview scope is
// "preview@<branch>" (or "preview" for every branch), with " from <dpl>"
// when the source deployment is named; production is "PRODUCTION".
func scopesText(refs VercelRefs) string {
	sorted := append([]VercelRef(nil), refs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.TeamID != b.TeamID {
			return a.TeamID < b.TeamID
		}
		if a.ProjectID != b.ProjectID {
			return a.ProjectID < b.ProjectID
		}
		pa, pb := a.Target == TargetProduction, b.Target == TargetProduction
		if pa != pb {
			return pb
		}
		return a.GitBranch < b.GitBranch
	})
	var b strings.Builder
	b.WriteString("Vercel ")
	for i, ref := range sorted {
		switch {
		case i == 0:
			b.WriteString(ref.TeamID + ": " + ref.ProjectID + " ")
		case ref.TeamID != sorted[i-1].TeamID:
			b.WriteString(" and " + ref.TeamID + ": " + ref.ProjectID + " ")
		case ref.ProjectID != sorted[i-1].ProjectID:
			b.WriteString(", " + ref.ProjectID + " ")
		default:
			b.WriteString("+")
		}
		b.WriteString(ref.scopeToken())
	}
	return b.String()
}

// scopeToken is one scope of scopesText.
func (v VercelRef) scopeToken() string {
	if v.Target == TargetProduction {
		return "PRODUCTION"
	}
	t := "preview"
	if v.GitBranch != "" {
		t += "@" + v.GitBranch
	}
	if v.Deployment != "" {
		t += " from " + v.Deployment
	}
	return t
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

// productionText follows a rotation's scopes when one is production: it is
// released last, staged, promoted only when healthy, and rolled back on any
// failure from the promote on.
const productionText = "; PRODUCTION last: STAGED, PROMOTE, auto ROLL BACK on failure"

func fromDeployment(d string) string {
	if d == "" {
		return " from the current deployment"
	}
	return " from " + d
}
