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
// fresh lists, per scope, the env vars no binding claims: Vercel must not
// hold them already (a value the broker did not write), checked before the
// prompt and again before the write.
type scopePlan struct {
	refs  []VercelRef // rotation order (production last)
	vars  map[DeployTarget]map[string]string
	fresh map[DeployTarget][]string
}

// envClaims maps every env var a binding lists in deployed_to to every
// record claiming it, sorted. Revoked bindings count: the broker wrote that
// value there and it is still in Vercel. Normally one (scope, env name) has
// one claimant; a failed push or release can leave two, and then only an
// env.push with replace_existing (which takes over every other claimant)
// may write there.
func envClaims(ctx context.Context, v Vault) (map[Deployed][]string, string) {
	all, err := v.ListBindings(ctx)
	if err != nil {
		return nil, agentbroker.CodeVaultFailed
	}
	out := map[Deployed][]string{}
	for _, sb := range all {
		for _, d := range sb.Binding.DeployedTo {
			out[d] = append(out[d], sb.Binding.Record)
		}
	}
	for d := range out {
		sort.Strings(out[d])
	}
	return out, ""
}

// othersClaiming lists the claimants of d other than record.
func othersClaiming(claims map[Deployed][]string, d Deployed, record string) []string {
	var out []string
	for _, c := range claims[d] {
		if c != record {
			out = append(out, c)
		}
	}
	return out
}

// planScope checks a rotation's scopes against its records' bindings: every
// scope must be allowed for every bound record, and every deployed_to entry
// of a covered record must be one of the scopes. A record is pushed under
// the env names it was deployed with in that scope, or under its own name
// where it was not deployed yet. claims (envClaims) refuses an env var
// any other record's binding also claims.
//
// Preview scopes must name a git branch (ROTATION_UNSCOPED_PREVIEW): an
// all-branches preview env var is used by every preview deployment, but a
// rotation can redeploy and health-check only one of them, so invalidating
// the old credential would break the rest.
func planScope(refs VercelRefs, items []scoped, claims map[Deployed][]string) (scopePlan, string) {
	named := map[DeployTarget]bool{}
	for _, ref := range refs {
		if ref.Target == TargetPreview && ref.GitBranch == "" {
			return scopePlan{}, CodeRotationUnscopedPreview
		}
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
				if d.Target == TargetPreview && d.GitBranch == "" {
					return scopePlan{}, CodeRotationUnscopedPreview
				}
				if !named[d.DeployTarget] {
					return scopePlan{}, CodeRotationScopeIncomplete
				}
			}
		}
	}
	plan := scopePlan{refs: refs.ordered(), vars: map[DeployTarget]map[string]string{}, fresh: map[DeployTarget][]string{}}
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
				d := Deployed{DeployTarget: t, Env: env}
				if len(othersClaiming(claims, d, it.record)) > 0 {
					return scopePlan{}, CodeEnvNameTaken // another record's value (also) lives there
				}
				if len(claims[d]) == 0 {
					plan.fresh[t] = append(plan.fresh[t], env)
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
		if err := r.push(ref.env(), plan.vars[ref.deployTarget()], plan.fresh[ref.deployTarget()], nil); err != nil {
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

// ---- push-time rotation checks ----

// planFitKey carries the caller's approval-budget check (WithPlanFit).
type planFitKey struct{}

// WithPlanFit returns ctx carrying fits, which reports whether a plan's
// approval text fits the Touch ID prompt for the requesting session. Prepare
// uses it to refuse (PLAN_TOO_LONG) a push after which no rotation of the
// pushed records could be approved. Without it that check is skipped.
func WithPlanFit(ctx context.Context, fits func(summary string) bool) context.Context {
	return context.WithValue(ctx, planFitKey{}, fits)
}

func planFit(ctx context.Context) func(string) bool {
	f, _ := ctx.Value(planFitKey{}).(func(string) bool)
	return f
}

// rotationGroup lists the non-revoked bindings one rotation of b must
// cover: for Neon every binding of the same project and branch, for Stripe
// every binding of the same lineage.
func rotationGroup(all map[string]Binding, b Binding) []Binding {
	var out []Binding
	for _, x := range all {
		if x.Revoked || x.Provider != b.Provider {
			continue
		}
		switch b.Provider {
		case ProviderNeon:
			if x.Resource.ProjectID != b.Resource.ProjectID || x.Resource.BranchID != b.Resource.BranchID {
				continue
			}
		case ProviderStripe:
			if x.Resource.Lineage != b.Resource.Lineage {
				continue
			}
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record < out[j].Record })
	return out
}

// rotatable refuses a push after which the pushed records (after: their
// bindings as the push would leave them) could not be rotated:
//   - ROTATION_INCOMPLETE: a Neon rotation of the group was interrupted
//     (a binding is pending); a retry resets the pending role again, which
//     would break a deployment this push gave its URIs (finish neon.rotate
//     first);
//   - ROTATION_UNSCOPED_PREVIEW: the group would be deployed to a preview
//     scope without git_branch;
//   - ROTATION_SCOPE_LIMIT: the group would span more scopes than one
//     rotation names;
//   - PLAN_TOO_LONG: even the shortest rotation approval of the group
//     (health path "/") would not fit the prompt (WithPlanFit).
func rotatable(ctx context.Context, v Vault, after map[string]Binding) string {
	stored, err := v.ListBindings(ctx)
	if err != nil {
		return agentbroker.CodeVaultFailed
	}
	all := map[string]Binding{}
	for _, sb := range stored {
		all[sb.Binding.Record] = sb.Binding
	}
	recs := make([]string, 0, len(after))
	for rec, b := range after {
		all[rec] = b
		recs = append(recs, rec)
	}
	sort.Strings(recs)
	for _, rec := range recs {
		group := rotationGroup(all, after[rec])
		var scopes []DeployTarget
		seen := map[DeployTarget]bool{}
		for _, m := range group {
			if m.PendingRole != "" {
				return CodeRotationIncomplete
			}
			for _, t := range m.deployedScopes() {
				if t.Target == TargetPreview && t.GitBranch == "" {
					return CodeRotationUnscopedPreview
				}
				if !seen[t] {
					seen[t] = true
					scopes = append(scopes, t)
				}
			}
		}
		if len(scopes) > maxRotationTargets {
			return CodeRotationScopeLimit
		}
		if fits := planFit(ctx); fits != nil && len(scopes) > 0 {
			if summary, ok := shortestRotation(ctx, v, after[rec], group, scopes); ok && !fits(summary) {
				return CodePlanTooLong
			}
		}
	}
	return ""
}

// shortestRotation is the shortest approval text a rotation of group over
// scopes could have: health path "/", the database name from the Neon
// project's provenance (else one character), and one-character names for
// records the group does not have yet. false: no rotation plan applies.
func shortestRotation(ctx context.Context, v Vault, b Binding, group []Binding, scopes []DeployTarget) (string, bool) {
	refs := make(VercelRefs, 0, len(scopes))
	for _, t := range scopes {
		refs = append(refs, VercelRef{TeamID: t.TeamID, ProjectID: t.ProjectID, Target: t.Target, Production: t.Target == TargetProduction, GitBranch: t.GitBranch})
	}
	kinds := map[string]Binding{}
	for _, m := range group {
		kinds[m.Kind] = m
	}
	name := func(kind string) string {
		if m, ok := kinds[kind]; ok {
			return m.Record
		}
		return "X"
	}
	switch b.Provider {
	case ProviderNeon:
		db := "d"
		if prov, err := v.LoadNeonProject(ctx, b.Resource.ProjectID); err == nil && prov.BranchID == b.Resource.BranchID {
			db = prov.Database
		}
		p := neonRotate{ProjectID: b.Resource.ProjectID, BranchID: b.Resource.BranchID, Database: db, HealthPath: "/", Vercel: refs,
			Records: RecordPair{Pooled: name(KindNeonPooled), Direct: name(KindNeonDirect)}}
		if len(b.Roles) == 2 {
			p.derived = neonRoleOrder{old: b.ActiveRole, next: b.inactiveRole()}
		}
		return p.summary(), true
	case ProviderStripe:
		cur, ok := kinds[KindStripeWebhookSecret]
		if !ok {
			return "", false
		}
		prov, err := v.LoadStripeEndpoint(ctx, cur.Resource.EndpointID)
		if err != nil {
			return "", false
		}
		p := stripeWebhookRotate{EndpointID: cur.Resource.EndpointID, Record: cur.Record, PreviousRecord: name(KindStripeWebhookSecretPrevious),
			Vercel: refs, HealthPath: "/", url: prov.URL, events: prov.Events}
		return p.summary(), true
	}
	return "", false
}

// freshAbsent refuses (ENV_NAME_TAKEN) when Vercel already holds an env var
// a rotation would newly write in one of refs (a value the broker did not
// write; read-only, before the prompt).
func freshAbsent(ctx context.Context, vp VercelPort, refs VercelRefs, fresh map[DeployTarget][]string) string {
	for _, ref := range refs {
		if code := foreignEnvsAbsent(ctx, vp, ref.env(), fresh[ref.deployTarget()], nil); code != "" {
			return code
		}
	}
	return ""
}
