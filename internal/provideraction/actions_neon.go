package provideraction

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

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

// execute creates the project, records its provenance, prepares the
// rotation roles as the owner role, then stores the first rotation role's
// URIs. The owner URIs the adapter returns on create go to discarding sinks
// and are never stored. A failure after create leaves project_id in the
// result for cleanup.
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
	// Provenance first: a later failure still leaves a project this broker
	// may delete, and the roles it is about to create are its own.
	if err := r.step(StepProvenanceSave, agentbroker.CodeVaultFailed, func() error {
		prov := NeonProjectProvenance{V: BindingVersion, ProjectID: info.ProjectID, Name: p.Name, BranchID: info.BranchID, Database: info.Database,
			OwnerRole: info.Role, Roles: []string{roles[0], roles[1]}}
		if !prov.Valid() || r.vault.SaveNeonProject(r.ctx, prov) != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
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
		// The records were absent at the precheck: they are created, never
		// overwritten.
		w := r.recorder(map[string]int64{p.Records.Pooled: 0, p.Records.Direct: 0})
		if err := r.neon.ResetRolePassword(r.ctx, info.ProjectID, info.BranchID, roles[0], info.Database, w.sink(p.Records.Pooled), w.sink(p.Records.Direct)); err != nil {
			return w.check(err)
		}
		return w.require(r.res, p.Records.Pooled, p.Records.Direct)
	}); err != nil {
		return err
	}
	r.res.ActiveRole = roles[0]
	return r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		res := BindingResource{ProjectID: info.ProjectID, BranchID: info.BranchID}
		for rec, kind := range map[string]string{p.Records.Pooled: KindNeonPooled, p.Records.Direct: KindNeonDirect} {
			b := newBinding(rec, ProviderNeon, kind, res, r.res.Records[rec])
			b.Roles, b.ActiveRole = []string{roles[0], roles[1]}, roles[0]
			if err := replaceBinding(r.ctx, r.vault, b); err != nil {
				return err
			}
		}
		return nil
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
		s += ", and CHANGE OWNERSHIP of all existing public-schema objects to " + NeonGroupRole
	} else {
		s += " (existing public-schema objects keep their owners)"
	}
	for _, role := range p.existing {
		s += "; EXISTING role " + role + " (not created by this broker) will act as the schema owner"
	}
	return s
}
func (p *neonRolesPrepare) controls() []string     { return []string{ControlNeon} }
func (p *neonRolesPrepare) liveControls() []string { return []string{ControlNeon} }

// precheck reads the project's provenance (absent for a project this broker
// did not create): the roles it created are its own.
func (p *neonRolesPrepare) precheck(ctx context.Context, v Vault) string {
	prov, err := v.LoadNeonProject(ctx, p.ProjectID)
	switch {
	case errors.Is(err, ErrMissing):
		p.prov = nil
	case err != nil || prov.ProjectID != p.ProjectID:
		return agentbroker.CodeVaultFailed
	default:
		p.prov = &prov
	}
	return ""
}

// liveCheck: owner_role must be the database's actual owner, and a role that
// already exists and was not created by this broker becomes a rotation role
// only with adopt_existing_roles (the text then names it).
func (p *neonRolesPrepare) liveCheck(ctx context.Context, ps *ports) (string, *Result) {
	existing, code := p.roleState(ctx, ps.neon)
	if code != "" {
		return code, nil
	}
	if len(existing) > 0 && !p.AdoptExistingRoles {
		return CodeNeonRoleExists, nil
	}
	p.existing = existing
	return "", nil
}

// roleState checks the owner and returns the roles that already exist and
// were not created by this broker (per the project's provenance).
func (p *neonRolesPrepare) roleState(ctx context.Context, n NeonPort) ([]string, string) {
	if code := checkNeonOwner(ctx, n, p.ProjectID, p.BranchID, p.Database, p.OwnerRole); code != "" {
		return nil, code
	}
	var existing []string
	for _, role := range p.roles() {
		ok, err := n.RoleExists(ctx, p.ProjectID, p.BranchID, role)
		if err != nil {
			return nil, CodeProviderFailed
		}
		if ok && !(p.prov != nil && p.prov.createdRole(p.BranchID, role)) {
			existing = append(existing, role)
		}
	}
	return existing, ""
}

func (p *neonRolesPrepare) execute(r *run) error {
	roles := p.roles()
	// The role state the owner approved must still hold: a role created in
	// between is refused rather than granted silently.
	if err := r.step(StepNeonCheckRoleState, CodeProviderFailed, func() error {
		existing, code := p.roleState(r.ctx, r.neon)
		if code != "" {
			return fail(code)
		}
		if strings.Join(existing, ",") != strings.Join(p.existing, ",") {
			return fail(CodeNeonRoleExists)
		}
		return nil
	}); err != nil {
		return err
	}
	return r.step(StepNeonPrepareRoles, CodeProviderFailed, func() error {
		if err := r.neon.PrepareRotationRoles(r.ctx, p.ProjectID, p.BranchID, p.Database, p.OwnerRole, roles, p.Adopt); err != nil {
			return err
		}
		r.res.PreparedRoles = []string{roles[0], roles[1]}
		return nil
	})
}

// checkNeonOwner: owner is the role Neon reports as database's owner.
func checkNeonOwner(ctx context.Context, n NeonPort, projectID, branchID, database, owner string) string {
	got, err := n.DatabaseOwner(ctx, projectID, branchID, database)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return CodeNeonOwnerRoleMismatch
		}
		return CodeProviderFailed
	}
	if got != owner {
		return CodeNeonOwnerRoleMismatch
	}
	return ""
}

// ---- neon.project.delete ----

func (p *neonProjectDelete) summary() string {
	what := "Neon project " + p.ProjectID
	if p.name != "" {
		what = "Neon project " + p.name + " (" + p.ProjectID + "), created by this broker,"
	}
	return "DELETE " + what + " and all its data, and revoke the bindings of its records (the records stay in the vault)"
}
func (p *neonProjectDelete) controls() []string { return []string{ControlNeon} }

func (p *neonProjectDelete) ours(b Binding) bool {
	return b.Provider == ProviderNeon && b.Resource.ProjectID == p.ProjectID
}

// precheck: v1 deletes only projects this broker created, and only once no
// record of it is still deployed (vercel.env.remove clears deployed_to).
func (p *neonProjectDelete) precheck(ctx context.Context, v Vault) string {
	prov, err := v.LoadNeonProject(ctx, p.ProjectID)
	switch {
	case errors.Is(err, ErrMissing):
		return CodeNotCreatedByBroker
	case err != nil || prov.ProjectID != p.ProjectID:
		return agentbroker.CodeVaultFailed
	}
	p.name = prov.Name
	return stillDeployed(ctx, v, p.ours)
}
func (p *neonProjectDelete) execute(r *run) error {
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		if code := stillDeployed(r.ctx, r.vault, p.ours); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
	err := r.step(StepNeonDeleteProject, CodeProviderFailed, func() error { return r.neon.DeleteProject(r.ctx, p.ProjectID) })
	r.res.Deleted = err == nil
	if err != nil {
		return err
	}
	return r.step(StepBindingRevoke, agentbroker.CodeVaultFailed, func() error {
		names, err := revokeBindings(r.ctx, r.vault, p.ours)
		r.res.RevokedBindings = names
		return err
	})
}

// ---- neon.rotate ----

// neonRoleOrder is a rotation's role order, derived from the bindings:
// old is the role deployments may use now (invalidated at the end), next
// the role the records hold afterwards. resume: an earlier rotation stored
// next's URIs and recorded them but did not finish, so no password is
// reset; the stored URIs are deployed and old is invalidated. retry: an
// earlier rotation marked the bindings pending (next) and failed before
// they followed the new URIs; next was never deployed, so its password is
// reset again, as in a normal rotation.
type neonRoleOrder struct {
	old, next     string
	resume, retry bool
}

// summary is terse: the whole plan must fit the Touch ID prompt
// (docs/provider-actions.md, "Approval text budget"). The owner role is a
// precondition (checked live), not an effect, so it is not shown.
func (p *neonRotate) summary() string {
	o := p.derived
	if o.next == "" && len(p.Roles) == 2 {
		o = neonRoleOrder{old: p.Roles[0], next: p.Roles[1]}
	}
	where := p.ProjectID + "/" + p.BranchID + "/" + p.Database
	recs := p.Records.Pooled + ", " + p.Records.Direct
	scopes := rotationText(p.Vercel, p.HealthPath)
	switch {
	case o.next == "":
		return "ROTATE Neon " + where + ": reset the inactive role into " + recs + scopes + "; then INVALIDATE the active role"
	case o.resume:
		return "COMPLETE Neon " + where + " rotation to role " + o.next + " (stored in " + recs + ")" + scopes + "; then INVALIDATE old role " + o.old
	}
	return "ROTATE Neon " + where + ": reset role " + o.next + " into " + recs + scopes + "; then INVALIDATE old role " + o.old
}
func (p *neonRotate) controls() []string     { return []string{ControlNeon, ControlVercel} }
func (p *neonRotate) liveControls() []string { return []string{ControlNeon} }

// neonChecked is a rotation's checked bindings and plan.
type neonChecked struct {
	pooled, direct bound
	order          neonRoleOrder
	scope          scopePlan
}

// neonOrder derives the role order from the two bindings' role state
// (docs/provider-actions.md, "Interrupted rotations"):
//   - neither pending nor retiring, same active role: a normal rotation;
//   - any pending: a retry of that rotation; the other binding is either
//     not marked yet (same active role) or already follows it (active =
//     pending role, retiring = the old one);
//   - otherwise, with the same active role and one retiring role: resume.
func neonOrder(a, b Binding) (neonRoleOrder, bool) {
	if len(a.Roles) != 2 || strings.Join(a.Roles, ",") != strings.Join(b.Roles, ",") {
		return neonRoleOrder{}, false
	}
	if a.PendingRole == "" && b.PendingRole != "" {
		a, b = b, a
	}
	if a.PendingRole != "" {
		o := neonRoleOrder{old: a.ActiveRole, next: a.PendingRole, retry: true}
		switch {
		case b.PendingRole != "":
			return o, b.ActiveRole == o.old && b.PendingRole == o.next
		case b.RetiringRole != "":
			return o, b.ActiveRole == o.next && b.RetiringRole == o.old
		}
		return o, b.ActiveRole == o.old
	}
	if a.ActiveRole != b.ActiveRole {
		return neonRoleOrder{}, false
	}
	retiring := a.RetiringRole
	if retiring == "" {
		retiring = b.RetiringRole
	}
	if retiring == "" {
		return neonRoleOrder{old: a.ActiveRole, next: a.inactiveRole()}, true
	}
	if (a.RetiringRole != "" && a.RetiringRole != retiring) || (b.RetiringRole != "" && b.RetiringRole != retiring) {
		return neonRoleOrder{}, false
	}
	return neonRoleOrder{old: retiring, next: a.ActiveRole, resume: true}, true
}

// check: both records are bound to this exact project and branch with the
// matching kinds and agree on the role state, which determines the order;
// every named scope is allowed and together they cover every scope the
// records were deployed to, and no env var they would rewrite belongs to
// another record.
func (p *neonRotate) check(ctx context.Context, v Vault) (neonChecked, string) {
	var c neonChecked
	var code string
	if c.pooled, code = boundToNeon(ctx, v, p.Records.Pooled, KindNeonPooled, p.ProjectID, p.BranchID); code != "" {
		return c, code
	}
	if c.direct, code = boundToNeon(ctx, v, p.Records.Direct, KindNeonDirect, p.ProjectID, p.BranchID); code != "" {
		return c, code
	}
	a, b := c.pooled.b, c.direct.b
	var ok bool
	if c.order, ok = neonOrder(a, b); !ok {
		return c, CodeNeonActiveRoleMismatch
	}
	for _, role := range a.Roles {
		if strings.EqualFold(role, p.OwnerRole) {
			return c, CodeNeonOwnerRoleMismatch
		}
	}
	// Only a pending binding may be one revision ahead.
	for _, lb := range []bound{c.pooled, c.direct} {
		if lb.rev != lb.b.RecordRevision && !c.order.retry {
			return c, CodeRecordNotBound
		}
	}
	if p.Roles != nil && (p.Roles[0] != c.order.old || p.Roles[1] != c.order.next) {
		return c, CodeNeonActiveRoleMismatch
	}
	claims, code := envClaims(ctx, v)
	if code != "" {
		return c, code
	}
	if c.scope, code = planScope(p.Vercel, []scoped{{p.Records.Pooled, &c.pooled.b, true}, {p.Records.Direct, &c.direct.b, true}}, claims); code != "" {
		return c, code
	}
	if !c.scope.fits(a, p.Records.Pooled) || !c.scope.fits(b, p.Records.Direct) {
		return c, CodeBindingLimit
	}
	return c, ""
}
func (p *neonRotate) precheck(ctx context.Context, v Vault) string {
	c, code := p.check(ctx, v)
	if code == "" {
		p.derived = c.order
	}
	return code
}

// liveCheck: owner_role must be the database's actual owner.
func (p *neonRotate) liveCheck(ctx context.Context, ps *ports) (string, *Result) {
	return checkNeonOwner(ctx, ps.neon, p.ProjectID, p.BranchID, p.Database, p.OwnerRole), nil
}

// execute is the zero-downtime dual-role rotation. The role deployments use
// (order.old) keeps working until the new role's URIs are stored, pushed to
// every scope the records were deployed to, deployed and healthy; only then
// is its password reset.
func (p *neonRotate) execute(r *run) error {
	var c neonChecked
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if c, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		if c.order != p.derived {
			return fail(CodeNeonActiveRoleMismatch) // changed since the owner approved
		}
		return nil
	}); err != nil {
		return err
	}
	old, next := c.order.old, c.order.next
	r.res.Resumed = c.order.resume
	// Read-only: the owner is still the database's owner, and both roles act
	// as the group owner (or the new role could not use the old role's
	// tables). Not ready fails with no side effects.
	if err := r.step(StepNeonCheckRoles, CodeProviderFailed, func() error {
		if code := checkNeonOwner(r.ctx, r.neon, p.ProjectID, p.BranchID, p.Database, p.OwnerRole); code != "" {
			return fail(code)
		}
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
	// Production: read the deployment serving production now (the rollback
	// target) before anything changes.
	if prod, ok := p.Vercel.production(); ok {
		if err := r.productionBaseline(prod); err != nil {
			return err
		}
	}
	if c.order.resume {
		// The records already hold next's URIs (exactly the bound revisions).
		if err := r.step(StepVaultReadRevisions, agentbroker.CodeVaultFailed, func() error {
			r.res.record(p.Records.Pooled, c.pooled.b.RecordRevision)
			r.res.record(p.Records.Direct, c.direct.b.RecordRevision)
			return nil
		}); err != nil {
			return err
		}
	} else {
		// The bindings say a reset of next is under way before it happens,
		// so a failure from here on leaves a retryable rotation, never an
		// unbound record.
		if err := r.step(StepBindingPending, agentbroker.CodeVaultFailed, func() error {
			for _, lb := range []*bound{&c.pooled, &c.direct} {
				if lb.b.PendingRole != "" || lb.b.RetiringRole != "" {
					continue // marked, or already following next
				}
				b := lb.b.clone()
				b.PendingRole = next
				rev, err := saveBindingRev(r.ctx, r.vault, b, lb.objRev)
				if err != nil {
					return err
				}
				lb.b, lb.objRev = b, rev
			}
			return nil
		}); err != nil {
			return err
		}
		if err := r.step(StepNeonResetNewRole, CodeProviderFailed, func() error {
			// Written only over the revisions just checked.
			w := r.recorder(map[string]int64{p.Records.Pooled: c.pooled.rev, p.Records.Direct: c.direct.rev})
			if err := r.neon.ResetRolePassword(r.ctx, p.ProjectID, p.BranchID, next, p.Database, w.sink(p.Records.Pooled), w.sink(p.Records.Direct)); err != nil {
				return w.check(err)
			}
			return w.require(r.res, p.Records.Pooled, p.Records.Direct) // stored durably before any destination is written
		}); err != nil {
			return err
		}
	}
	// The bindings follow the new values: next is active, old is retiring
	// until it is invalidated, and every scope about to be written is
	// recorded before the write.
	objRevs := map[string]int64{}
	if err := r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		for _, lb := range []bound{c.pooled, c.direct} {
			b, ok := lb.b.withDeployed(c.scope.deployed(lb.b.Record)...)
			if !ok {
				return fail(CodeBindingLimit)
			}
			b.RecordRevision = r.res.Records[b.Record]
			b.ActiveRole, b.RetiringRole, b.PendingRole = next, old, ""
			rev, err := saveBindingRev(r.ctx, r.vault, b, lb.objRev)
			if err != nil {
				return err
			}
			objRevs[b.Record] = rev
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.rotateScopes(c.scope, p.HealthPath); err != nil {
		return err
	}
	r.res.ActiveRole = next
	// Only after every scope passed health: the old role's password is reset
	// and discarded.
	if err := r.step(StepNeonInvalidateOld, CodeProviderFailed, func() error {
		return r.neon.ResetRolePassword(r.ctx, p.ProjectID, p.BranchID, old, p.Database, nil, nil)
	}); err != nil {
		return err
	}
	r.res.InvalidatedRole = old
	// The rotation is complete: nothing is retiring any more. (If this save
	// fails, the next rotation completes this one again, harmlessly.)
	return r.step(StepBindingFinish, agentbroker.CodeVaultFailed, func() error {
		for _, rec := range []string{p.Records.Pooled, p.Records.Direct} {
			b, objRev, err := r.vault.LoadBinding(r.ctx, rec)
			if err != nil || objRev != objRevs[rec] || b.RecordRevision != r.res.Records[rec] {
				return fail(agentbroker.CodeVaultFailed)
			}
			b.RetiringRole = ""
			if err := saveBinding(r.ctx, r.vault, b, objRev); err != nil {
				return err
			}
		}
		return nil
	})
}
