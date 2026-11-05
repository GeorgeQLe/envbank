package provideraction

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

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
		// The record was absent at the precheck: created, never overwritten.
		w := r.recorder(map[string]int64{p.Record: 0})
		id, err := r.stripe.CreateWebhook(r.ctx, p.URL, append([]string(nil), p.Events...), "", w.sink(p.Record))
		if stripeEndpointRe.MatchString(id) {
			r.res.EndpointID = id // reported even on a later failure, for cleanup
		}
		if err != nil {
			return w.check(err)
		}
		if !stripeEndpointRe.MatchString(id) {
			return fail(CodeProviderResponse)
		}
		return w.require(r.res, p.Record)
	}); err != nil {
		// The endpoint exists even though its secret was not stored: its
		// provenance lets stripe.webhook.delete clean it up.
		r.keepEndpointProvenance(r.res.EndpointID, p.URL, r.res.EndpointID, p.Events, "")
		return err
	}
	id := r.res.EndpointID
	// Best effort, read-only: the API version Stripe gave the endpoint (the
	// account default), so a later rotation can pin it.
	version := ""
	if hook, err := r.stripe.Webhook(r.ctx, id); err == nil && stripeAPIVersionRe.MatchString(hook.APIVersion) {
		version = hook.APIVersion
	}
	if err := r.saveEndpointProvenance(id, p.URL, id, p.Events, version); err != nil {
		return err
	}
	return r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		return replaceBinding(r.ctx, r.vault, newBinding(p.Record, ProviderStripe, KindStripeWebhookSecret, BindingResource{EndpointID: id, Lineage: id}, r.res.Records[p.Record]))
	})
}

// saveEndpointProvenance records that this broker created endpoint id,
// with the URL and events it created it with.
func (r *run) saveEndpointProvenance(id, url, lineage string, events []string, apiVersion string) error {
	return r.step(StepProvenanceSave, agentbroker.CodeVaultFailed, func() error {
		prov := StripeEndpointProvenance{V: BindingVersion, EndpointID: id, URL: url, Lineage: lineage, Events: append([]string(nil), events...), APIVersion: apiVersion}
		if !prov.Valid() || r.vault.SaveStripeEndpoint(r.ctx, prov) != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
		return nil
	})
}

// keepEndpointProvenance is the best-effort provenance save after a failed
// create step that still created endpoint id (no step: the operation has
// already failed with that step's code).
func (r *run) keepEndpointProvenance(id, url, lineage string, events []string, apiVersion string) {
	if id == "" {
		return
	}
	prov := StripeEndpointProvenance{V: BindingVersion, EndpointID: id, URL: url, Lineage: lineage, Events: append([]string(nil), events...), APIVersion: apiVersion}
	if prov.Valid() {
		_ = r.vault.SaveStripeEndpoint(r.ctx, prov)
	}
}

func (p *stripeWebhookDelete) summary() string {
	what := "Stripe webhook endpoint " + p.EndpointID
	if p.url != "" {
		what += " for " + p.url + ", created by this broker"
	}
	return "DELETE " + what + ", and revoke the bindings of its records (the records stay in the vault)"
}
func (p *stripeWebhookDelete) controls() []string { return []string{ControlStripe} }

// current: the binding of a record holding this endpoint's current secret.
// (A previous secret of the same endpoint is not checked: deleting the
// orphan of an interrupted rotation must stay possible, and its
// deployments also hold the current secret.)
func (p *stripeWebhookDelete) current(b Binding) bool {
	return b.Provider == ProviderStripe && b.Kind == KindStripeWebhookSecret && b.Resource.EndpointID == p.EndpointID
}

// precheck: v1 deletes only endpoints this broker created, and only once
// its current secret is no longer deployed (vercel.env.remove).
func (p *stripeWebhookDelete) precheck(ctx context.Context, v Vault) string {
	prov, err := v.LoadStripeEndpoint(ctx, p.EndpointID)
	switch {
	case errors.Is(err, ErrMissing):
		return CodeNotCreatedByBroker
	case err != nil || prov.EndpointID != p.EndpointID:
		return agentbroker.CodeVaultFailed
	}
	p.url = prov.URL
	return stillDeployed(ctx, v, p.current)
}
func (p *stripeWebhookDelete) execute(r *run) error {
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		if code := stillDeployed(r.ctx, r.vault, p.current); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
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

// summary is terse: the whole plan must fit the Touch ID prompt
// (docs/provider-actions.md, "Approval text budget"). The URL and event
// count come from the endpoint's provenance (precheck); the new endpoint is
// created with exactly those.
func (p *stripeWebhookRotate) summary() string {
	what := p.EndpointID
	if p.url != "" {
		what += " (" + p.url + ", " + strconv.Itoa(len(p.events)) + " events)"
	}
	return "ROTATE Stripe webhook " + what + " to a copy: new secret into " + p.Record + ", old kept in " + p.PreviousRecord +
		rotationText(p.Vercel, p.HealthPath) + "; then DELETE the old one"
}
func (p *stripeWebhookRotate) controls() []string     { return []string{ControlStripe, ControlVercel} }
func (p *stripeWebhookRotate) liveControls() []string { return []string{ControlStripe, ControlVercel} }

// stripeChecked is a rotation's checked bindings. prevRev is the object
// revision of previous_record's binding (0 when none) and prevRecRev the
// record revision previous_record is written over (0: absent); prev is its
// live binding, nil when previous_record is absent (it is created) or holds
// the secret of an endpoint already deleted (its binding was revoked by
// stripe.webhook.delete; it is overwritten). prevEndpoint is the endpoint a
// live previous_record is bound to: it must no longer exist. prov is the
// endpoint's provenance.
type stripeChecked struct {
	cur          bound
	prev         *Binding
	prevRev      int64
	prevRecRev   int64
	prevEndpoint string
	prov         StripeEndpointProvenance
	scope        scopePlan
}

// check: record is bound to this endpoint (its lineage's current one),
// which this broker created with recorded URL and events; previous_record
// is absent, bound as the previous secret of the same lineage, or that
// binding revoked (its endpoint deleted); every named scope is allowed and
// together they cover every scope either record was deployed to.
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
	c.cur = cur
	prov, err := v.LoadStripeEndpoint(ctx, p.EndpointID)
	switch {
	case errors.Is(err, ErrMissing):
		return c, CodeNotCreatedByBroker
	case err != nil || prov.EndpointID != p.EndpointID:
		return c, agentbroker.CodeVaultFailed
	case prov.Lineage != cur.b.Resource.Lineage:
		return c, CodeBindingMismatch
	case prov.Events == nil:
		return c, CodeStripeEndpointDrift // recorded before events were: not recreatable as approved
	}
	c.prov = prov
	exists, err := v.Exists(ctx, p.PreviousRecord)
	if err != nil {
		return c, agentbroker.CodeVaultFailed
	}
	sameLineage := func(b Binding) bool {
		return b.Provider == ProviderStripe && b.Kind == KindStripeWebhookSecretPrevious && b.Resource.Lineage == cur.b.Resource.Lineage
	}
	switch {
	case !exists:
		_, rev, err := v.LoadBinding(ctx, p.PreviousRecord)
		switch {
		case errors.Is(err, ErrMissing):
		case err != nil:
			return c, agentbroker.CodeVaultFailed
		default:
			c.prevRev = rev // a stale object for an absent record is replaced
		}
	default:
		b, rev, err := v.LoadBinding(ctx, p.PreviousRecord)
		if err == nil && b.Revoked && sameLineage(b) {
			// The previous secret's endpoint was deleted: the value is dead
			// and is overwritten, as long as nothing else rewrote it.
			if r, err := v.Revision(ctx, p.PreviousRecord); err != nil || r != b.RecordRevision {
				return c, CodeRecordNotBound
			}
			c.prevRev, c.prevRecRev = rev, b.RecordRevision
			break
		}
		prev, code := liveBinding(ctx, v, p.PreviousRecord)
		if code != "" {
			return c, code
		}
		if !sameLineage(prev.b) {
			return c, CodeBindingMismatch
		}
		c.prev, c.prevRev, c.prevRecRev = &prev.b, prev.objRev, prev.b.RecordRevision
		if prev.b.Resource.EndpointID != p.EndpointID {
			c.prevEndpoint = prev.b.Resource.EndpointID
		}
	}
	items := []scoped{{p.Record, &c.cur.b, true}, {p.PreviousRecord, c.prev, c.prev != nil}}
	if c.prev == nil {
		// Created (or overwritten) now: it inherits record's destinations.
		items[1].b = nil
	}
	claims, code := envClaims(ctx, v)
	if code != "" {
		return c, code
	}
	if c.scope, code = planScope(p.Vercel, items, claims); code != "" {
		return c, code
	}
	if !c.scope.fits(c.cur.b, p.Record) {
		return c, CodeBindingLimit
	}
	if c.prev != nil && !c.scope.fits(*c.prev, p.PreviousRecord) {
		return c, CodeBindingLimit
	}
	return c, ""
}

func (p *stripeWebhookRotate) precheck(ctx context.Context, v Vault) string {
	c, code := p.check(ctx, v)
	if code == "" {
		p.prevEndpoint = c.prevEndpoint
		p.url, p.events = c.prov.URL, append([]string(nil), c.prov.Events...)
		p.fresh, p.recordedVersion = c.scope.fresh, c.prov.APIVersion
	}
	return code
}

// sameEndpoint: hook has exactly the URL and event set of prov.
func sameEndpoint(hook StripeWebhook, prov StripeEndpointProvenance) bool {
	if hook.URL != prov.URL || len(hook.Events) != len(prov.Events) {
		return false
	}
	want := map[string]bool{}
	for _, e := range prov.Events {
		want[e] = true
	}
	for _, e := range hook.Events {
		if !want[e] {
			return false
		}
		delete(want, e)
	}
	return len(want) == 0
}

// readEndpoint reads the live endpoint and refuses drift from what this
// broker created (STRIPE_ENDPOINT_DRIFT): another URL or event set, a
// disabled endpoint, an API version other than the recorded one, or one
// that is not a valid version string.
func readEndpoint(ctx context.Context, s StripePort, id string, prov StripeEndpointProvenance) (StripeWebhook, string) {
	hook, err := s.Webhook(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return StripeWebhook{}, CodeStripeEndpointDrift
		}
		return StripeWebhook{}, CodeProviderFailed
	}
	if !sameEndpoint(hook, prov) || hook.Status != "enabled" ||
		(hook.APIVersion != "" && !stripeAPIVersionRe.MatchString(hook.APIVersion)) ||
		(prov.APIVersion != "" && hook.APIVersion != prov.APIVersion) {
		return StripeWebhook{}, CodeStripeEndpointDrift
	}
	return hook, ""
}

// liveCheck: the endpoint still has the URL and events the approval names,
// and an endpoint previous_record is still bound to must be gone. If it
// still exists, an earlier rotation did not finish: its secret may still be
// in use, and overwriting previous_record would lose it.
func (p *stripeWebhookRotate) liveCheck(ctx context.Context, ps *ports) (string, *Result) {
	prov := StripeEndpointProvenance{EndpointID: p.EndpointID, URL: p.url, Events: p.events, APIVersion: p.recordedVersion}
	hook, code := readEndpoint(ctx, ps.stripe, p.EndpointID, prov)
	if code != "" {
		return code, nil
	}
	p.apiVersion = hook.APIVersion
	if code := freshAbsent(ctx, ps.vercel, p.Vercel, p.fresh); code != "" {
		return code, nil
	}
	if p.prevEndpoint == "" {
		return "", nil
	}
	_, err := ps.stripe.Webhook(ctx, p.prevEndpoint)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", nil
	case err != nil:
		return CodeProviderFailed, nil
	}
	return CodeStripeOrphanEndpoint, &Result{OrphanEndpointID: p.prevEndpoint}
}

// execute keeps the old endpoint (and its secret, now also in
// PreviousRecord) valid until the new secret is stored, pushed to every
// scope, deployed and healthy; only then is the old endpoint deleted.
func (p *stripeWebhookRotate) execute(r *run) error {
	var c stripeChecked
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if c, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		if c.prevEndpoint != p.prevEndpoint {
			return fail(CodeBindingMismatch) // changed since the owner approved
		}
		if c.prov.URL != p.url || !sameEndpoint(StripeWebhook{URL: p.url, Events: p.events}, c.prov) || c.prov.APIVersion != p.recordedVersion {
			return fail(CodeStripeEndpointDrift)
		}
		return nil
	}); err != nil {
		return err
	}
	cur := c.cur.b
	if err := r.step(StepStripeReadEndpoint, CodeProviderFailed, func() error {
		hook, code := readEndpoint(r.ctx, r.stripe, p.EndpointID, c.prov)
		if code != "" {
			return fail(code)
		}
		if hook.APIVersion != p.apiVersion {
			return fail(CodeStripeEndpointDrift) // changed since the owner approved
		}
		return nil
	}); err != nil {
		return err
	}
	if prod, ok := p.Vercel.production(); ok {
		if err := r.productionBaseline(prod); err != nil {
			return err
		}
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
		// Written only over the revision checked (0: created).
		rev, err := r.vault.StoreSecretAt(r.ctx, p.PreviousRecord, c.prevRecRev, func(consume func([]byte) error) error {
			view := append([]byte(nil), current...)
			defer wipe(view)
			return consume(view)
		})
		if errors.Is(err, ErrRecordChanged) {
			return fail(CodeRecordChanged)
		}
		if err != nil || rev < 1 {
			return fail(agentbroker.CodeVaultFailed)
		}
		r.res.record(p.PreviousRecord, rev)
		// previous_record holds the value record held, so it inherits its
		// lineage and allowed destinations; its deployed_to is its own (kept
		// when it was live) plus what this rotation writes.
		prev := cur.clone()
		prev.Record, prev.Kind, prev.RecordRevision, prev.Revoked = p.PreviousRecord, KindStripeWebhookSecretPrevious, rev, false
		prev.DeployedTo = nil
		if c.prev != nil {
			prev.DeployedTo = append([]Deployed(nil), c.prev.DeployedTo...)
		}
		prev, ok := prev.withDeployed(c.scope.deployed(p.PreviousRecord)...)
		if !ok {
			return fail(CodeBindingLimit)
		}
		return saveBinding(r.ctx, r.vault, prev, c.prevRev)
	}); err != nil {
		return err
	}
	if err := r.step(StepStripeCreate, CodeProviderFailed, func() error {
		w := r.recorder(map[string]int64{p.Record: cur.RecordRevision})
		id, err := r.stripe.CreateWebhook(r.ctx, c.prov.URL, append([]string(nil), c.prov.Events...), p.apiVersion, w.sink(p.Record))
		if stripeEndpointRe.MatchString(id) && id != p.EndpointID {
			r.res.EndpointID = id
		}
		if err != nil {
			return w.check(err)
		}
		if !stripeEndpointRe.MatchString(id) || id == p.EndpointID {
			return fail(CodeProviderResponse)
		}
		return w.require(r.res, p.Record)
	}); err != nil {
		r.keepEndpointProvenance(r.res.EndpointID, c.prov.URL, cur.Resource.Lineage, c.prov.Events, p.apiVersion)
		return err
	}
	if err := r.saveEndpointProvenance(r.res.EndpointID, c.prov.URL, cur.Resource.Lineage, c.prov.Events, p.apiVersion); err != nil {
		return err
	}
	// The record's binding moves to the new endpoint (same lineage); every
	// scope about to be written is recorded first.
	if err := r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		b, ok := cur.withDeployed(c.scope.deployed(p.Record)...)
		if !ok {
			return fail(CodeBindingLimit)
		}
		b.Resource.EndpointID, b.RecordRevision = r.res.EndpointID, r.res.Records[p.Record]
		return saveBinding(r.ctx, r.vault, b, c.cur.objRev)
	}); err != nil {
		return err
	}
	if err := r.rotateScopes(c.scope, p.HealthPath); err != nil {
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
