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
	id := r.res.EndpointID
	if err := r.saveEndpointProvenance(id, p.URL, id); err != nil {
		return err
	}
	return r.step(StepBindingSave, agentbroker.CodeVaultFailed, func() error {
		return replaceBinding(r.ctx, r.vault, newBinding(p.Record, ProviderStripe, KindStripeWebhookSecret, BindingResource{EndpointID: id, Lineage: id}, r.res.Records[p.Record]))
	})
}

// saveEndpointProvenance records that this broker created endpoint id.
func (r *run) saveEndpointProvenance(id, url, lineage string) error {
	return r.step(StepProvenanceSave, agentbroker.CodeVaultFailed, func() error {
		prov := StripeEndpointProvenance{V: BindingVersion, EndpointID: id, URL: url, Lineage: lineage}
		if !prov.Valid() || r.vault.SaveStripeEndpoint(r.ctx, prov) != nil {
			return fail(agentbroker.CodeVaultFailed)
		}
		return nil
	})
}

func (p *stripeWebhookDelete) summary() string {
	what := "Stripe webhook endpoint " + p.EndpointID
	if p.url != "" {
		what += " for " + p.url + ", created by this broker"
	}
	return "DELETE " + what + ", and revoke the bindings of its records (the records stay in the vault)"
}
func (p *stripeWebhookDelete) controls() []string { return []string{ControlStripe} }

// precheck: v1 deletes only endpoints this broker created.
func (p *stripeWebhookDelete) precheck(ctx context.Context, v Vault) string {
	prov, err := v.LoadStripeEndpoint(ctx, p.EndpointID)
	switch {
	case errors.Is(err, ErrMissing):
		return CodeNotCreatedByBroker
	case err != nil || prov.EndpointID != p.EndpointID:
		return agentbroker.CodeVaultFailed
	}
	p.url = prov.URL
	return ""
}
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
	return "ROTATE Stripe webhook " + p.EndpointID + ": new endpoint, same URL and events; copy bound record " + p.Record +
		" to " + p.PreviousRecord + " (bound as previous), new secret in " + p.Record + ", push both" +
		rotationText(p.Vercel, p.HealthPath) + ", then delete " + p.EndpointID
}
func (p *stripeWebhookRotate) controls() []string     { return []string{ControlStripe, ControlVercel} }
func (p *stripeWebhookRotate) liveControls() []string { return []string{ControlStripe} }

// stripeChecked is a rotation's checked bindings. prevRev is the object
// revision of previous_record's binding (0 when none); prev is its live
// binding, nil when previous_record is absent (it is created) or holds the
// secret of an endpoint already deleted (its binding was revoked by
// stripe.webhook.delete; it is overwritten). prevEndpoint is the endpoint a
// live previous_record is bound to: it must no longer exist.
type stripeChecked struct {
	cur          bound
	prev         *Binding
	prevRev      int64
	prevEndpoint string
	scope        scopePlan
}

// check: record is bound to this endpoint (its lineage's current one);
// previous_record is absent, bound as the previous secret of the same
// lineage, or that binding revoked (its endpoint deleted); every named
// scope is allowed and together they cover every scope either record was
// deployed to.
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
			c.prevRev = rev
			break
		}
		prev, code := liveBinding(ctx, v, p.PreviousRecord)
		if code != "" {
			return c, code
		}
		if !sameLineage(prev.b) {
			return c, CodeBindingMismatch
		}
		c.prev, c.prevRev = &prev.b, prev.objRev
		if prev.b.Resource.EndpointID != p.EndpointID {
			c.prevEndpoint = prev.b.Resource.EndpointID
		}
	}
	items := []scoped{{p.Record, &c.cur.b, true}, {p.PreviousRecord, c.prev, c.prev != nil}}
	if c.prev == nil {
		// Created (or overwritten) now: it inherits record's destinations.
		items[1].b = nil
	}
	if c.scope, code = planScope(p.Vercel, items); code != "" {
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
	}
	return code
}

// liveCheck: an endpoint previous_record is still bound to must be gone. If
// it still exists, an earlier rotation did not finish: its secret may still
// be in use, and overwriting previous_record would lose it.
func (p *stripeWebhookRotate) liveCheck(ctx context.Context, ps *ports) (string, *Result) {
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
		return nil
	}); err != nil {
		return err
	}
	cur := c.cur.b
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
	if err := r.saveEndpointProvenance(r.res.EndpointID, hook.URL, cur.Resource.Lineage); err != nil {
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
