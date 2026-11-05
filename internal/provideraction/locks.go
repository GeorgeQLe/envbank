package provideraction

import (
	"context"
	"sort"
)

// CodeResourceBusy: another operation (running, or waiting for its owner's
// approval) holds a provider resource or record this action would change.
// It is refused before any prompt; retry when that operation has finished.
const CodeResourceBusy = "RESOURCE_BUSY"

// Resource lock keys. Two operations that share a key never run, or wait
// for approval, at the same time.
func lockNeon(projectID string) string           { return "neon:" + projectID }
func lockVercel(teamID, projectID string) string { return "vercel:" + teamID + "/" + projectID }
func lockVercelName(teamID, name string) string  { return "vercel-name:" + teamID + "/" + name }
func lockStripeLineage(lineage string) string    { return "stripe-lineage:" + lineage }
func lockStripeEndpoint(id string) string        { return "stripe-endpoint:" + id }
func lockRecord(name string) string              { return "record:" + name }

// stripeLineage is the lineage an endpoint's live bindings name, or "" when
// none does. Read-only; any vault failure is treated as "unknown" and the
// endpoint key alone still serializes the endpoint.
func stripeLineage(ctx context.Context, v Vault, endpointID string) string {
	all, err := v.ListBindings(ctx)
	if err != nil {
		return ""
	}
	for _, sb := range all {
		b := sb.Binding
		if b.Provider == ProviderStripe && b.Resource.EndpointID == endpointID && b.Resource.Lineage != "" {
			return b.Resource.Lineage
		}
	}
	return ""
}

func stripeKeys(ctx context.Context, v Vault, endpointID string) []string {
	keys := []string{lockStripeEndpoint(endpointID)}
	if lineage := stripeLineage(ctx, v, endpointID); lineage != "" {
		keys = append(keys, lockStripeLineage(lineage))
	}
	return keys
}

func (p *neonProjectCreate) resources(context.Context, Vault) []string {
	return []string{lockRecord(p.Records.Pooled), lockRecord(p.Records.Direct)}
}
func (p *neonRolesPrepare) resources(context.Context, Vault) []string {
	return []string{lockNeon(p.ProjectID)}
}
func (p *neonProjectDelete) resources(context.Context, Vault) []string {
	return []string{lockNeon(p.ProjectID)}
}

// vercelKeys locks every Vercel project a rotation writes to.
func vercelKeys(refs VercelRefs) []string {
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		keys = append(keys, lockVercel(ref.TeamID, ref.ProjectID))
	}
	return keys
}

func (p *neonRotate) resources(context.Context, Vault) []string {
	return append([]string{lockNeon(p.ProjectID), lockRecord(p.Records.Pooled), lockRecord(p.Records.Direct)}, vercelKeys(p.Vercel)...)
}
func (p *vercelProjectCreate) resources(context.Context, Vault) []string {
	return []string{lockVercelName(p.TeamID, p.Name)}
}
func (p *vercelProjectDelete) resources(context.Context, Vault) []string {
	return []string{lockVercel(p.TeamID, p.ProjectID)}
}

// providerKeys locks the provider resource record's binding names (any
// binding, revoked included), so a project or endpoint delete cannot run
// between a push's or remove's checks and its write. Read-only; a vault
// failure locks nothing extra (the action's own checks then refuse).
func providerKeys(ctx context.Context, v Vault, record string) []string {
	b, _, err := v.LoadBinding(ctx, record)
	if err != nil {
		return nil
	}
	switch b.Provider {
	case ProviderNeon:
		if b.Resource.ProjectID != "" {
			return []string{lockNeon(b.Resource.ProjectID)}
		}
	case ProviderStripe:
		if b.Resource.EndpointID != "" {
			return stripeKeys(ctx, v, b.Resource.EndpointID)
		}
	}
	return nil
}

// env.push also locks every record it pushes and its provider resource,
// and every record claiming an env var it may replace (their bindings
// change), so no rotation or delete of them runs meanwhile.
func (p *vercelEnvPush) resources(ctx context.Context, v Vault) []string {
	keys := []string{lockVercel(p.TeamID, p.ProjectID)}
	for _, rec := range p.recordNames() {
		keys = append(keys, lockRecord(rec))
		keys = append(keys, providerKeys(ctx, v, rec)...)
	}
	if claims, code := envClaims(ctx, v); code == "" {
		for _, env := range p.envNames() {
			for _, owner := range claims[Deployed{DeployTarget: p.ref().deployTarget(), Env: env}] {
				keys = append(keys, lockRecord(owner))
			}
		}
	}
	return keys
}
func (p *vercelEnvRemove) resources(ctx context.Context, v Vault) []string {
	return append([]string{lockVercel(p.TeamID, p.ProjectID), lockRecord(p.Record)}, providerKeys(ctx, v, p.Record)...)
}
func (p *vercelRedeploy) resources(context.Context, Vault) []string {
	return []string{lockVercel(p.TeamID, p.ProjectID)}
}
func (p *stripeWebhookCreate) resources(context.Context, Vault) []string {
	return []string{lockRecord(p.Record)}
}
func (p *stripeWebhookRotate) resources(ctx context.Context, v Vault) []string {
	keys := append(stripeKeys(ctx, v, p.EndpointID), lockRecord(p.Record), lockRecord(p.PreviousRecord))
	return append(keys, vercelKeys(p.Vercel)...)
}
func (p *stripeWebhookDelete) resources(ctx context.Context, v Vault) []string {
	return stripeKeys(ctx, v, p.EndpointID)
}
func (p *bindingAllow) resources(context.Context, Vault) []string {
	keys := make([]string, 0, len(p.Records))
	for _, rec := range p.records() {
		keys = append(keys, lockRecord(rec))
	}
	return keys
}

// lease holds resource keys until released (idempotent).
type lease struct {
	e    *Executor
	keys []string
	done bool
}

// lock takes every key or none: RESOURCE_BUSY if another operation holds
// any of them.
func (e *Executor) lock(keys []string) (*lease, string) {
	uniq := map[string]bool{}
	for _, k := range keys {
		uniq[k] = true
	}
	sorted := make([]string, 0, len(uniq))
	for k := range uniq {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, k := range sorted {
		if e.locks[k] {
			return nil, CodeResourceBusy
		}
	}
	for _, k := range sorted {
		e.locks[k] = true
	}
	return &lease{e: e, keys: sorted}, ""
}

func (l *lease) release() {
	if l == nil {
		return
	}
	l.e.mu.Lock()
	defer l.e.mu.Unlock()
	l.releaseLocked()
}

func (l *lease) releaseLocked() {
	if l == nil || l.done {
		return
	}
	l.done = true
	for _, k := range l.keys {
		delete(l.e.locks, k)
	}
}
