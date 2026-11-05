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
func (p *neonRotate) resources(context.Context, Vault) []string {
	return []string{lockNeon(p.ProjectID), lockVercel(p.Vercel.TeamID, p.Vercel.ProjectID),
		lockRecord(p.Records.Pooled), lockRecord(p.Records.Direct)}
}
func (p *vercelProjectCreate) resources(context.Context, Vault) []string {
	return []string{lockVercelName(p.TeamID, p.Name)}
}
func (p *vercelProjectDelete) resources(context.Context, Vault) []string {
	return []string{lockVercel(p.TeamID, p.ProjectID)}
}
func (p *vercelEnvPush) resources(context.Context, Vault) []string {
	return []string{lockVercel(p.TeamID, p.ProjectID)}
}
func (p *vercelRedeploy) resources(context.Context, Vault) []string {
	return []string{lockVercel(p.TeamID, p.ProjectID)}
}
func (p *stripeWebhookCreate) resources(context.Context, Vault) []string {
	return []string{lockRecord(p.Record)}
}
func (p *stripeWebhookRotate) resources(ctx context.Context, v Vault) []string {
	return append(stripeKeys(ctx, v, p.EndpointID), lockVercel(p.Vercel.TeamID, p.Vercel.ProjectID),
		lockRecord(p.Record), lockRecord(p.PreviousRecord))
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
