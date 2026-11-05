package provideraction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

// Record bindings (provenance). When a provider action creates a record, the
// broker stores a binding beside it as an encrypted vault object (never a
// record, so names, run and request cannot reach it): which provider
// resource the value belongs to, its kind, the record revision the broker
// stored, and the Vercel projects it may be deployed to. Only this service
// writes bindings, and only inside an owner-approved operation.
//
//   - A push (vercel.env.push and the composite pushes) needs a live binding
//     whose allowed_destinations hold the target (team_id, project_id).
//   - A destination is added only by binding.allow, whose own approval text
//     names the records and the project.
//   - A rotation overwrites only records bound to the same provider resource
//     with the matching kinds.
//   - A binding is live when it exists, is not revoked, and its
//     record_revision is the record's current revision: a value written by
//     anything else (owner entry, import) is not bound.

// Binding kinds.
const (
	KindNeonPooled                  = "neon.pooled"
	KindNeonDirect                  = "neon.direct"
	KindStripeWebhookSecret         = "stripe.webhook_secret"
	KindStripeWebhookSecretPrevious = "stripe.webhook_secret_previous"
)

// Binding providers.
const (
	ProviderNeon   = "neon"
	ProviderStripe = "stripe"
)

// BindingVersion is the binding payload schema version.
const BindingVersion = 1

// MaxAllowedDestinations bounds a binding's allowed_destinations.
const MaxAllowedDestinations = 16

// maxAllowRecords bounds the records one binding.allow names.
const maxAllowRecords = 16

// Destination is a Vercel project a bound record may be deployed to (every
// target of the project, production included).
type Destination struct {
	TeamID    string `json:"team_id"`
	ProjectID string `json:"project_id"`
}

func (d Destination) valid() bool {
	return vercelTeamRe.MatchString(d.TeamID) && vercelProjectRe.MatchString(d.ProjectID)
}

// BindingResource is the provider resource a record's value belongs to.
// Neon: ProjectID and BranchID. Stripe: EndpointID (the endpoint whose
// signing secret the record holds) and Lineage (the first endpoint of its
// rotation chain; rotations keep it).
type BindingResource struct {
	ProjectID  string `json:"project_id,omitempty"`
	BranchID   string `json:"branch_id,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Lineage    string `json:"lineage,omitempty"`
}

// Binding is one record's provenance (value-free).
type Binding struct {
	V                   int             `json:"v"`
	Record              string          `json:"record"`
	Provider            string          `json:"provider"`
	Kind                string          `json:"kind"`
	Resource            BindingResource `json:"resource"`
	RecordRevision      int64           `json:"record_revision"`
	AllowedDestinations []Destination   `json:"allowed_destinations"`
	Revoked             bool            `json:"revoked,omitempty"`
}

// Valid reports whether b is a well-formed binding.
func (b Binding) Valid() bool {
	if b.V != BindingVersion || !validRecord(b.Record) || b.RecordRevision < 1 || b.AllowedDestinations == nil ||
		len(b.AllowedDestinations) > MaxAllowedDestinations {
		return false
	}
	r := b.Resource
	switch b.Kind {
	case KindNeonPooled, KindNeonDirect:
		if b.Provider != ProviderNeon || !neonProjectRe.MatchString(r.ProjectID) || !neonBranchRe.MatchString(r.BranchID) || r.EndpointID != "" || r.Lineage != "" {
			return false
		}
	case KindStripeWebhookSecret, KindStripeWebhookSecretPrevious:
		if b.Provider != ProviderStripe || !stripeEndpointRe.MatchString(r.EndpointID) || !stripeEndpointRe.MatchString(r.Lineage) || r.ProjectID != "" || r.BranchID != "" {
			return false
		}
	default:
		return false
	}
	seen := map[Destination]bool{}
	for _, d := range b.AllowedDestinations {
		if !d.valid() || seen[d] {
			return false
		}
		seen[d] = true
	}
	return true
}

func (b Binding) allows(d Destination) bool {
	for _, x := range b.AllowedDestinations {
		if x == d {
			return true
		}
	}
	return false
}

func (b Binding) clone() Binding {
	c := b
	c.AllowedDestinations = append([]Destination{}, b.AllowedDestinations...)
	return c
}

// DecodeBinding strictly decodes and validates a stored binding payload.
func DecodeBinding(raw []byte) (Binding, error) {
	var b Binding
	if decodeStrictBytes(raw, &b) != nil || !b.Valid() {
		return Binding{}, errors.New("provider binding is invalid")
	}
	return b, nil
}

// VercelProject records that this broker created a Vercel project
// (provenance only: it allows no record to be deployed there).
type VercelProject struct {
	V         int    `json:"v"`
	TeamID    string `json:"team_id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

// Valid reports whether p is well formed.
func (p VercelProject) Valid() bool {
	return p.V == BindingVersion && vercelTeamRe.MatchString(p.TeamID) && vercelProjectRe.MatchString(p.ProjectID) && vercelNameRe.MatchString(p.Name)
}

// DecodeVercelProject strictly decodes and validates a stored provenance payload.
func DecodeVercelProject(raw []byte) (VercelProject, error) {
	var p VercelProject
	if decodeStrictBytes(raw, &p) != nil || !p.Valid() {
		return VercelProject{}, errors.New("vercel project provenance is invalid")
	}
	return p, nil
}

// VercelProjectKey is the vault-object key of a project's provenance.
func VercelProjectKey(teamID, projectID string) string { return teamID + "/" + projectID }

// StoredBinding is a binding with its vault-object revision.
type StoredBinding struct {
	Binding  Binding
	Revision int64
}

// BindingStore keeps bindings and Vercel provenance durably and encrypted
// in the vault (vault objects, not records). Only the provider service
// writes to it.
type BindingStore interface {
	// LoadBinding returns record's binding and its object revision, or
	// ErrMissing.
	LoadBinding(ctx context.Context, record string) (Binding, int64, error)
	// SaveBinding creates (expected 0) or replaces (expected = the loaded
	// object revision) b, failing on a revision conflict.
	SaveBinding(ctx context.Context, b Binding, expected int64) (int64, error)
	ListBindings(ctx context.Context) ([]StoredBinding, error)
	// LoadVercelProject returns a project's provenance, or ErrMissing.
	LoadVercelProject(ctx context.Context, teamID, projectID string) (VercelProject, error)
	SaveVercelProject(ctx context.Context, p VercelProject) error
}

func decodeStrictBytes(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

// ---- checks (used before the prompt and again as an operation's first step) ----

// bound is a live binding as checked.
type bound struct {
	b      Binding
	objRev int64
}

// liveBinding loads record's binding and checks it is live: present, not
// revoked, and pinned to the record's current revision.
func liveBinding(ctx context.Context, v Vault, record string) (bound, string) {
	b, objRev, err := v.LoadBinding(ctx, record)
	if errors.Is(err, ErrMissing) {
		return bound{}, CodeRecordNotBound
	}
	if err != nil || b.Record != record || !b.Valid() {
		return bound{}, agentbroker.CodeVaultFailed
	}
	if b.Revoked {
		return bound{}, CodeRecordNotBound
	}
	rev, err := v.Latest(ctx, record, func([]byte) error { return nil })
	if errors.Is(err, ErrMissing) {
		return bound{}, agentbroker.CodeUnknownSecret
	}
	if err != nil {
		return bound{}, agentbroker.CodeVaultFailed
	}
	if rev != b.RecordRevision {
		return bound{}, CodeRecordNotBound // written by something other than this broker
	}
	return bound{b: b, objRev: objRev}, ""
}

// boundForPush checks that every record may be deployed to dest.
func boundForPush(ctx context.Context, v Vault, dest Destination, records ...string) (map[string]bound, string) {
	out := make(map[string]bound, len(records))
	for _, rec := range records {
		lb, code := liveBinding(ctx, v, rec)
		if code != "" {
			return nil, code
		}
		if !lb.b.allows(dest) {
			return nil, CodeDestinationNotAllowed
		}
		out[rec] = lb
	}
	return out, ""
}

// boundToNeon checks a record is bound to exactly this Neon project and branch
// with kind.
func boundToNeon(ctx context.Context, v Vault, record, kind, projectID, branchID string) (bound, string) {
	lb, code := liveBinding(ctx, v, record)
	if code != "" {
		return bound{}, code
	}
	if lb.b.Provider != ProviderNeon || lb.b.Kind != kind || lb.b.Resource.ProjectID != projectID || lb.b.Resource.BranchID != branchID {
		return bound{}, CodeBindingMismatch
	}
	return lb, ""
}

// replaceBinding stores b for a record this operation just created (the
// record did not exist, so any old binding object under its name is stale).
func replaceBinding(ctx context.Context, v Vault, b Binding) error {
	_, objRev, err := v.LoadBinding(ctx, b.Record)
	if err != nil && !errors.Is(err, ErrMissing) {
		return fail(agentbroker.CodeVaultFailed)
	}
	if errors.Is(err, ErrMissing) {
		objRev = 0
	}
	return saveBinding(ctx, v, b, objRev)
}

func saveBinding(ctx context.Context, v Vault, b Binding, expected int64) error {
	if !b.Valid() {
		return fail(agentbroker.CodeVaultFailed)
	}
	if _, err := v.SaveBinding(ctx, b, expected); err != nil {
		return fail(agentbroker.CodeVaultFailed)
	}
	return nil
}

// newBinding is a fresh binding with no allowed destination.
func newBinding(record, provider, kind string, res BindingResource, rev int64) Binding {
	return Binding{V: BindingVersion, Record: record, Provider: provider, Kind: kind, Resource: res, RecordRevision: rev, AllowedDestinations: []Destination{}}
}

// revokeBindings marks every live binding match selects revoked and returns
// the record names, sorted. Records are never deleted.
func revokeBindings(ctx context.Context, v Vault, match func(Binding) bool) ([]string, error) {
	all, err := v.ListBindings(ctx)
	if err != nil {
		return nil, fail(agentbroker.CodeVaultFailed)
	}
	var names []string
	for _, sb := range all {
		if sb.Binding.Revoked || !match(sb.Binding) {
			continue
		}
		b := sb.Binding.clone()
		b.Revoked = true
		if err := saveBinding(ctx, v, b, sb.Revision); err != nil {
			return names, err
		}
		names = append(names, b.Record)
	}
	sort.Strings(names)
	return names, nil
}

// ---- binding.allow ----

type bindingAllow struct {
	Records   []string `json:"records"`
	TeamID    string   `json:"team_id"`
	ProjectID string   `json:"project_id"`
	// brokerCreated is set by precheck from the project's provenance.
	brokerCreated bool
}

func (p *bindingAllow) validate() bool {
	if len(p.Records) == 0 || len(p.Records) > maxAllowRecords || !p.dest().valid() {
		return false
	}
	seen := map[string]bool{}
	for _, r := range p.Records {
		if !validRecord(r) || seen[r] {
			return false
		}
		seen[r] = true
	}
	return true
}

func (p *bindingAllow) dest() Destination {
	return Destination{TeamID: p.TeamID, ProjectID: p.ProjectID}
}

func (p *bindingAllow) records() []string {
	out := append([]string(nil), p.Records...)
	sort.Strings(out)
	return out
}

func (p *bindingAllow) summary() string {
	origin := "NOT created by this broker"
	if p.brokerCreated {
		origin = "created by this broker"
	}
	return "ALLOW records " + strings.Join(p.records(), ", ") + " to be deployed to Vercel project " + p.ProjectID + " (" + p.TeamID +
		"), every target including PRODUCTION; code deployed there can read their values. Project " + origin
}
func (p *bindingAllow) controls() []string { return nil }

func (p *bindingAllow) check(ctx context.Context, v Vault) (map[string]bound, string) {
	out := map[string]bound{}
	for _, rec := range p.records() {
		lb, code := liveBinding(ctx, v, rec)
		if code != "" {
			return nil, code
		}
		if !lb.b.allows(p.dest()) && len(lb.b.AllowedDestinations) >= MaxAllowedDestinations {
			return nil, CodeBindingLimit
		}
		out[rec] = lb
	}
	return out, ""
}

func (p *bindingAllow) precheck(ctx context.Context, v Vault) string {
	if _, code := p.check(ctx, v); code != "" {
		return code
	}
	_, err := v.LoadVercelProject(ctx, p.TeamID, p.ProjectID)
	switch {
	case err == nil:
		p.brokerCreated = true
	case errors.Is(err, ErrMissing):
		p.brokerCreated = false
	default:
		return agentbroker.CodeVaultFailed
	}
	return ""
}

func (p *bindingAllow) execute(r *run) error {
	var checked map[string]bound
	if err := r.step(StepBindingCheck, agentbroker.CodeVaultFailed, func() error {
		var code string
		if checked, code = p.check(r.ctx, r.vault); code != "" {
			return fail(code)
		}
		return nil
	}); err != nil {
		return err
	}
	return r.step(StepBindingAllow, agentbroker.CodeVaultFailed, func() error {
		for _, rec := range p.records() {
			lb := checked[rec]
			b := lb.b.clone()
			if !b.allows(p.dest()) {
				b.AllowedDestinations = append(b.AllowedDestinations, p.dest())
				if err := saveBinding(r.ctx, r.vault, b, lb.objRev); err != nil {
					return err
				}
			}
			r.res.record(rec, b.RecordRevision)
		}
		r.res.TeamID, r.res.ProjectID = p.TeamID, p.ProjectID
		return nil
	})
}
