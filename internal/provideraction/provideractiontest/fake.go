// Package provideractiontest holds in-memory fakes of the provider-action
// ports, vault and clock for tests. It makes no network calls.
package provideractiontest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
)

// Sentinel returns a random, recognizable secret value.
func Sentinel(prefix string) string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "SENTINEL" + hex.EncodeToString(b)
}

// Encodings returns value and its common encodings, for leak scans.
func Encodings(value string) []string {
	b := []byte(value)
	return []string{value, base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b))}
}

// Leak returns the first value (or encoding of one) found in out, or "".
func Leak(out []byte, values ...string) string {
	s := string(out)
	for _, v := range values {
		for _, e := range Encodings(v) {
			if len(e) >= 8 && strings.Contains(s, e) {
				return e
			}
		}
		if i := strings.Index(v, "SENTINEL"); i >= 0 && strings.Contains(s, v[i:]) {
			return v[i:]
		}
	}
	return ""
}

// Log records calls in order.
type Log struct {
	mu    sync.Mutex
	calls []string
}

// Add appends one call.
func (l *Log) Add(c string) { l.mu.Lock(); l.calls = append(l.calls, c); l.mu.Unlock() }

// Calls returns a copy of the calls so far.
func (l *Log) Calls() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

// Index returns the position of the first call equal to c, or -1.
func (l *Log) Index(c string) int {
	for i, x := range l.Calls() {
		if x == c {
			return i
		}
	}
	return -1
}

// Vault is an in-memory revisioned vault.
type Vault struct {
	Log *Log

	mu   sync.Mutex
	vals map[string][]byte
	revs map[string]int64
	// FailStore makes StoreSecret fail for these records.
	FailStore map[string]bool
	// FailBinding makes SaveBinding fail for these records.
	FailBinding map[string]bool

	// Bindings and Vercel provenance, as encoded JSON (the shape the real
	// store encrypts), with optimistic object revisions.
	bindings    map[string][]byte
	bindingRevs map[string]int64
	projects    map[string][]byte
}

// NewVault returns a vault holding values (revision 1 each).
func NewVault(log *Log, values map[string]string) *Vault {
	v := &Vault{Log: log, vals: map[string][]byte{}, revs: map[string]int64{}, FailStore: map[string]bool{}, FailBinding: map[string]bool{},
		bindings: map[string][]byte{}, bindingRevs: map[string]int64{}, projects: map[string][]byte{}}
	for k, val := range values {
		v.vals[k], v.revs[k] = []byte(val), 1
	}
	return v
}

// Set stores a value directly (test setup).
func (v *Vault) Set(name, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.vals[name] = []byte(value)
	v.revs[name]++
}

// Value returns name's value (test assertions only).
func (v *Vault) Value(name string) (string, int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return string(v.vals[name]), v.revs[name]
}

func (v *Vault) StoreSecret(_ context.Context, name string, fill func(func([]byte) error) error) (int64, error) {
	v.mu.Lock()
	fail := v.FailStore[name]
	v.mu.Unlock()
	if fail {
		return 0, errors.New("store failed")
	}
	var got []byte
	if err := fill(func(b []byte) error { got = append([]byte(nil), b...); return nil }); err != nil {
		return 0, err
	}
	v.mu.Lock()
	v.vals[name] = got
	v.revs[name]++
	rev := v.revs[name]
	v.mu.Unlock()
	if v.Log != nil {
		v.Log.Add("vault.store " + name)
	}
	return rev, nil
}

func (v *Vault) ReadSecret(_ context.Context, name string, revision int64, consume func([]byte) error) error {
	v.mu.Lock()
	val, ok := v.vals[name]
	rev := v.revs[name]
	val = append([]byte(nil), val...)
	v.mu.Unlock()
	if !ok || rev != revision {
		return errors.New("revision mismatch")
	}
	return consume(val)
}

func (v *Vault) Latest(_ context.Context, name string, consume func([]byte) error) (int64, error) {
	v.mu.Lock()
	val, ok := v.vals[name]
	rev := v.revs[name]
	val = append([]byte(nil), val...)
	v.mu.Unlock()
	if !ok {
		return 0, provideraction.ErrMissing
	}
	return rev, consume(val)
}

func (v *Vault) Exists(_ context.Context, name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.vals[name]
	return ok, nil
}

// Names, Values and Store implement agentbroker.Vault, so one fake can back
// both the agent broker and the provider service (as brokerVault does).
func (v *Vault) Names(context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.vals))
	for n := range v.vals {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Vault) Values(_ context.Context, names []string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	for _, n := range names {
		val, ok := v.vals[n]
		if !ok {
			return nil, agentbroker.ErrMissing
		}
		out[n] = string(val)
	}
	return out, nil
}

func (v *Vault) Store(_ context.Context, name, value string) error {
	v.Set(name, value)
	return nil
}

// LoadBinding implements provideraction.BindingStore.
func (v *Vault) LoadBinding(_ context.Context, record string) (provideraction.Binding, int64, error) {
	v.mu.Lock()
	raw, ok := v.bindings[record]
	rev := v.bindingRevs[record]
	v.mu.Unlock()
	if !ok {
		return provideraction.Binding{}, 0, provideraction.ErrMissing
	}
	b, err := provideraction.DecodeBinding(raw)
	return b, rev, err
}

// SaveBinding implements provideraction.BindingStore.
func (v *Vault) SaveBinding(_ context.Context, b provideraction.Binding, expected int64) (int64, error) {
	if !b.Valid() {
		return 0, errors.New("invalid binding")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return 0, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.FailBinding[b.Record] {
		return 0, errors.New("binding store failed")
	}
	if v.bindingRevs[b.Record] != expected {
		return 0, errors.New("revision conflict")
	}
	v.bindings[b.Record] = raw
	v.bindingRevs[b.Record]++
	return v.bindingRevs[b.Record], nil
}

// ListBindings implements provideraction.BindingStore.
func (v *Vault) ListBindings(context.Context) ([]provideraction.StoredBinding, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []provideraction.StoredBinding
	for rec, raw := range v.bindings {
		b, err := provideraction.DecodeBinding(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, provideraction.StoredBinding{Binding: b, Revision: v.bindingRevs[rec]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Binding.Record < out[j].Binding.Record })
	return out, nil
}

// LoadVercelProject implements provideraction.BindingStore.
func (v *Vault) LoadVercelProject(_ context.Context, teamID, projectID string) (provideraction.VercelProject, error) {
	v.mu.Lock()
	raw, ok := v.projects[provideraction.VercelProjectKey(teamID, projectID)]
	v.mu.Unlock()
	if !ok {
		return provideraction.VercelProject{}, provideraction.ErrMissing
	}
	return provideraction.DecodeVercelProject(raw)
}

// SaveVercelProject implements provideraction.BindingStore.
func (v *Vault) SaveVercelProject(_ context.Context, p provideraction.VercelProject) error {
	if !p.Valid() {
		return errors.New("invalid provenance")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	key := provideraction.VercelProjectKey(p.TeamID, p.ProjectID)
	if _, ok := v.projects[key]; ok {
		return errors.New("revision conflict")
	}
	v.projects[key] = raw
	return nil
}

// Bind stores a binding directly (test setup), pinned to the record's
// current revision.
func (v *Vault) Bind(b provideraction.Binding) {
	v.mu.Lock()
	b.RecordRevision = v.revs[b.Record]
	if b.AllowedDestinations == nil {
		b.AllowedDestinations = []provideraction.Destination{}
	}
	b.V = provideraction.BindingVersion
	expected := v.bindingRevs[b.Record]
	v.mu.Unlock()
	if _, err := v.SaveBinding(context.Background(), b, expected); err != nil {
		panic(err)
	}
}

// Binding returns record's binding (test assertions only).
func (v *Vault) Binding(record string) (provideraction.Binding, bool) {
	b, _, err := v.LoadBinding(context.Background(), record)
	return b, err == nil
}

// Clock advances instantly on Sleep.
type Clock struct {
	mu sync.Mutex
	T  time.Time
}

func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.T }
func (c *Clock) Sleep(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.mu.Lock()
	c.T = c.T.Add(d)
	c.mu.Unlock()
	return nil
}

// Providers is a fake Factory whose ports log every call.
type Providers struct {
	Log *Log
	// Fail makes the call with this exact log entry fail (with an error
	// whose text carries a secret, which must never surface).
	Fail string
	// Block, if set, makes every port call wait for it to close (or ctx).
	Block chan struct{}
	// Secret is put into provider error texts.
	Secret string
	// RolesNotPrepared makes RotationRolesReady report false.
	RolesNotPrepared bool

	mu        sync.Mutex
	Creds     [][]byte          // credential slices the factory was given
	Pushed    map[string]string // env key → value read from the vault
	Issued    []string          // every secret the fakes created
	Endpoints map[string]provideraction.StripeWebhook
	// Closed counts port Close calls (each port must be closed once, when
	// its operation ends).
	Closed int
	next   int
}

// Closes returns how many ports were closed so far.
func (p *Providers) Closes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Closed
}

func (p *Providers) close() error {
	p.mu.Lock()
	p.Closed++
	p.mu.Unlock()
	return nil
}

// NewProviders returns a fake factory.
func NewProviders(log *Log) *Providers {
	return &Providers{Log: log, Secret: Sentinel("provider_error_"), Pushed: map[string]string{}, Endpoints: map[string]provideraction.StripeWebhook{}}
}

func (p *Providers) call(ctx context.Context, c string) error {
	p.Log.Add(c)
	if p.Block != nil {
		select {
		case <-p.Block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p.Fail == c {
		return fmt.Errorf("provider rejected %s: %s", c, p.Secret)
	}
	return nil
}

func (p *Providers) issue(prefix string) string {
	s := Sentinel(prefix)
	p.mu.Lock()
	p.Issued = append(p.Issued, s)
	p.mu.Unlock()
	return s
}

// IssuedSecrets returns every secret the fakes created so far.
func (p *Providers) IssuedSecrets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.Issued...)
}

func (p *Providers) id(prefix string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	return fmt.Sprintf("%s%04d", prefix, p.next)
}

func (p *Providers) keep(cred []byte) {
	p.mu.Lock()
	p.Creds = append(p.Creds, cred) // the same slice, to check it is wiped
	p.mu.Unlock()
}

// Neon implements provideraction.Factory.
func (p *Providers) Neon(cred []byte) (provideraction.NeonPort, error) {
	p.keep(cred)
	return neon{p}, nil
}

// Vercel implements provideraction.Factory.
func (p *Providers) Vercel(cred []byte) (provideraction.VercelPort, error) {
	p.keep(cred)
	return vercel{p}, nil
}

// Stripe implements provideraction.Factory.
func (p *Providers) Stripe(cred []byte) (provideraction.StripePort, error) {
	p.keep(cred)
	return stripe{p}, nil
}

type neon struct{ p *Providers }

func (n neon) Close() error { return n.p.close() }

func (n neon) uris(ctx context.Context, role, db string, pooled, direct *lifecycle.SecretSink) error {
	pw := n.p.issue("npg_")
	if _, err := pooled.StoreBytes(ctx, []byte("postgresql://"+role+":"+pw+"@ep-x-pooler.neon.tech/"+db)); err != nil {
		return err
	}
	_, err := direct.StoreBytes(ctx, []byte("postgresql://"+role+":"+pw+"@ep-x.neon.tech/"+db))
	return err
}

func (n neon) CreateProject(ctx context.Context, spec provideraction.NeonProjectSpec, pooled, direct *lifecycle.SecretSink) (provideraction.NeonProject, error) {
	if err := n.p.call(ctx, "neon.create_project "+spec.Name); err != nil {
		return provideraction.NeonProject{}, err
	}
	if err := n.uris(ctx, "neondb_owner", "neondb", pooled, direct); err != nil {
		return provideraction.NeonProject{}, err
	}
	return provideraction.NeonProject{ProjectID: "calm-sky-123456", BranchID: "br-main-1", Role: "neondb_owner", Database: "neondb"}, nil
}

func (n neon) DeleteProject(ctx context.Context, id string) error {
	return n.p.call(ctx, "neon.delete_project "+id)
}

func (n neon) PrepareRotationRoles(ctx context.Context, _, _, _, owner string, roles [2]string, adopt bool) error {
	return n.p.call(ctx, fmt.Sprintf("neon.prepare_roles %s %s,%s adopt=%v", owner, roles[0], roles[1], adopt))
}

func (n neon) RotationRolesReady(ctx context.Context, _, _, _, owner string, roles [2]string) (bool, error) {
	if err := n.p.call(ctx, fmt.Sprintf("neon.roles_ready %s %s,%s", owner, roles[0], roles[1])); err != nil {
		return false, err
	}
	return !n.p.RolesNotPrepared, nil
}

func (n neon) ResetRolePassword(ctx context.Context, _, _, role, db string, pooled, direct *lifecycle.SecretSink) error {
	if pooled == nil && direct == nil {
		if err := n.p.call(ctx, "neon.invalidate "+role); err != nil {
			return err
		}
		n.p.issue("npg_discarded_")
		return nil
	}
	if err := n.p.call(ctx, "neon.reset "+role); err != nil {
		return err
	}
	return n.uris(ctx, role, db, pooled, direct)
}

type vercel struct{ p *Providers }

func (v vercel) Close() error { return v.p.close() }

func (v vercel) CreateProject(ctx context.Context, _, name, _, _ string) (string, error) {
	if err := v.p.call(ctx, "vercel.create_project "+name); err != nil {
		return "", err
	}
	return v.p.id("prj_"), nil
}

func (v vercel) DeleteProject(ctx context.Context, _, id string) error {
	return v.p.call(ctx, "vercel.delete_project "+id)
}

func (v vercel) UpsertSensitiveEnv(ctx context.Context, env provideraction.VercelEnv, key string, value *lifecycle.SecretSource) error {
	if err := v.p.call(ctx, "vercel.upsert "+key+" "+env.Target); err != nil {
		return err
	}
	return value.WithSecret(ctx, func(b []byte) error {
		v.p.mu.Lock()
		v.p.Pushed[key] = string(b)
		v.p.mu.Unlock()
		return nil
	})
}

func (v vercel) CurrentDeployment(ctx context.Context, _, _, _ string) (string, error) {
	if err := v.p.call(ctx, "vercel.current"); err != nil {
		return "", err
	}
	return "dpl_current", nil
}

func (v vercel) Redeploy(ctx context.Context, _, _, _, source string) (string, error) {
	if err := v.p.call(ctx, "vercel.redeploy "+source); err != nil {
		return "", err
	}
	return v.p.id("dpl_new"), nil
}

func (v vercel) WaitReady(ctx context.Context, _, id string) (string, error) {
	if err := v.p.call(ctx, "vercel.wait_ready"); err != nil {
		return "", err
	}
	return "https://app-" + strings.ToLower(strings.TrimPrefix(id, "dpl_")) + ".vercel.app", nil
}

func (v vercel) CheckHealth(ctx context.Context, _, path string) error {
	return v.p.call(ctx, "vercel.health "+path)
}

type stripe struct{ p *Providers }

func (s stripe) Close() error { return s.p.close() }

func (s stripe) CreateWebhook(ctx context.Context, url string, events []string, secret *lifecycle.SecretSink) (string, error) {
	if err := s.p.call(ctx, "stripe.create"); err != nil {
		return "", err
	}
	id := s.p.id("we_new")
	if _, err := secret.StoreBytes(ctx, []byte(s.p.issue("whsec_"))); err != nil {
		return id, err
	}
	s.p.mu.Lock()
	s.p.Endpoints[id] = provideraction.StripeWebhook{URL: url, Events: append([]string(nil), events...)}
	s.p.mu.Unlock()
	return id, nil
}

func (s stripe) Webhook(ctx context.Context, id string) (provideraction.StripeWebhook, error) {
	if err := s.p.call(ctx, "stripe.webhook "+id); err != nil {
		return provideraction.StripeWebhook{}, err
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if w, ok := s.p.Endpoints[id]; ok {
		return w, nil
	}
	return provideraction.StripeWebhook{URL: "https://shop.example.com/api/stripe/webhook", Events: []string{"checkout.session.completed", "invoice.paid"}}, nil
}

func (s stripe) DeleteWebhook(ctx context.Context, id string) error {
	return s.p.call(ctx, "stripe.delete "+id)
}
