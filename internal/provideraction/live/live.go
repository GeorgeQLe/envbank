// Package live is the production provideraction.Factory: it maps the
// provider-action ports onto the concrete Neon, Vercel and Stripe adapters
// (internal/provider/...).
//
// Endpoints are fixed: every adapter is built with its default production
// endpoint (https://console.neon.tech/api/v2, https://api.vercel.com,
// https://api.stripe.com). New takes no endpoint, client or transport, so no
// flag, config or agent input can redirect a control credential. The
// loopback overrides the synthetic end-to-end test needs are an unexported
// field set only from this package's _test.go files, which are never
// compiled into the binary.
//
// Credentials: each port is built from the broker's credential buffer for
// one operation. The adapters copy the bytes they send; Close wipes every
// such copy, and the service closes each port before it wipes its buffer.
package live

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/neon"
	"github.com/GeorgeQLe/envbank/internal/provider/stripe"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
)

// Config is the owner's non-secret provider configuration (broker flags).
type Config struct {
	// NeonOrgID, when set (org-…), creates Neon projects in that
	// organization. Leave empty for an organization API key whose org is
	// implied, or a personal key.
	NeonOrgID string
}

var orgIDPattern = regexp.MustCompile(`^org-[a-z0-9]+(?:-[a-z0-9]+){0,7}$`)

// ValidNeonOrgID reports whether id is a Neon organization ID (org-…).
func ValidNeonOrgID(id string) bool { return len(id) <= 64 && orgIDPattern.MatchString(id) }

// Factory builds per-operation ports with production endpoints.
type Factory struct {
	cfg Config
	ep  testEndpoints // zero in production; see package doc
}

// testEndpoints redirect the adapters to loopback fakes. Only this
// package's tests set it.
type testEndpoints struct {
	neon, vercel, stripe string
	// health replaces the health-check transport (the fake deployment).
	health http.RoundTripper
	// neonSQL replaces the Neon adapter's Postgres connector.
	neonSQL func(ctx context.Context, uri []byte, readOnly bool) (neon.SQLSession, error)
	// waitReady bounds Vercel WaitReady (default defaultWaitReady).
	waitReady time.Duration
}

var _ provideraction.Factory = (*Factory)(nil)

// New returns the production factory.
func New(cfg Config) (*Factory, error) {
	if cfg.NeonOrgID != "" && !ValidNeonOrgID(cfg.NeonOrgID) {
		return nil, errors.New("Neon organization ID must look like org-…")
	}
	return &Factory{cfg: cfg}, nil
}

// errClosed: a port used after its operation ended.
var errClosed = provider.NewError("port", 0, "CLOSED", provider.RetryNever)

// authorized refuses a provider mutation outside a running, approved
// operation (provideraction.OperationAuthority). The Vercel adapter checks
// the same authority itself immediately before sending each mutation.
func authorized(ctx context.Context, operation string) error {
	if provideraction.OperationAuthority(ctx) != nil {
		return provider.NewError(operation, 0, "AUTHORIZATION_DENIED", provider.RetrySafe)
	}
	return nil
}

func randomKey(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("random source unavailable")
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

// ---- Neon ----

// Neon implements provideraction.Factory.
func (f *Factory) Neon(credential []byte) (provideraction.NeonPort, error) {
	a, err := neon.New(credential, neon.Options{Endpoint: f.ep.neon, OrgID: f.cfg.NeonOrgID})
	if err != nil {
		return nil, err
	}
	if f.ep.neonSQL != nil {
		if err := neon.SetSQLConnectorForTest(a, f.ep.neonSQL); err != nil {
			a.Close()
			return nil, err
		}
	}
	return &neonPort{a: a}, nil
}

type neonPort struct{ a *neon.Adapter }

func (p *neonPort) Close() error { p.a.Close(); return nil }

func (p *neonPort) CreateProject(ctx context.Context, spec provideraction.NeonProjectSpec, pooled, direct *lifecycle.SecretSink) (provideraction.NeonProject, error) {
	if err := authorized(ctx, "project_create"); err != nil {
		return provideraction.NeonProject{}, err
	}
	info, err := p.a.CreateProject(ctx, neon.ProjectSpec{Name: spec.Name, RegionID: spec.RegionID, PGVersion: spec.PGVersion}, pooled, direct)
	// A project ID is returned even on a later failure, for cleanup.
	return provideraction.NeonProject{ProjectID: info.ProjectID, BranchID: info.BranchID, Role: info.Role, Database: info.Database}, err
}

func (p *neonPort) DeleteProject(ctx context.Context, projectID string) error {
	if err := authorized(ctx, "project_delete"); err != nil {
		return err
	}
	return p.a.DeleteProject(ctx, projectID)
}

func (p *neonPort) PrepareRotationRoles(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string, adopt bool) error {
	if err := authorized(ctx, "rotation_roles_prepare"); err != nil {
		return err
	}
	return p.a.PrepareRotationRoles(ctx, projectID, branchID, database, ownerRole, roles, adopt)
}

func (p *neonPort) RotationRolesReady(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string) (bool, error) {
	return p.a.RotationRolesReady(ctx, projectID, branchID, database, ownerRole, roles)
}

func (p *neonPort) ResetRolePassword(ctx context.Context, projectID, branchID, role, database string, pooled, direct *lifecycle.SecretSink) error {
	if err := authorized(ctx, "role_reset_password"); err != nil {
		return err
	}
	if pooled == nil && direct == nil {
		// Invalidate only: the new password's URIs are wiped, never stored.
		pooled, direct = discardSink(), discardSink()
	}
	return p.a.ResetRolePassword(ctx, projectID, branchID, role, database, pooled, direct)
}

type discardWriter struct{}

func (discardWriter) StoreSecret(_ context.Context, _ string, fill func(func([]byte) error) error) (int64, error) {
	if err := fill(func(v []byte) error {
		for i := range v {
			v[i] = 0
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return 1, nil
}

func discardSink() *lifecycle.SecretSink {
	s, _ := lifecycle.NewSecretSink(discardWriter{}, "discarded")
	return s
}

// ---- Stripe ----

// Stripe implements provideraction.Factory. Live-mode keys are refused here
// as well as by the service and the adapter.
func (f *Factory) Stripe(credential []byte) (provideraction.StripePort, error) {
	if stripe.LiveModeKey(credential) || !(bytes.HasPrefix(credential, []byte("sk_test_")) || bytes.HasPrefix(credential, []byte("rk_test_"))) {
		return nil, errors.New("Stripe control credential must be a test-mode key")
	}
	a, err := stripe.New(credential, stripe.Options{Endpoint: f.ep.stripe})
	if err != nil {
		return nil, err
	}
	return &stripePort{a: a}, nil
}

type stripePort struct{ a *stripe.Adapter }

func (p *stripePort) Close() error { p.a.Close(); return nil }

// stripeIdentity labels the create request; the adapter only requires it
// to be present. A restricted webhook key may not read the account, so the
// account is not looked up.
const stripeIdentity = "stripe-test-mode"

func (p *stripePort) CreateWebhook(ctx context.Context, endpointURL string, events []string, secret *lifecycle.SecretSink) (string, error) {
	if err := authorized(ctx, "create"); err != nil {
		return "", err
	}
	key, err := randomKey("envbank-pa-")
	if err != nil {
		return "", provider.NewError("create", 0, "RANDOM_UNAVAILABLE", provider.RetryNever)
	}
	ev, err := p.a.Create(ctx, lifecycle.CredentialRequest{ProviderIdentity: stripeIdentity, CredentialType: "webhook-signing-secret",
		DestinationRecord: "provider-action", IdempotencyKey: key,
		Parameters: map[string][]string{"url": {endpointURL}, "enabled_events": append([]string(nil), events...)}}, secret)
	return ev.CredentialID, err
}

func (p *stripePort) Webhook(ctx context.Context, endpointID string) (provideraction.StripeWebhook, error) {
	ep, err := p.a.Endpoint(ctx, endpointID)
	if err != nil {
		return provideraction.StripeWebhook{}, err
	}
	return provideraction.StripeWebhook{URL: ep.URL, Events: ep.Events}, nil
}

func (p *stripePort) DeleteWebhook(ctx context.Context, endpointID string) error {
	if err := authorized(ctx, "revoke"); err != nil {
		return err
	}
	return p.a.Revoke(ctx, endpointID)
}

// ---- Vercel ----

const (
	defaultWaitReady = 25 * time.Minute
	healthTimeout    = 10 * time.Second
	maxHealthBody    = 4 << 10
	healthUserAgent  = "envbank-health/1"
)

// Vercel implements provideraction.Factory. Adapters are built lazily per
// scope from credential (the broker's buffer, valid for this operation) and
// all closed by Close.
func (f *Factory) Vercel(credential []byte) (provideraction.VercelPort, error) {
	if len(credential) == 0 {
		return nil, errors.New("Vercel access token is invalid")
	}
	health := &http.Client{
		Timeout: healthTimeout,
		// No redirects: a protected or moved deployment is reported, never
		// followed (and nothing is sent anywhere else).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: true, TLSHandshakeTimeout: healthTimeout, ResponseHeaderTimeout: healthTimeout},
	}
	if f.ep.health != nil {
		health.Transport = f.ep.health
	}
	wait := defaultWaitReady
	if f.ep.waitReady > 0 {
		wait = f.ep.waitReady
	}
	return &vercelPort{f: f, cred: credential, health: health, wait: wait,
		deployments: map[string]vercel.Scope{}, urls: map[string]bool{}}, nil
}

type vercelPort struct {
	f      *Factory
	health *http.Client
	wait   time.Duration

	mu       sync.Mutex
	cred     []byte // the broker's buffer; adapters copy it, Close wipes the copies
	adapters []*vercel.Adapter
	closed   bool
	// deployments this port created, with their scope (WaitReady reads a
	// deployment only in the scope it was created in).
	deployments map[string]vercel.Scope
	// urls WaitReady returned: the only hosts CheckHealth contacts.
	urls map[string]bool
}

func (p *vercelPort) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.adapters {
		a.Close()
	}
	p.adapters, p.cred, p.closed = nil, nil, true
	return nil
}

func (p *vercelPort) track(a *vercel.Adapter, err error) (*vercel.Adapter, error) {
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		a.Close()
		return nil, errClosed
	}
	p.adapters = append(p.adapters, a)
	return a, nil
}

func (p *vercelPort) credential() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errClosed
	}
	return p.cred, nil
}

func (p *vercelPort) team(teamID string) (*vercel.Adapter, error) {
	cred, err := p.credential()
	if err != nil {
		return nil, err
	}
	return p.track(vercel.NewTeam(cred, teamID, vercel.Options{Endpoint: p.f.ep.vercel}))
}

func (p *vercelPort) project(scope vercel.Scope) (*vercel.Adapter, error) {
	cred, err := p.credential()
	if err != nil {
		return nil, err
	}
	return p.track(vercel.New(cred, scope, vercel.Options{Endpoint: p.f.ep.vercel}))
}

// mutating carries the operation's authority into the adapter, which checks
// it immediately before each mutating request (as the PR #50 workflow
// supplies its signed-policy check).
func mutating(ctx context.Context) context.Context {
	return vercel.WithMutationAuthorization(ctx, provideraction.OperationAuthority)
}

func (p *vercelPort) CreateProject(ctx context.Context, teamID, name, gitRepo, framework string) (string, error) {
	a, err := p.team(teamID)
	if err != nil {
		return "", err
	}
	return a.CreateProject(mutating(ctx), teamID, name, gitRepo, framework)
}

func (p *vercelPort) DeleteProject(ctx context.Context, teamID, projectID string) error {
	a, err := p.team(teamID)
	if err != nil {
		return err
	}
	return a.DeleteProject(mutating(ctx), teamID, projectID)
}

// UpsertSensitiveEnv writes one sensitive variable through the adapter's
// exact-scope Write. The value is read only inside value.WithSecret; the
// write request's own copy is destroyed before the callback returns.
func (p *vercelPort) UpsertSensitiveEnv(ctx context.Context, env provideraction.VercelEnv, key string, value *lifecycle.SecretSource) error {
	scope := vercel.Scope{TeamID: env.TeamID, ProjectID: env.ProjectID, Environment: env.Target, GitBranch: env.GitBranch}
	a, err := p.project(scope)
	if err != nil {
		return err
	}
	return value.WithSecret(ctx, func(v []byte) error {
		req := provider.NewWriteRequest("upsert", scope.Target(), vercel.ServiceName, scope.Fingerprint(), key, "", v)
		defer req.Destroy()
		_, err := a.Write(mutating(ctx), req)
		return err
	})
}

func (p *vercelPort) CurrentDeployment(ctx context.Context, teamID, projectID, target string) (string, error) {
	a, err := p.project(vercel.Scope{TeamID: teamID, ProjectID: projectID, Environment: target})
	if err != nil {
		return "", err
	}
	var d vercel.Deployment
	if target == vercel.EnvironmentProduction {
		d, err = a.CurrentDeployment(ctx)
	} else {
		d, err = a.LatestPreviewDeployment(ctx)
	}
	return d.ID, err
}

func (p *vercelPort) Redeploy(ctx context.Context, teamID, projectID, target, sourceDeploymentID string) (string, error) {
	if target == vercel.EnvironmentProduction {
		// Vercel creates a production redeploy staged (custom domains are
		// never auto-assigned), so production traffic would keep the old
		// credentials and a rotation would then invalidate them under it.
		return "", provideraction.ErrPromotionUnsupported
	}
	scope := vercel.Scope{TeamID: teamID, ProjectID: projectID, Environment: target}
	a, err := p.project(scope)
	if err != nil {
		return "", err
	}
	opID, err := randomKey("envbank-pa-")
	if err != nil {
		return "", provider.NewError("redeploy", 0, "RANDOM_UNAVAILABLE", provider.RetryNever)
	}
	d, err := a.Redeploy(mutating(ctx), sourceDeploymentID, opID)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.deployments[d.ID] = scope
	p.mu.Unlock()
	return d.ID, nil
}

func (p *vercelPort) WaitReady(ctx context.Context, teamID, deploymentID string) (string, error) {
	p.mu.Lock()
	scope, ok := p.deployments[deploymentID]
	p.mu.Unlock()
	if !ok || scope.TeamID != teamID {
		return "", provider.NewError("wait_ready", 0, "UNKNOWN_DEPLOYMENT", provider.RetryNever)
	}
	a, err := p.project(scope)
	if err != nil {
		return "", err
	}
	d, err := a.WaitReady(ctx, deploymentID, p.wait)
	if err != nil {
		return "", err
	}
	if !healthHost(d.URL) {
		return "", provider.NewError("wait_ready", 0, "DEPLOYMENT_URL_INVALID", provider.RetryNever)
	}
	u := "https://" + d.URL
	p.mu.Lock()
	p.urls[u] = true
	p.mu.Unlock()
	return u, nil
}

// healthHost accepts a deployment host under vercel.app (Vercel's
// deployment URLs, which the health check targets). Custom domains are not
// checked: a redeploy is never aliased to them by this broker.
func healthHost(host string) bool {
	const suffix = ".vercel.app"
	if len(host) <= len(suffix) || len(host) > 253 || !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false // one label only: no sub-subdomains, no dots
		}
	}
	return label[0] != '-' && label[len(label)-1] != '-'
}

// CheckHealth makes one GET to deploymentURL+path: only a URL WaitReady
// returned (https, a *.vercel.app host), no credentials or cookies ever, no
// redirects followed, at most 4 KiB of body read and discarded. 2xx is
// healthy; 401 (Vercel deployment protection) is ErrHealthProtected and is
// never bypassed; anything else is unhealthy.
func (p *vercelPort) CheckHealth(ctx context.Context, deploymentURL, path string) error {
	p.mu.Lock()
	known := p.urls[deploymentURL]
	p.mu.Unlock()
	u, err := url.Parse(deploymentURL)
	if !known || err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || !healthHost(u.Host) {
		return provider.NewError("health", 0, "HEALTH_URL_REFUSED", provider.RetryNever)
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#%\\") || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return provider.NewError("health", 0, "HEALTH_PATH_REFUSED", provider.RetryNever)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+u.Host+path, http.NoBody)
	if err != nil {
		return provider.NewError("health", 0, "REQUEST_INVALID", provider.RetryNever)
	}
	req.Header.Set("User-Agent", healthUserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := p.health.Do(req)
	if err != nil {
		return provider.NewError("health", 0, "TRANSPORT", provider.RetrySafe)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBody))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil
	case resp.StatusCode == http.StatusUnauthorized:
		return provideraction.ErrHealthProtected
	default:
		return provider.NewError("health", resp.StatusCode, "UNHEALTHY", provider.RetryNever)
	}
}
