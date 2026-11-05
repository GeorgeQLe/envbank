package live

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// The production factory has no endpoint override: New takes none, and the
// zero testEndpoints means every adapter uses its fixed production endpoint.
func TestNewUsesFixedProductionEndpoints(t *testing.T) {
	f, err := New(Config{NeonOrgID: "org-abc-123"})
	if err != nil {
		t.Fatal(err)
	}
	if f.ep.neon != "" || f.ep.vercel != "" || f.ep.stripe != "" || f.ep.health != nil || f.ep.neonSQL != nil || f.ep.waitReady != 0 {
		t.Fatal("production factory carries endpoint overrides")
	}
	for _, bad := range []string{"org_abc", "abc", "org-", "org-ABC", "org-a/../b"} {
		if _, err := New(Config{NeonOrgID: bad}); err == nil {
			t.Errorf("org ID %q accepted", bad)
		}
	}
}

// Outside an operation the service started, ports refuse every mutation
// before anything is sent.
func TestMutationsRefusedOutsideAnApprovedOperation(t *testing.T) {
	fx := newFakes(t)
	f := fx.factory(Config{})
	ctx := context.Background()
	n, _ := f.Neon([]byte(fx.keys["CONTROL_NEON_API_KEY"]))
	defer n.Close()
	v, _ := f.Vercel([]byte(fx.keys["CONTROL_VERCEL_TOKEN"]))
	defer v.Close()
	s, _ := f.Stripe([]byte(fx.keys["CONTROL_STRIPE_KEY"]))
	defer s.Close()
	if _, err := n.CreateProject(ctx, provideraction.NeonProjectSpec{Name: "x"}, nil, nil); err == nil {
		t.Error("neon create outside an operation")
	}
	if err := n.DeleteProject(ctx, "abc"); err == nil {
		t.Error("neon delete outside an operation")
	}
	if _, err := v.CreateProject(ctx, fx.team, "envbank-x", "", ""); err == nil {
		t.Error("vercel create outside an operation")
	}
	if err := s.DeleteWebhook(ctx, "we_abc"); err == nil {
		t.Error("stripe delete outside an operation")
	}
	for _, e := range fx.ev.list() {
		t.Errorf("provider state changed: %s", e)
	}
}

func TestStripeFactoryRefusesLiveKeys(t *testing.T) {
	f, _ := New(Config{})
	for _, k := range []string{"sk_live_" + "abc", "rk_live_abc", "pk_test_abc", "whsec_abc"} {
		if _, err := f.Stripe([]byte(k)); err == nil {
			t.Errorf("key with prefix %q accepted", k[:8])
		}
	}
}

func TestPortsWipeTheirCredentialCopiesOnClose(t *testing.T) {
	fx := newFakes(t)
	f := fx.factory(Config{})
	v, _ := f.Vercel([]byte(fx.keys["CONTROL_VERCEL_TOKEN"]))
	vp := v.(*vercelPort)
	if _, err := vp.team(fx.team); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	if vp.cred != nil || len(vp.adapters) != 0 {
		t.Fatal("Vercel port kept its credential after Close")
	}
	if _, err := vp.team(fx.team); !errors.Is(err, errClosed) {
		t.Fatalf("closed port built an adapter: %v", err)
	}
}

type recordingTransport struct {
	reqs   []*http.Request
	status int
	header http.Header
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.reqs = append(r.reqs, req)
	h := r.header
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: r.status, Header: h, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<20))), Request: req}, nil
}

func healthPort(t *testing.T, rt http.RoundTripper, urls ...string) *vercelPort {
	f, _ := New(Config{})
	f.ep.health = rt
	v, err := f.Vercel([]byte(provideractiontest.Sentinel("vcp_")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	p := v.(*vercelPort)
	for _, u := range urls {
		p.urls[u] = true
	}
	return p
}

func TestCheckHealth(t *testing.T) {
	ctx := context.Background()
	const dep = "https://app-abc123.vercel.app"
	ok := &recordingTransport{status: 204}
	if err := healthPort(t, ok, dep).CheckHealth(ctx, dep, "/api/health"); err != nil {
		t.Fatal(err)
	}
	if r := ok.reqs[0]; r.URL.String() != dep+"/api/health" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		t.Fatalf("health request %v %v", r.URL, r.Header)
	}
	if err := healthPort(t, &recordingTransport{status: 401}, dep).CheckHealth(ctx, dep, "/"); !errors.Is(err, provideraction.ErrHealthProtected) {
		t.Fatalf("401: %v", err)
	}
	redirect := &recordingTransport{status: 307, header: http.Header{"Location": {"https://vercel.com/sso-api?url=x"}}}
	if err := healthPort(t, redirect, dep).CheckHealth(ctx, dep, "/"); err == nil || len(redirect.reqs) != 1 {
		t.Fatalf("redirect followed or accepted: %v (%d requests)", err, len(redirect.reqs))
	}
	if err := healthPort(t, &recordingTransport{status: 503}, dep).CheckHealth(ctx, dep, "/"); err == nil {
		t.Fatal("503 healthy")
	}
	// Only URLs this port's WaitReady returned, on a single vercel.app label.
	refused := &recordingTransport{status: 200}
	for _, u := range []string{"https://example.com", "https://a.b.vercel.app", "http://app-abc123.vercel.app", "https://app-abc123.vercel.app:8443",
		"https://user@app-abc123.vercel.app", "https://vercel.app", "https://127.0.0.1"} {
		if err := healthPort(t, refused, u).CheckHealth(ctx, u, "/"); err == nil {
			t.Errorf("health URL %q accepted", u)
		}
	}
	if err := healthPort(t, refused).CheckHealth(ctx, dep, "/"); err == nil {
		t.Error("URL not returned by WaitReady accepted")
	}
	for _, path := range []string{"api", "/a?x=1", "/a#f", "/../x", "//x", "/%2e%2e"} {
		if err := healthPort(t, refused, dep).CheckHealth(ctx, dep, path); err == nil {
			t.Errorf("path %q accepted", path)
		}
	}
	if len(refused.reqs) != 0 {
		t.Fatalf("refused checks sent %d requests", len(refused.reqs))
	}
}
