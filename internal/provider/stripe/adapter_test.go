package stripe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type writer struct{ value []byte }

func (writer *writer) StoreSecret(_ context.Context, _ string, provide func(func([]byte) error) error) (int64, error) {
	err := provide(func(value []byte) error { writer.value = append([]byte(nil), value...); return nil })
	return 2, err
}

func TestWebhookCreateStreamsSecretToSink(t *testing.T) {
	const sentinel = "whsec_unique_adapter_sentinel"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer sk_test_control" {
			t.Fatal("missing control credential")
		}
		if request.Header.Get("Idempotency-Key") != "operation-action" {
			t.Fatal("missing idempotency key")
		}
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), "enabled_events%5B%5D=checkout.session.completed") {
			t.Fatalf("body=%s", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"we_123","secret":"` + sentinel + `"}`)), Header: http.Header{}}, nil
	})}
	adapter, err := New([]byte("sk_test_control"), Options{Endpoint: "http://127.0.0.1", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	stored := &writer{}
	sink, _ := lifecycle.NewSecretSink(stored, "STRIPE_WEBHOOK_SECRET")
	evidence, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct_123", CredentialType: "webhook-signing-secret", DestinationRecord: "STRIPE_WEBHOOK_SECRET", IdempotencyKey: "operation-action", Parameters: map[string][]string{"url": {"https://example.test/webhook"}, "enabled_events": {"checkout.session.completed"}}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.value) != sentinel || evidence.CredentialID != "we_123" || evidence.Receipt.Revision != 2 {
		t.Fatalf("evidence=%#v stored=%q", evidence, stored.value)
	}
}

func TestWebhookCreateNeverReturnsResponseSecretInError(t *testing.T) {
	const sentinel = "whsec_unique_error_sentinel"
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{"error":{"message":"` + sentinel + `"}}`)), Header: http.Header{}}, nil
	})}
	adapter, _ := New([]byte("sk_test_control"), Options{Endpoint: "http://127.0.0.1", Client: client})
	defer adapter.Close()
	sink, _ := lifecycle.NewSecretSink(&writer{}, "TOKEN")
	_, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct_123", CredentialType: "webhook-signing-secret", DestinationRecord: "TOKEN", IdempotencyKey: "operation-error", Parameters: map[string][]string{"url": {"https://example.test/webhook"}, "enabled_events": {"*"}}}, sink)
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error=%v", err)
	}
}

func TestWebhookCreateRequiresStableIdempotencyKey(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil })}
	adapter, _ := New([]byte("sk_test_control"), Options{Endpoint: "http://127.0.0.1", Client: client})
	defer adapter.Close()
	sink, _ := lifecycle.NewSecretSink(&writer{}, "TOKEN")
	_, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct_123", CredentialType: "webhook-signing-secret", DestinationRecord: "TOKEN", Parameters: map[string][]string{"url": {"https://example.test/webhook"}, "enabled_events": {"*"}}}, sink)
	if err == nil || called {
		t.Fatal("non-idempotent creation reached Stripe")
	}
}

func TestNewRefusesLiveModeControlKeys(t *testing.T) {
	for _, key := range []string{"sk_live_unique_live_sentinel", "rk_live_unique_live_sentinel"} {
		adapter, err := New([]byte(key), Options{Endpoint: "http://127.0.0.1"})
		if err == nil || adapter != nil {
			t.Fatalf("live-mode key accepted")
		}
		if strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "live_unique") {
			t.Fatalf("error echoed the key: %v", err)
		}
	}
	for _, key := range []string{"sk_test_control", "rk_test_control"} {
		adapter, err := New([]byte(key), Options{Endpoint: "http://127.0.0.1"})
		if err != nil {
			t.Fatalf("test-mode key refused: %v", err)
		}
		if formatted := fmt.Sprintf("%v %+v %s %#v", adapter, adapter, adapter, adapter); strings.Contains(formatted, "control") {
			t.Fatalf("adapter formatting leaked the key: %s", formatted)
		}
		adapter.Close()
	}
	if !LiveModeKey([]byte("sk_live_x")) || !LiveModeKey([]byte("rk_live_x")) || LiveModeKey([]byte("sk_test_x")) || LiveModeKey([]byte("pk_live_x")) {
		t.Fatal("live-mode classification is wrong")
	}
}

func TestEndpointIsPinned(t *testing.T) {
	for _, ok := range []string{"", "https://api.stripe.com", "https://api.stripe.com/", "http://127.0.0.1:8080", "https://[::1]:9"} {
		if _, err := New([]byte("sk_test_control"), Options{Endpoint: ok}); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://localhost", "https://localhost", "http://api.stripe.com", "https://api.stripe.com:444", "https://api.stripe.com.evil.test",
		"https://evil.test", "https://user@api.stripe.com", "https://api.stripe.com/v1", "https://api.stripe.com?x=1", "http://10.0.0.1", "http://0.0.0.0"} {
		if _, err := New([]byte("sk_test_control"), Options{Endpoint: bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWebhookCreatePassesOnlyAValidAPIVersion(t *testing.T) {
	var bodies []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(body))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"we_123","secret":"whsec_x"}`)), Header: http.Header{}}, nil
	})}
	adapter, err := New([]byte("sk_test_control"), Options{Endpoint: "http://127.0.0.1", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	create := func(versions ...string) error {
		params := map[string][]string{"url": {"https://example.test/webhook"}, "enabled_events": {"invoice.paid"}}
		if versions != nil {
			params["api_version"] = versions
		}
		sink, _ := lifecycle.NewSecretSink(&writer{}, "STRIPE_WEBHOOK_SECRET")
		_, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct_123", CredentialType: "webhook-signing-secret", DestinationRecord: "STRIPE_WEBHOOK_SECRET", IdempotencyKey: fmt.Sprintf("op-%d", len(bodies)), Parameters: params}, sink)
		return err
	}
	if err := create("2024-06-20"); err != nil || !strings.Contains(bodies[0], "api_version=2024-06-20") {
		t.Fatalf("err %v body %s", err, bodies)
	}
	if err := create(); err != nil || strings.Contains(bodies[1], "api_version") {
		t.Fatalf("default: err %v body %s", err, bodies)
	}
	for _, bad := range [][]string{{"latest"}, {""}, {"2024-06-20", "2025-01-01"}, {"2024-06-20&x=1"}} {
		if err := create(bad...); err == nil {
			t.Fatalf("accepted api_version %q", bad)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("invalid versions were sent: %d requests", len(bodies))
	}
}

func TestEndpointDecodesStatusAndAPIVersion(t *testing.T) {
	cases := map[string]struct {
		body, status, version string
		ok                    bool
	}{
		"enabled with version": {`{"id":"we_1","url":"https://example.test/w","enabled_events":["invoice.paid"],"status":"enabled","api_version":"2024-06-20"}`, "enabled", "2024-06-20", true},
		"null version":         {`{"id":"we_1","url":"https://example.test/w","enabled_events":["invoice.paid"],"status":"disabled","api_version":null}`, "disabled", "", true},
		"unknown status":       {`{"id":"we_1","url":"https://example.test/w","enabled_events":["invoice.paid"],"status":"paused","api_version":null}`, "", "", false},
		"missing status":       {`{"id":"we_1","url":"https://example.test/w","enabled_events":["invoice.paid"]}`, "", "", false},
		"empty version":        {`{"id":"we_1","url":"https://example.test/w","enabled_events":["invoice.paid"],"status":"enabled","api_version":""}`, "", "", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(c.body)), Header: http.Header{}}, nil
			})}
			adapter, err := New([]byte("sk_test_control"), Options{Endpoint: "http://127.0.0.1", Client: client})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			ep, err := adapter.Endpoint(context.Background(), "we_1")
			if (err == nil) != c.ok || (c.ok && (ep.Status != c.status || ep.APIVersion != c.version)) {
				t.Fatalf("endpoint %+v err %v", ep, err)
			}
		})
	}
}
