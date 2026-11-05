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
	adapter, err := New([]byte("sk_test_control"), Options{Endpoint: "http://localhost", Client: client})
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
	adapter, _ := New([]byte("sk_test_control"), Options{Endpoint: "http://localhost", Client: client})
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
	adapter, _ := New([]byte("sk_test_control"), Options{Endpoint: "http://localhost", Client: client})
	defer adapter.Close()
	sink, _ := lifecycle.NewSecretSink(&writer{}, "TOKEN")
	_, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct_123", CredentialType: "webhook-signing-secret", DestinationRecord: "TOKEN", Parameters: map[string][]string{"url": {"https://example.test/webhook"}, "enabled_events": {"*"}}}, sink)
	if err == nil || called {
		t.Fatal("non-idempotent creation reached Stripe")
	}
}

func TestNewRefusesLiveModeControlKeys(t *testing.T) {
	for _, key := range []string{"sk_live_unique_live_sentinel", "rk_live_unique_live_sentinel"} {
		adapter, err := New([]byte(key), Options{Endpoint: "http://localhost"})
		if err == nil || adapter != nil {
			t.Fatalf("live-mode key accepted")
		}
		if strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "live_unique") {
			t.Fatalf("error echoed the key: %v", err)
		}
	}
	for _, key := range []string{"sk_test_control", "rk_test_control"} {
		adapter, err := New([]byte(key), Options{Endpoint: "http://localhost"})
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
