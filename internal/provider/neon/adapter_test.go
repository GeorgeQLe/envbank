package neon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
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

func respond(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func newAdapter(t *testing.T, handler func(*http.Request) (*http.Response, error)) *Adapter {
	t.Helper()
	adapter, err := New([]byte("napi_control"), Options{Endpoint: "http://localhost", Client: &http.Client{Transport: roundTripFunc(handler)}, PollInterval: time.Millisecond, PollTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	return adapter
}

func roleRequest(parameters map[string][]string) lifecycle.CredentialRequest {
	return lifecycle.CredentialRequest{ProviderIdentity: "acct", CredentialType: TypeRolePassword, DestinationRecord: "DATABASE_URL", IdempotencyKey: "operation-action", Parameters: parameters}
}

func TestIdentifyUsesAuthAccount(t *testing.T) {
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/v2/auth" || request.Header.Get("Authorization") != "Bearer napi_control" {
			t.Fatalf("request=%s %s", request.Method, request.URL)
		}
		return respond(200, `{"account_id":"org-cool-1234","auth_method":"api_key_org"}`), nil
	})
	identity, err := adapter.Identify(context.Background())
	if err != nil || identity != (provider.Identity{Provider: "neon", ID: "org-cool-1234"}) {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
}

func TestRolePasswordCreateWaitsForOperationsAndStoresURI(t *testing.T) {
	const sentinel = "npg_unique_role_sentinel"
	var polls atomic.Int32
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v2/projects/proj-1/branches/br-main/roles/app_a/reset_password":
			if request.Header.Get("X-Request-ID") != "operation-action" {
				t.Fatal("missing request id")
			}
			return respond(200, `{"role":{"name":"app_a","password":"`+sentinel+`"},"operations":[{"id":"op-1","status":"running"}]}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/api/v2/projects/proj-1/operations/op-1":
			if polls.Add(1) < 3 {
				return respond(200, `{"operation":{"id":"op-1","status":"running"}}`), nil
			}
			return respond(200, `{"operation":{"id":"op-1","status":"finished"}}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/api/v2/projects/proj-1/branches/br-main/endpoints":
			return respond(200, `{"endpoints":[{"id":"ep-1","type":"read_write","host":"ep-cool.us-east-2.aws.neon.tech"}]}`), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		return nil, nil
	})
	stored := &writer{}
	sink, _ := lifecycle.NewSecretSink(stored, "DATABASE_URL")
	evidence, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}, "database_name": {"appdb"}, "pooled": {"true"}}), sink)
	if err != nil {
		t.Fatal(err)
	}
	want := "postgresql://app_a:" + sentinel + "@ep-cool-pooler.us-east-2.aws.neon.tech/appdb?sslmode=require&channel_binding=require"
	if string(stored.value) != want || evidence.CredentialID != "role:proj-1/br-main/app_a" || evidence.Receipt.Revision != 2 || polls.Load() != 3 {
		t.Fatalf("evidence=%#v stored=%q polls=%d", evidence, stored.value, polls.Load())
	}
}

func TestRolePasswordCreateStoresRawPasswordWithoutDatabase(t *testing.T) {
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			return respond(200, `{"role":{"password":"npg_raw_sentinel"},"operations":[]}`), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		return nil, nil
	})
	stored := &writer{}
	sink, _ := lifecycle.NewSecretSink(stored, "PGPASSWORD")
	if _, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}}), sink); err != nil || string(stored.value) != "npg_raw_sentinel" {
		t.Fatalf("stored=%q err=%v", stored.value, err)
	}
}

func TestRolePasswordCreateFailedOperationIsAmbiguousAndLeaksNothing(t *testing.T) {
	const sentinel = "npg_failed_sentinel"
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			return respond(200, `{"role":{"password":"`+sentinel+`"},"operations":[{"id":"op-1"}]}`), nil
		}
		return respond(200, `{"operation":{"status":"failed","error":"`+sentinel+`"}}`), nil
	})
	stored := &writer{}
	sink, _ := lifecycle.NewSecretSink(stored, "PGPASSWORD")
	_, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}}), sink)
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "OPERATION_FAILED" || typed.Retry != provider.RetryAmbiguous || strings.Contains(err.Error(), sentinel) || len(stored.value) != 0 {
		t.Fatalf("err=%v stored=%q", err, stored.value)
	}
}

func TestRolePasswordCreateRejectsAmbiguousEndpoints(t *testing.T) {
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			return respond(200, `{"role":{"password":"npg_two_hosts"},"operations":[]}`), nil
		}
		return respond(200, `{"endpoints":[{"type":"read_write","host":"a.neon.tech"},{"type":"read_write","host":"b.neon.tech"}]}`), nil
	})
	sink, _ := lifecycle.NewSecretSink(&writer{}, "DATABASE_URL")
	_, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}, "database_name": {"appdb"}}), sink)
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "ENDPOINT_AMBIGUOUS" || typed.Retry != provider.RetryAmbiguous {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateRequiresIdempotencyKeyAndValidScope(t *testing.T) {
	called := false
	adapter := newAdapter(t, func(*http.Request) (*http.Response, error) { called = true; return nil, nil })
	sink, _ := lifecycle.NewSecretSink(&writer{}, "TOKEN")
	request := roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}})
	request.IdempotencyKey = ""
	if _, err := adapter.Create(context.Background(), request, sink); err == nil {
		t.Fatal("missing idempotency key accepted")
	}
	for _, bad := range []map[string][]string{
		{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app a"}},
		{"project_id": {"proj-1"}, "branch_id": {"../x"}, "role_name": {"app_a"}},
		{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}, "pooled": {"true"}},
		{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}, "database_name": {"a", "b"}},
	} {
		if _, err := adapter.Create(context.Background(), roleRequest(bad), sink); err == nil {
			t.Fatalf("parameters %v accepted", bad)
		}
	}
	if called {
		t.Fatal("invalid request reached Neon")
	}
}

func TestAPIKeyCreateListsAndRevokes(t *testing.T) {
	const sentinel = "napi_unique_key_sentinel"
	var deleted string
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v2/organizations/org-1/api_keys":
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"key_name":"envbank-rotation","project_id":"proj-1"}` || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("body=%s", body)
			}
			return respond(200, `{"id":1000042,"key":"`+sentinel+`","name":"envbank-rotation","project_id":"proj-1"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/api/v2/organizations/org-1/api_keys":
			return respond(200, `[{"id":7,"name":"other"},{"id":1000042,"name":"envbank-rotation","last_used_at":null}]`), nil
		case request.Method == http.MethodDelete:
			deleted = request.URL.Path
			return respond(200, `{"id":1000042,"revoked":true}`), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		return nil, nil
	})
	stored := &writer{}
	sink, _ := lifecycle.NewSecretSink(stored, "NEON_API_KEY")
	evidence, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct", CredentialType: TypeAPIKey, DestinationRecord: "NEON_API_KEY", IdempotencyKey: "operation-action", Parameters: map[string][]string{"key_name": {"envbank-rotation"}, "org_id": {"org-1"}, "project_id": {"proj-1"}}}, sink)
	if err != nil || string(stored.value) != sentinel || evidence.CredentialID != "api-key:org:org-1:1000042" {
		t.Fatalf("evidence=%#v stored=%q err=%v", evidence, stored.value, err)
	}
	verified, err := adapter.Validate(context.Background(), evidence.CredentialID)
	if err != nil || verified.Presence != provider.PresencePresent || verified.Result != provider.VerificationVerified || verified.Validate() != nil {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	absent, err := adapter.Validate(context.Background(), "api-key:org:org-1:99")
	if err != nil || absent.Presence != provider.PresenceAbsent {
		t.Fatalf("absent=%#v err=%v", absent, err)
	}
	if err := adapter.Revoke(context.Background(), evidence.CredentialID); err != nil || deleted != "/api/v2/organizations/org-1/api_keys/1000042" {
		t.Fatalf("deleted=%q err=%v", deleted, err)
	}
}

func TestAPIKeyProjectScopeRequiresOrganization(t *testing.T) {
	adapter := newAdapter(t, func(*http.Request) (*http.Response, error) { t.Fatal("reached Neon"); return nil, nil })
	sink, _ := lifecycle.NewSecretSink(&writer{}, "NEON_API_KEY")
	_, err := adapter.Create(context.Background(), lifecycle.CredentialRequest{ProviderIdentity: "acct", CredentialType: TypeAPIKey, DestinationRecord: "NEON_API_KEY", IdempotencyKey: "k", Parameters: map[string][]string{"key_name": {"x"}, "project_id": {"proj-1"}}}, sink)
	if err == nil {
		t.Fatal("project-scoped key without organization accepted")
	}
}

func TestRoleValidateIsLimitedPresence(t *testing.T) {
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/projects/proj-1/branches/br-main/roles/app_a" {
			return respond(200, `{"role":{"name":"app_a","protected":false}}`), nil
		}
		return respond(404, `{"code":"","message":"role not found"}`), nil
	})
	present, err := adapter.Validate(context.Background(), "role:proj-1/br-main/app_a")
	if err != nil || present.Result != provider.VerificationLimited || present.Presence != provider.PresencePresent || present.Validate() != nil {
		t.Fatalf("present=%#v err=%v", present, err)
	}
	absent, err := adapter.Validate(context.Background(), "role:proj-1/br-main/app_b")
	if err != nil || absent.Presence != provider.PresenceAbsent {
		t.Fatalf("absent=%#v err=%v", absent, err)
	}
	if _, err := adapter.Validate(context.Background(), "role:proj-1/br-main"); err == nil {
		t.Fatal("malformed role id accepted")
	}
}

func TestRoleRevokeResetsAndDiscardsPassword(t *testing.T) {
	const sentinel = "npg_discarded_sentinel"
	var reset bool
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/roles/app_old/reset_password") {
			reset = true
			return respond(200, `{"role":{"password":"`+sentinel+`"},"operations":[{"id":"op-9"}]}`), nil
		}
		return respond(200, `{"operation":{"status":"finished"}}`), nil
	})
	if err := adapter.Revoke(context.Background(), "role:proj-1/br-main/app_old"); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
}

func TestMutationRetryClassification(t *testing.T) {
	for status, want := range map[int]provider.RetryClass{423: provider.RetrySafe, 503: provider.RetrySafe, 500: provider.RetryAmbiguous, 502: provider.RetryAmbiguous, 403: provider.RetryNever} {
		adapter := newAdapter(t, func(*http.Request) (*http.Response, error) {
			return respond(status, `{"message":"npg_error_sentinel"}`), nil
		})
		sink, _ := lifecycle.NewSecretSink(&writer{}, "PGPASSWORD")
		_, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}}), sink)
		var typed provider.Error
		if !errors.As(err, &typed) || typed.Status != status || typed.Retry != want || strings.Contains(err.Error(), "sentinel") {
			t.Fatalf("status %d: err=%v", status, err)
		}
	}
}

func TestTransportFailureOnMutationIsAmbiguous(t *testing.T) {
	adapter := newAdapter(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection reset npg_transport_sentinel")
	})
	err := adapter.Revoke(context.Background(), "api-key:42")
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Retry != provider.RetryAmbiguous || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("err=%v", err)
	}
	_, err = adapter.Identify(context.Background())
	if !errors.As(err, &typed) || typed.Retry != provider.RetrySafe {
		t.Fatalf("err=%v", err)
	}
}

func TestOperationPollTimeoutIsAmbiguous(t *testing.T) {
	adapter := newAdapter(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			return respond(200, `{"role":{"password":"npg_slow_sentinel"},"operations":[{"id":"op-1"}]}`), nil
		}
		return respond(200, `{"operation":{"status":"running"}}`), nil
	})
	adapter.pollTimeout = 5 * time.Millisecond
	sink, _ := lifecycle.NewSecretSink(&writer{}, "PGPASSWORD")
	_, err := adapter.Create(context.Background(), roleRequest(map[string][]string{"project_id": {"proj-1"}, "branch_id": {"br-main"}, "role_name": {"app_a"}}), sink)
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "OPERATION_TIMEOUT" || typed.Retry != provider.RetryAmbiguous {
		t.Fatalf("err=%v", err)
	}
}

func TestNewRejectsUnsafeEndpointsAndCredentials(t *testing.T) {
	if _, err := New([]byte("napi_x"), Options{Endpoint: "http://example.com"}); err == nil {
		t.Fatal("plaintext remote endpoint accepted")
	}
	if _, err := New([]byte("napi_x"), Options{Endpoint: "https://console.neon.tech/api"}); err == nil {
		t.Fatal("endpoint with path accepted")
	}
	if _, err := New([]byte("napi x"), Options{}); err == nil {
		t.Fatal("credential with whitespace accepted")
	}
}
