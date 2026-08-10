package railway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

func TestBindAndInspectUseOnlyIdentityAndTargetMetadata(t *testing.T) {
	operations := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Project-Access-Token") != "project-token-fixture" ||
			request.Header.Get("Authorization") != "" {
			t.Error("request did not use project-token authentication")
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.Contains(body.Query, "EnvBankRailwayIdentity"):
			operations = append(operations, "EnvBankRailwayIdentity")
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"project-id","environmentId":"environment-id"}}}`)
		case strings.Contains(body.Query, "EnvBankRailwayTarget"):
			operations = append(operations, "EnvBankRailwayTarget")
			fmt.Fprint(response, targetResponse())
		default:
			t.Fatalf("forbidden GraphQL document: %s", body.Query)
		}
	}))
	defer server.Close()

	adapter, err := New([]byte("project-token-fixture"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	request := BindingRequest{Project: "siftcut-staging", Environment: "staging",
		Services: map[string]string{"postgres": "", "migrator": "", "api": "", "web": ""}}
	target, err := adapter.Bind(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if target.ProjectID != "project-id" || target.EnvironmentID != "environment-id" ||
		target.ServiceIDs["postgres"] != "postgres-id" || len(target.ServiceIDs) != 4 {
		t.Fatalf("unexpected binding: %+v", target)
	}
	metadata, err := adapter.Inspect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	for service, variables := range metadata.Variables {
		if len(variables) != 0 {
			t.Fatalf("service %s unexpectedly contained variable metadata", service)
		}
	}
	for _, operation := range operations {
		if operation != "EnvBankRailwayIdentity" && operation != "EnvBankRailwayTarget" {
			t.Fatalf("unexpected operation %s", operation)
		}
	}
}

func TestBindingFailsClosedOnIdentityAndServiceDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(request.Body).Decode(&body)
		if strings.Contains(body.Query, "Identity") {
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"wrong-project","environmentId":"environment-id"}}}`)
			return
		}
		fmt.Fprint(response, targetResponse())
	}))
	defer server.Close()
	adapter, err := New([]byte("token"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	_, err = adapter.Bind(context.Background(), BindingRequest{Project: "siftcut-staging",
		ProjectID: "project-id", Environment: "staging", Services: map[string]string{"api": "api-id"}})
	var safe provider.Error
	if !strings.Contains(fmt.Sprint(err), "TARGET_ID_MISMATCH") || !errors.As(err, &safe) {
		t.Fatalf("wrong project token did not fail safely: %v", err)
	}
}

func TestBindingRejectsEnvironmentNameAndScopedIDFromDifferentNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(request.Body).Decode(&body)
		if strings.Contains(body.Query, "Identity") {
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"project-id","environmentId":"staging-id"}}}`)
			return
		}
		fmt.Fprint(response, `{"data":{"project":{"id":"project-id","name":"siftcut-staging","environments":{"edges":[{"node":{"id":"production-id","name":"production"}},{"node":{"id":"staging-id","name":"staging"}}]},"services":{"edges":[{"node":{"id":"api-id","name":"api"}}]}}}}`)
	}))
	defer server.Close()
	adapter, err := New([]byte("token"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	_, err = adapter.Bind(context.Background(), BindingRequest{Project: "siftcut-staging",
		Environment: "production", Services: map[string]string{"api": "api-id"}})
	var safe provider.Error
	if !errors.As(err, &safe) || safe.Code != "ENVIRONMENT_MISMATCH" || safe.Retry != provider.RetryNever {
		t.Fatalf("cross-environment binding did not fail safely: %v", err)
	}
}

func TestGraphQLErrorsDiscardMessagesAndBodies(t *testing.T) {
	const sentinel = "provider-response-secret-SENTINEL-41"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(response, `{"errors":[{"message":%q,"extensions":{"code":%q}}]}`,
			sentinel, "unsafe code "+sentinel)
	}))
	defer server.Close()
	adapter, err := New([]byte("token"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	_, err = adapter.Identity(context.Background())
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("GraphQL error was not safely bounded: %v", err)
	}
}

func TestBindingRejectsDuplicateServiceResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(request.Body).Decode(&body)
		if strings.Contains(body.Query, "Identity") {
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"project-id","environmentId":"environment-id"}}}`)
			return
		}
		duplicate := strings.Replace(targetResponse(),
			`{"node":{"id":"api-id","name":"api"}}`,
			`{"node":{"id":"api-id","name":"api"}},{"node":{"id":"other-api-id","name":"api"}}`, 1)
		fmt.Fprint(response, duplicate)
	}))
	defer server.Close()
	adapter, err := New([]byte("token"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	_, err = adapter.Bind(context.Background(), BindingRequest{Project: "siftcut-staging",
		Environment: "staging", Services: map[string]string{"api": ""}})
	if err == nil || !strings.Contains(err.Error(), "SERVICE_RESOLUTION") {
		t.Fatalf("duplicate service name was accepted: %v", err)
	}
}

func TestWriteUsesOnlySkipDeployVariableUpsertAndVerifyReadsNoValues(t *testing.T) {
	const secret = "write-value-SENTINEL-82"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		var body struct {
			Query     string `json:"query"`
			Variables struct {
				Input struct {
					ProjectID, EnvironmentID, ServiceID, Name, Value string
					SkipDeploys                                      bool
				} `json:"input"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		lowerQuery := strings.ToLower(body.Query)
		if body.Variables.Input.Value != secret {
			t.Fatal("Railway write did not receive the callback-scoped value")
		}
		if !strings.Contains(body.Query, "EnvBankRailwayVariableUpsert") ||
			strings.Contains(lowerQuery, "serviceinstancedeploy") || strings.Contains(lowerQuery, "redeploy") ||
			strings.Contains(lowerQuery, "restart") ||
			body.Variables.Input.ProjectID != "project-id" ||
			body.Variables.Input.EnvironmentID != "environment-id" ||
			body.Variables.Input.ServiceID != "api-id" || body.Variables.Input.Name != "SECRET" ||
			!body.Variables.Input.SkipDeploys {
			t.Fatalf("unexpected sanitized write request: query=%q name=%q", body.Query, body.Variables.Input.Name)
		}
		fmt.Fprint(response, `{"data":{"variableUpsert":true}}`)
	}))
	defer server.Close()
	adapter, err := New([]byte("token"), Options{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	target := provider.Target{ProjectID: "project-id", EnvironmentID: "environment-id",
		ServiceIDs: map[string]string{"api": "api-id"}}
	write := provider.NewWriteRequest("upsert", target, "api", "api-id", "SECRET", "ignored", []byte(secret))
	if _, err := adapter.Write(context.Background(), write); err != nil {
		t.Fatal(err)
	}
	write.Destroy()
	evidence, err := adapter.Verify(context.Background(), provider.VerifyRequest{Target: target,
		Service: "api", ServiceID: "api-id", Name: "SECRET"})
	if err != nil || evidence.Result != provider.VerificationLimited ||
		evidence.Presence != provider.PresenceUnknown || requests != 1 {
		t.Fatalf("unexpected names-only verification: evidence=%+v requests=%d err=%v", evidence, requests, err)
	}
}

func TestMalformedSuccessfulWriteResponsesAreAmbiguousAndSanitized(t *testing.T) {
	const sentinel = "provider-response-secret-SENTINEL-93"
	tests := []struct {
		name string
		body func() io.ReadCloser
	}{
		{name: "unreadable body", body: func() io.ReadCloser { return failingReadCloser{err: errors.New(sentinel)} }},
		{name: "oversized body", body: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1) + sentinel))
		}},
		{name: "malformed envelope", body: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(`{"data":` + sentinel))
		}},
		{name: "null envelope", body: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(`{"data":null,"ignored":"` + sentinel + `"}`))
		}},
		{name: "GraphQL errors", body: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(`{"errors":[{"message":"` + sentinel + `","extensions":{"code":"unsafe ` + sentinel + `"}}]}`))
		}},
		{name: "invalid mutation result", body: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(`{"data":{"variableUpsert":"` + sentinel + `"}}`))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: test.body(), Header: make(http.Header)}, nil
			})}
			adapter, err := New([]byte("token"), Options{Endpoint: "http://127.0.0.1/graphql", Client: client})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()

			write := testWriteRequest([]byte("write-secret"))
			_, err = adapter.Write(context.Background(), write)
			write.Destroy()
			var safe provider.Error
			if !errors.As(err, &safe) || safe.Status != http.StatusOK || safe.Retry != provider.RetryAmbiguous {
				t.Fatalf("successful malformed write response was not ambiguous: %v", err)
			}
			if safe.Validate() != nil || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("write response error was not sanitized: %v", err)
			}
		})
	}
}

func TestWriteHTTPErrorRetryClassificationIsStatusBased(t *testing.T) {
	tests := []struct {
		status int
		retry  provider.RetryClass
	}{
		{status: http.StatusTooManyRequests, retry: provider.RetrySafe},
		{status: http.StatusServiceUnavailable, retry: provider.RetryAmbiguous},
		{status: http.StatusBadRequest, retry: provider.RetryNever},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.status), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(`{}`)),
					Header: make(http.Header)}, nil
			})}
			adapter, err := New([]byte("token"), Options{Endpoint: "http://127.0.0.1/graphql", Client: client})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()

			write := testWriteRequest([]byte("write-secret"))
			_, err = adapter.Write(context.Background(), write)
			write.Destroy()
			var safe provider.Error
			if !errors.As(err, &safe) || safe.Status != test.status || safe.Retry != test.retry || safe.Code != "HTTP_ERROR" {
				t.Fatalf("unexpected HTTP error classification: %v", err)
			}
		})
	}
}

func testWriteRequest(secret []byte) provider.WriteRequest {
	target := provider.Target{ProjectID: "project-id", EnvironmentID: "environment-id",
		ServiceIDs: map[string]string{"api": "api-id"}}
	return provider.NewWriteRequest("upsert", target, "api", "api-id", "SECRET", "ignored", secret)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct {
	err error
}

func (reader failingReadCloser) Read([]byte) (int, error) {
	return 0, reader.err
}

func (failingReadCloser) Close() error {
	return nil
}

func targetResponse() string {
	return `{"data":{"project":{"id":"project-id","name":"siftcut-staging","environments":{"edges":[{"node":{"id":"environment-id","name":"staging"}}]},"services":{"edges":[{"node":{"id":"postgres-id","name":"postgres"}},{"node":{"id":"migrator-id","name":"migrator"}},{"node":{"id":"api-id","name":"api"}},{"node":{"id":"web-id","name":"web"}},{"node":{"id":"other-id","name":"unrelated"}}]}}}}`
}
