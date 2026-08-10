package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWriteRequestSecretIsRedactedAndCannotBeMarshaled(t *testing.T) {
	const sentinel = "provider-secret-SENTINEL-9384"
	request := NewWriteRequest("upsert", Target{ProjectID: "project", EnvironmentID: "environment",
		ServiceIDs: map[string]string{"api": "service"}}, "api", "service", "TOKEN", "key", []byte(sentinel))
	for _, rendered := range []string{fmt.Sprint(request), fmt.Sprintf("%v", request),
		fmt.Sprintf("%+v", request), fmt.Sprintf("%#v", request)} {
		if strings.Contains(rendered, sentinel) {
			t.Fatalf("format exposed secret: %s", rendered)
		}
	}
	if raw, err := json.Marshal(request); err == nil || strings.Contains(string(raw), sentinel) ||
		strings.Contains(err.Error(), sentinel) {
		t.Fatalf("write request JSON was not safely rejected: raw=%q err=%v", raw, err)
	}
	var retainedView []byte
	if err := request.ViewSecret(func(value []byte) error {
		if string(value) != sentinel {
			t.Fatal("adapter did not receive the exact value")
		}
		retainedView = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range retainedView {
		if value != 0 {
			t.Fatal("callback-scoped secret view was not cleared")
		}
	}
	request.Destroy()
	if err := request.ViewSecret(func(value []byte) error {
		if len(value) != 0 {
			t.Fatal("destroyed request retained its value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderErrorsDiscardBodiesAndUnsafeCodes(t *testing.T) {
	const sentinel = "response-body-secret-SENTINEL"
	for _, input := range []error{
		errors.New(sentinel),
		fmt.Errorf("wrapped: %w", errors.New(sentinel)),
		NewError("write", 429, "bad code "+sentinel, RetrySafe),
	} {
		safe := SanitizeError("write", input)
		raw, err := json.Marshal(safe)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(safe.Error(), sentinel) || strings.Contains(string(raw), sentinel) {
			t.Fatal("sanitized provider error exposed source text")
		}
	}

	typed := NewError("inspect", 429, "RATE_LIMITED", RetrySafe)
	safe := SanitizeError("write", &typed)
	if safe.Operation != "write" || safe.Status != 429 || safe.Code != "RATE_LIMITED" || safe.Retry != RetrySafe {
		t.Fatalf("safe metadata was not preserved: %+v", safe)
	}
}
