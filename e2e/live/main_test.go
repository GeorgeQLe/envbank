package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

func TestAcceptanceMarkerIsMandatoryAndCaseSensitive(t *testing.T) {
	for _, target := range []string{"production", "envbank_acceptance", "ENVBANK-ACCEPTANCE"} {
		if _, err := requireMarked("target", target); err == nil {
			t.Fatalf("accepted unmarked target %q", target)
		}
	}
	if got, err := requireMarked("target", "dedicated-ENVBANK_ACCEPTANCE-free"); err != nil || got == "" {
		t.Fatalf("marked target rejected: %q %v", got, err)
	}
}

func TestWriteRecoveryStateIsPrivateAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stripe-cleanup.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeRecoveryState(path, []byte(`{"resource_id":"we_test"}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("recovery state mode = %o, want 600", got)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != `{"resource_id":"we_test"}` {
		t.Fatalf("unexpected recovery state %q", contents)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".envbank-acceptance-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary recovery state remained: %v", matches)
	}
}

func TestMemoryWriterValidatesWithoutRetainingStripeSecret(t *testing.T) {
	writer := &memoryWriter{}
	if _, err := writer.StoreSecret(context.Background(), "record", func(consume func([]byte) error) error {
		return consume([]byte("not-a-webhook-secret"))
	}); err == nil {
		t.Fatal("invalid secret accepted")
	}
	if writer.stored {
		t.Fatal("invalid secret marked stored")
	}
}

func TestStripeAbsenceClassification(t *testing.T) {
	if !absentOrNil(nil) || !absentOrNil(provider.NewError("validate", 404, "STRIPE_RESPONSE", provider.RetryNever)) {
		t.Fatal("absence was not accepted")
	}
	if absentOrNil(provider.NewError("validate", 500, "STRIPE_RESPONSE", provider.RetrySafe)) || absentOrNil(errors.New("transport")) {
		t.Fatal("unsafe cleanup error accepted as absence")
	}
}
