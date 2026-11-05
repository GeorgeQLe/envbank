package main

import (
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provideraction/live"
)

// Without --provider-actions the seam stays nil: every provider_action is
// PROVIDER_UNAVAILABLE.
func TestProviderFactorySeamIsNilByDefault(t *testing.T) {
	f, err := providerActionFactory(false, "")
	if err != nil || f != nil {
		t.Fatalf("default build configured provider adapters: %v %v", f, err)
	}
	svc := newProviderService(nil, f)
	defer svc.Close()
	if svc.Available() {
		t.Fatal("provider actions available without a factory or vault")
	}
	if _, err := providerActionFactory(false, "org-abc"); err == nil {
		t.Fatal("--neon-org-id accepted without --provider-actions")
	}
}

// --provider-actions turns on the live factory (fixed production endpoints);
// --neon-org-id must be an org- ID.
func TestProviderActionsFlagEnablesLiveFactory(t *testing.T) {
	f, err := providerActionFactory(true, "org-abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.(*live.Factory); !ok {
		t.Fatalf("factory %T", f)
	}
	if _, err := providerActionFactory(true, "abc"); err == nil {
		t.Fatal("invalid org ID accepted")
	}
	svc := newProviderService(&brokerVault{}, f)
	defer svc.Close()
	if !svc.Available() {
		t.Fatal("provider actions unavailable with a vault and the live factory")
	}
}
