package main

import "testing"

// The default build has no provider adapters: every provider_action is
// PROVIDER_UNAVAILABLE until a factory is plugged into the seam.
func TestProviderFactorySeamIsNilByDefault(t *testing.T) {
	if providerActionFactory() != nil {
		t.Fatal("the default build must not configure provider adapters")
	}
	svc := newProviderService(nil, providerActionFactory())
	defer svc.Close()
	if svc.Available() {
		t.Fatal("provider actions available without a factory or vault")
	}
}
