package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestIssuerFromPublishable(t *testing.T) {
	host := "still-piranha-1.clerk.accounts.dev"
	key := "pk_test_" + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(host+"$")), "=")
	issuer, err := issuerFromPublishable(key)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "https://"+host {
		t.Fatalf("issuer = %q", issuer)
	}
}

func TestParseEnvironmentIgnoresDiagnostics(t *testing.T) {
	values, err := parseEnvironment([]byte("status: pulling\n# Clerk\nVITE_CLERK_PUBLISHABLE_KEY=pk_test_value\nCLERK_SECRET_KEY='sk_test_value'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if values["VITE_CLERK_PUBLISHABLE_KEY"] != "pk_test_value" || values["CLERK_SECRET_KEY"] != "sk_test_value" {
		t.Fatalf("values = %#v", values)
	}
	if _, exists := values["status: pulling"]; exists {
		t.Fatal("diagnostic line was accepted as an environment value")
	}
}

func TestIdentityRejectsPaths(t *testing.T) {
	identity := &identityFlags{app: "app_example", instance: "dev", authorizedParty: "https://example.com/path"}
	if err := identity.validate(); err == nil {
		t.Fatal("authorized-party path was accepted")
	}
}
