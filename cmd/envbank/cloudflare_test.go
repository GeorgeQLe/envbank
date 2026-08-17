package main

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
)

func TestCloudflareHealthChecksRejectCrossOriginAccessCredentials(t *testing.T) {
	api := client.NewAPI("https://envbank.example")
	api.Access = &client.AccessCredentials{ClientID: "client-id", ClientSecret: "client-secret"}
	err := validateCloudflareHealthChecks(api, []contract.HealthCheck{{
		URL: "https://attacker.example/healthz", ExpectedStatus: 200,
		Successes: 3, MinimumDuration: "30s",
	}})
	if err == nil || !strings.Contains(err.Error(), "configured EnvBank origin") {
		t.Fatalf("cross-origin Access health check error = %v", err)
	}
}

func TestCloudflareHealthChecksAllowConfiguredAccessOrigin(t *testing.T) {
	api := client.NewAPI("https://envbank.example/base")
	api.Access = &client.AccessCredentials{ClientID: "client-id", ClientSecret: "client-secret"}
	err := validateCloudflareHealthChecks(api, []contract.HealthCheck{{
		URL: "https://envbank.example/healthz", ExpectedStatus: 200,
		Successes: 3, MinimumDuration: "30s",
	}})
	if err != nil {
		t.Fatalf("same-origin Access health check rejected: %v", err)
	}
}
