package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentClientNeedsNoVaultAndFailsClosedWithoutBroker(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	t.Setenv("ENVBANK_PASSPHRASE", "")
	for _, args := range [][]string{
		{"names", "--socket", sock},
		{"request", "--socket", sock, "--reason", "deploy", "API_KEY"},
		{"run", "--socket", sock, "--secret", "API_KEY", "--dir", "/", "--", "/usr/bin/true"},
	} {
		err := agentCommand(args)
		if err == nil || !strings.Contains(err.Error(), "BROKER_UNAVAILABLE") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{}, {"get", "API_KEY"}, {"request", "--socket", sock, "API_KEY"}, {"run", "--socket", sock, "--", "/usr/bin/true"}} {
		if err := agentCommand(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestAgentBrokerRefusesWithoutTerminal(t *testing.T) {
	// `go test` stdin is not a terminal: the broker must refuse before touching any config.
	err := agentBrokerCommand([]string{"--config", filepath.Join(t.TempDir(), "absent.json")})
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("err=%v", err)
	}
}

func TestMCPServeFlags(t *testing.T) {
	if err := mcpCommand([]string{"serve", "--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := mcpCommand([]string{"other"}); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}
