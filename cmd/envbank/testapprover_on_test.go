//go:build envbank_testapprover

package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestFileApproverAnswersFromItsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answer")
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	get := registerTestApprover(fs)
	if get() != nil {
		t.Fatal("approver without the flag")
	}
	if err := fs.Parse([]string{"--test-approver-file", path}); err != nil {
		t.Fatal(err)
	}
	a := get()
	for content, want := range map[string]approval.Outcome{"approve\n": approval.Approved, "deny": approval.Denied, "unavailable": approval.Unavailable, "y": approval.Denied} {
		_ = os.WriteFile(path, []byte(content), 0o600)
		if got := a.Approve(context.Background(), "test"); got != want {
			t.Fatalf("%q: %v", content, got)
		}
	}
	_ = os.Remove(path)
	if a.Approve(context.Background(), "test") != approval.Denied {
		t.Fatal("missing file must deny")
	}
}

// The test-approver build refuses Chromux (any XPC agent channel) and any
// config outside TMPDIR before touching a terminal, a config or a service.
func TestTestApproverBuildRefusesChromuxAndRealConfigs(t *testing.T) {
	answer := filepath.Join(t.TempDir(), "approve")
	disposable := filepath.Join(t.TempDir(), "device.json")
	for name, args := range map[string][]string{
		"chromux":                         {"--owner-input", "chromux", "--owner-input-unqualified", "--config", disposable},
		"chromux+approver":                {"--test-approver-file", answer, "--owner-input", "chromux", "--owner-input-unqualified", "--legacy-socket", "--config", disposable},
		"other channel":                   {"--owner-input", "xpc", "--config", disposable},
		"default config":                  {"--test-approver-file", answer, "--legacy-socket"},
		"home config":                     {"--legacy-socket", "--config", filepath.Join(os.Getenv("HOME"), ".envbank-test-device.json")},
		"escape via dotdot":               {"--legacy-socket", "--config", filepath.Join(os.TempDir(), "..", "device.json")},
		"tmpdir itself":                   {"--legacy-socket", "--config", os.TempDir()},
		"production owner-input identity": {"--legacy-socket", "--owner-input-identifier", ownerinput.ServiceIdentifier, "--config", disposable},
	} {
		err := agentBrokerCommand(args)
		if err == nil || !strings.HasPrefix(err.Error(), testBuildRefused+": ") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A disposable config under TMPDIR passes the guard (and then needs a terminal).
	err := agentBrokerCommand([]string{"--test-approver-file", answer, "--legacy-socket", "--config", disposable})
	if err == nil || strings.Contains(err.Error(), testBuildRefused) || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("disposable config: %v", err)
	}
	// A TMPDIR that is the home directory proves nothing.
	t.Setenv("TMPDIR", os.Getenv("HOME"))
	if err := testBuildGuard("terminal", ownerInputIdentifier, filepath.Join(os.Getenv("HOME"), "x", "device.json")); err == nil {
		t.Fatal("TMPDIR=$HOME accepted")
	}
}

// A tagged build has its own Keychain namespace and owner-input identity,
// and refuses any device config that a tagged build did not create, even
// under TMPDIR, before any prompt.
func TestTestApproverBuildRefusesProductionIdentityAndVaults(t *testing.T) {
	if keychain.ServiceName(keychain.Service) == keychain.Service || ownerInputIdentifier == ownerinput.ServiceIdentifier ||
		!strings.HasPrefix(ownerInputIdentifier, testBuildSigningIdentifier) {
		t.Fatal("test build shares a production Keychain service or signing identity")
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := client.NewConfig("http://127.0.0.1:1", "vault", "device", "test", keys, []byte("disposable-passphrase"))
	if err != nil || !cfg.IsTestVault() {
		t.Fatalf("tagged build did not mark its config: %v", err)
	}
	dir := t.TempDir()
	marked := filepath.Join(dir, "marked.json")
	if err := cfg.Save(marked); err != nil {
		t.Fatal(err)
	}
	cfg.TestVault = "" // as written by a production build
	unmarked := filepath.Join(dir, "unmarked.json")
	if err := cfg.Save(unmarked); err != nil {
		t.Fatal(err)
	}
	err = agentBrokerCommand([]string{"--legacy-socket", "--config", unmarked})
	if err == nil || !strings.HasPrefix(err.Error(), testBuildRefused+": ") {
		t.Fatalf("unmarked config: %v", err)
	}
	err = agentBrokerCommand([]string{"--legacy-socket", "--config", marked})
	if err == nil || strings.Contains(err.Error(), testBuildRefused) || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("marked config: %v", err)
	}
}
