package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
)

// pinOwnerKey simulates the owner-only enrollment result for CLI fixtures. It
// never touches the Keychain or Secure Enclave.
func pinOwnerKey(t *testing.T, configPath, passphrasePath string, public []byte) {
	t.Helper()
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	passphrase, err := readPassphrase(passphrasePath)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := cfg.Unlock(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.SetOwnerApprovalKey(public); err != nil {
		t.Fatal(err)
	}
	if err = cfg.Lock(secrets, passphrase); err != nil {
		t.Fatal(err)
	}
	if err = cfg.Save(configPath); err != nil {
		t.Fatal(err)
	}
}

func stubOwnerEnrollment(t *testing.T, interactive bool, confirm error, enroll func() ([]byte, error)) {
	t.Helper()
	previousEnroll, previousInteractive, previousConfirm := ownerApprovalEnroll, ownerApprovalInteractive, ownerApprovalConfirm
	ownerApprovalEnroll = enroll
	ownerApprovalInteractive = func() bool { return interactive }
	ownerApprovalConfirm = func() error { return confirm }
	t.Cleanup(func() {
		ownerApprovalEnroll, ownerApprovalInteractive, ownerApprovalConfirm = previousEnroll, previousInteractive, previousConfirm
	})
}

func TestOwnerEnrollmentRefusesNonInteractiveBeforeReadingConfig(t *testing.T) {
	stubOwnerEnrollment(t, false, nil, func() ([]byte, error) {
		t.Fatal("non-interactive enrollment reached the Secure Enclave")
		return nil, nil
	})
	_, _, err := captureRunWithStdin(t, []string{"owner-approval", "enroll", "--config", "/nonexistent/must-not-read.json"}, "enroll owner approval key\n")
	if err == nil || !strings.Contains(err.Error(), "interactive") {
		t.Fatalf("non-interactive enrollment not refused: %v", err)
	}
}

func TestOwnerEnrollmentPinsOnceAndStatusReportsKeyID(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	auth := authArgs(fixture, fixture.firstConfigPath)
	calls := 0
	owner := ownerapprovaltest.New("enrolled-owner")
	stubOwnerEnrollment(t, true, errors.New("owner approval enrollment cancelled"), func() ([]byte, error) {
		calls++
		return owner.PublicKey(), nil
	})
	if _, _, err := captureRunWithStdin(t, append([]string{"owner-approval", "enroll"}, auth...), ""); err == nil || calls != 0 {
		t.Fatal("unconfirmed enrollment created a key")
	}
	out, _, err := captureRunWithStdin(t, append([]string{"owner-approval", "status"}, auth...), "")
	if err != nil || !strings.Contains(out, "not-enrolled") {
		t.Fatalf("status before enrollment: %v", err)
	}
	ownerApprovalConfirm = func() error { return nil }
	out, _, err = captureRunWithStdin(t, append([]string{"owner-approval", "enroll"}, auth...), "")
	if err != nil || calls != 1 || !strings.Contains(out, ownerapproval.KeyID(owner.PublicKey())) {
		t.Fatalf("enrollment failed: %v", err)
	}
	if _, _, err = captureRunWithStdin(t, append([]string{"owner-approval", "enroll"}, auth...), ""); err == nil || calls != 1 {
		t.Fatal("second enrollment replaced the owner pin")
	}
	out, _, err = captureRunWithStdin(t, append([]string{"owner-approval", "status"}, auth...), "")
	if err != nil || !strings.Contains(out, "pinned") || !strings.Contains(out, ownerapproval.KeyID(owner.PublicKey())) {
		t.Fatalf("status after enrollment: %v", err)
	}
}

func TestOwnerEnrollmentFailureLeavesNoPin(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	auth := authArgs(fixture, fixture.firstConfigPath)
	stubOwnerEnrollment(t, true, nil, func() ([]byte, error) { return nil, ownerapproval.ErrEntitlement })
	if _, _, err := captureRunWithStdin(t, append([]string{"owner-approval", "enroll"}, auth...), ""); !errors.Is(err, ownerapproval.ErrEntitlement) {
		t.Fatalf("enrollment failure not surfaced: %v", err)
	}
	out, _, err := captureRunWithStdin(t, append([]string{"owner-approval", "status"}, auth...), "")
	if err != nil || !strings.Contains(out, "not-enrolled") {
		t.Fatal("failed enrollment pinned a key")
	}
}
