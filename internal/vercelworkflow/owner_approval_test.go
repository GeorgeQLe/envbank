package vercelworkflow

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
)

// testOwner is a SOFTWARE stand-in for the Secure Enclave key. It exercises
// the canonical owner-signature contract only, not hardware or presence.
var testOwner = ownerapprovaltest.New("vercelworkflow-owner")

var fixtureBase = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// ownerSign performs the same owner-then-device signing as the CLI approval.
func ownerSign(p *lifecycle.AutomationPolicy, device ed25519.PrivateKey) error {
	return ownerSignWith(p, device, testOwner)
}

func ownerSignWith(p *lifecycle.AutomationPolicy, device ed25519.PrivateKey, signer ownerapproval.Signer) error {
	signedAt := fixtureBase
	if expires, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && !expires.After(signedAt) {
		signedAt = expires.Add(-time.Minute)
	}
	return ownerapproval.Approve(context.Background(), p, device, signer, signer.PublicKey(), signedAt, "test approval")
}

func TestDeviceKeyHolderCannotMintHardwareApproval(t *testing.T) {
	b, s, a, p, device := fixture(t, "preview")
	// The configured MCP backend retains the device key. A device-only
	// re-signature (the legacy TTY/software path) must not authorize writes.
	s.policy.OwnerApproval = nil
	if err := s.policy.Sign(device); err != nil {
		t.Fatal(err)
	}
	if s.policy.Validate(b.now()) != nil {
		t.Fatal("fixture policy should be device-valid")
	}
	r, e := b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if e != nil || r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 {
		t.Fatal("device-only approval authorized a Vercel mutation")
	}
	r, _ = b.Call(context.Background(), "envbank_policy_status", mcpserver.Request{PlanID: p})
	if r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" {
		t.Fatal("device-only approval reported as approved")
	}
	// A software P-256 key minted by the device-key holder is not the pin.
	if err := ownerSignWith(&s.policy, device, ownerapprovaltest.New("agent-minted")); err != nil {
		t.Fatal(err)
	}
	r, _ = b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 {
		t.Fatal("unpinned owner key authorized a Vercel mutation")
	}
	// Changing an owner-approved binding and re-signing only with the device
	// key breaks the owner signature.
	if err := ownerSign(&s.policy, device); err != nil {
		t.Fatal(err)
	}
	s.policy.DeploymentSourceID = "dpl_other"
	if err := s.policy.Sign(device); err != nil {
		t.Fatal(err)
	}
	r, _ = b.Call(context.Background(), "envbank_workflow_start", mcpserver.Request{PlanID: p})
	if r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || s.reads != 0 || a.writes != 0 {
		t.Fatal("device re-signed tampering authorized a Vercel mutation")
	}
}

func TestMissingOwnerPinFailsClosedWithoutFallback(t *testing.T) {
	b, s, a, p, _ := fixture(t, "production")
	b.OwnerApprovalKey = nil
	for _, name := range []string{"envbank_workflow_start", "envbank_policy_status"} {
		r, e := b.Call(context.Background(), name, mcpserver.Request{PlanID: p})
		if e != nil || r.BlockerCode != "OWNER_APPROVAL_KEY_NOT_PINNED" || s.reads != 0 || a.writes != 0 {
			t.Fatalf("%s did not refuse without an owner pin", name)
		}
	}
	r, _ := b.Rollback(context.Background(), "vd-"+p)
	if r.BlockerCode == "" && r.Stage != "" {
		t.Fatal("rollback proceeded without an owner pin")
	}
	r, _ = b.Call(context.Background(), "envbank_deployment_rollback", mcpserver.Request{OperationID: "vd-" + p})
	if r.BlockerCode != "OWNER_APPROVAL_KEY_NOT_PINNED" {
		t.Fatal("MCP rollback did not refuse without an owner pin")
	}
}

func TestLegacyInFlightApprovalCannotBeUpgradedSilently(t *testing.T) {
	b, s, a, p, device := fixture(t, "preview")
	r := runTo(t, b, p, "writing")
	// Simulate an operation journaled under a legacy device-only approval.
	state := s.states[r.OperationID]
	legacy := state.Approval
	legacy.OwnerApproval = nil
	_ = legacy.Sign(device)
	state.Approval = legacy
	state.PolicyDigest, _ = legacy.Digest()
	s.states[r.OperationID] = state
	r, e := b.Call(context.Background(), "envbank_workflow_resume", mcpserver.Request{OperationID: r.OperationID})
	if e != nil || r.BlockerCode != "VERCEL_APPROVAL_REQUIRED" || a.writes != 0 || s.reads != 0 {
		t.Fatal("hardware renewal silently upgraded a legacy device-only operation")
	}
}
