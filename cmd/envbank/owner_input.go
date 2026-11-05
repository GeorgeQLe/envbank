package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
)

// secretSource is a paired, verified desktop-host provider (or a test fake).
type secretSource interface {
	Entry(ctx context.Context, purpose, title, detail, subject string, minBytes, maxBytes int, confirm bool, onCode func(string)) ([]byte, string, error)
}

// ownerSurface routes owner SECRET entry to a verified desktop provider when
// one is paired, displays requests and status in the broker terminal, and
// sends every approval to the biometric approver (typing in the terminal
// approves nothing). If the provider is unavailable or fails verification,
// secret entry falls back to the terminal and says so there; an explicit
// decline in the provider is a decline, never a silent fallback.
type ownerSurface struct {
	*agentbroker.TerminalPrompter
	approver approval.Approver
	provider secretSource // nil ⇒ terminal only
}

// Confirm implements setupOwner: the plan is shown in the terminal for
// reference and decided with Touch ID.
func (o *ownerSurface) Confirm(ctx context.Context, title string, lines []string, reason string) approval.Outcome {
	o.ShowPlan(title, lines)
	return confirmWith(ctx, o.approver, o, reason)
}

// confirmWith runs one approval and reports it in the terminal.
func confirmWith(ctx context.Context, a approval.Approver, n interface{ Notify(string) }, reason string) approval.Outcome {
	if a == nil || !a.Available() {
		n.Notify("Touch ID is unavailable on this Mac: refused (nothing typed here can approve)")
		return approval.Unavailable
	}
	n.Notify("waiting for Touch ID (typing in this terminal approves nothing)")
	out := a.Approve(ctx, reason)
	if out != approval.Approved {
		n.Notify("not approved (" + out.String() + ")")
	}
	return out
}

func (o *ownerSurface) entry(ctx context.Context, purpose, title, detail, subject string, minBytes int, confirm bool) ([]byte, bool, bool) {
	if o.provider == nil {
		return nil, false, false
	}
	value, outcome, err := o.provider.Entry(ctx, purpose, title, detail, subject, minBytes, 1024, confirm, func(code string) {
		o.Notify("secure input requested in Chromux, request code " + code + " (it must match the window)")
	})
	if err != nil {
		o.Notify("Chromux secure input unavailable (" + err.Error() + "); using this terminal instead")
		return nil, false, false
	}
	if outcome != "entered" {
		o.Notify("Chromux secure input: " + outcome)
		return nil, false, true
	}
	return value, true, true
}

// NewPassphrase implements setupOwner.
func (o *ownerSurface) NewPassphrase(ctx context.Context, title string, minBytes int, differentFrom []byte) ([]byte, bool, error) {
	purpose := ownerinput.PurposeNewVault
	if differentFrom != nil {
		purpose = ownerinput.PurposeRecovery
	}
	for attempt := 0; attempt < 3; attempt++ {
		v, ok, handled := o.entry(ctx, purpose, title, "Requested by EnvBank setup, which an agent started.", "", minBytes, true)
		if !handled {
			return o.TerminalPrompter.NewPassphrase(ctx, title, minBytes, differentFrom)
		}
		if !ok {
			return nil, false, nil
		}
		if differentFrom != nil && bytes.Equal(v, differentFrom) {
			wipeBytes(v)
			o.Notify("the recovery passphrase must differ from the vault passphrase; asking again")
			continue
		}
		return v, true, nil
	}
	return nil, false, nil
}

// ReadSecret implements agentbroker.Prompter for agent-requested ingest. A
// replacement was already approved with Touch ID by the broker.
func (o *ownerSurface) ReadSecret(ctx context.Context, req agentbroker.Ingest) ([]byte, bool, error) {
	v, ok, handled := o.entry(ctx, ownerinput.PurposeSecretVal, "Store "+req.Name, req.Reason, req.Name, agentbroker.Limits.MinValueBytes, true)
	if !handled {
		return o.TerminalPrompter.ReadSecret(ctx, req)
	}
	return v, ok, nil
}

type pairer interface {
	Pair(ctx context.Context, confirm func(id ownerinput.Identity, code string) bool) error
}

// pairProvider pairs a desktop provider for this broker session. The details
// are shown in the terminal; the owner confirms the code with Touch ID.
func pairProvider(ctx context.Context, p pairer, t *agentbroker.TerminalPrompter, a approval.Approver, label ownerinput.PairingLabel) error {
	return p.Pair(ctx, pairConfirm(ctx, t, a, label))
}

// pairConfirm is the broker-terminal half of pairing: Chromux has already
// confirmed the code with the owner's Touch ID; the broker shows the code and
// the service identity here and asks for Touch ID again. Each confirmation
// gets its own approval deadline (re-pairing after a service restart happens
// long after start-up), bounded by ctx only while ctx is live.
//
// label names this broker's vault and device (the same fields go in the
// pairing frame, so Chromux's Touch ID text names them too).
func pairConfirm(ctx context.Context, t *agentbroker.TerminalPrompter, a approval.Approver, label ownerinput.PairingLabel) func(id ownerinput.Identity, code string) bool {
	return func(id ownerinput.Identity, code string) bool {
		t.ShowPlan("Pair Chromux secure input", []string{
			"this broker: " + label.Describe(),
			fmt.Sprintf("service signed by team %s (Developer ID), identifier %s; verified by macOS on every message", id.TeamID, id.Identifier),
			"service build cdhash " + id.CDHash + " (pinned for this session)",
			"Chromux reports that you confirmed pairing code " + code + " there with Touch ID.",
			"Touch ID here only if the Chromux window showed exactly this code.",
		})
		reason := approval.Reason("pair EnvBank (%s) with Chromux secure input that showed code %s (team %s, %s, build %.12s)",
			label.Describe(), code, approval.Clean(id.TeamID, 16), approval.Clean(id.Identifier, 64), approval.Clean(id.CDHash, 64))
		actx := ctx
		if ctx.Err() != nil {
			actx = context.Background()
		}
		actx, cancel := context.WithTimeout(actx, approval.DefaultTimeout)
		defer cancel()
		return confirmWith(actx, a, t, reason) == approval.Approved
	}
}
