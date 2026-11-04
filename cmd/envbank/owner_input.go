package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
)

// secretSource is a paired, verified desktop-host provider (or a test fake).
type secretSource interface {
	Entry(ctx context.Context, purpose, title, detail, subject string, minBytes, maxBytes int, confirm bool, onCode func(string)) ([]byte, string, error)
}

// ownerSurface routes owner SECRET entry to a verified desktop provider when
// one is paired, and everything else (plan confirmation, run approvals,
// status) to the broker terminal. If the provider is unavailable or fails
// verification, it falls back to the terminal and says so there; an explicit
// decline in the provider is a decline, never a silent fallback.
type ownerSurface struct {
	*agentbroker.TerminalPrompter
	provider secretSource // nil ⇒ terminal only
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

// ReadSecret implements agentbroker.Prompter for agent-requested ingest.
func (o *ownerSurface) ReadSecret(ctx context.Context, req agentbroker.Ingest) ([]byte, bool, error) {
	if o.provider != nil && req.Replaces {
		// Replacing an existing secret needs an explicit yes in the terminal first.
		ok, err := o.ConfirmPlan(ctx, "Replace "+req.Name+"?", []string{req.Name + " already exists; an agent asked to replace it.", "reason: " + req.Reason})
		if err != nil || !ok {
			return nil, false, err
		}
	}
	v, ok, handled := o.entry(ctx, ownerinput.PurposeSecretVal, "Store "+req.Name, req.Reason, req.Name, agentbroker.Limits.MinValueBytes, true)
	if !handled {
		return o.TerminalPrompter.ReadSecret(ctx, req)
	}
	return v, ok, nil
}

// pairProvider pairs a desktop provider for this broker session in the terminal.
func pairProvider(ctx context.Context, p *ownerinput.Provider, t *agentbroker.TerminalPrompter) error {
	return p.Pair(ctx, func(id ownerinput.Identity, code string) bool {
		ok, err := t.ConfirmPlan(ctx, "Pair Chromux secure input", []string{
			fmt.Sprintf("signed by team %s, identifier %s, hardened runtime", id.TeamID, id.Identifier),
			"build cdhash " + id.CDHash,
			"Chromux should now show pairing code " + code + ".",
			"Answer yes only if the Chromux window shows exactly this code.",
		})
		return err == nil && ok
	})
}
