package ownerinput

import (
	"context"
	"strings"
	"testing"
)

// The pairing frame carries the broker's vault fingerprint and sanitized
// device name (each at most 64 bytes) so the host's Touch ID text names the
// broker; setup mode sends "setup"; an invalid fingerprint is omitted.
func TestPairingFrameCarriesBrokerIdentity(t *testing.T) {
	long := strings.Repeat("é", 80) // 160 bytes
	for name, tc := range map[string]struct {
		label       PairingLabel
		vault, name string
		hasVault    bool
		hasName     bool
	}{
		"vault":   {label: PairingLabel{VaultFingerprint: VaultFingerprint("v1"), DeviceName: "Owner's‮Mac\n"}, vault: VaultFingerprint("v1"), hasVault: true, name: "Owner's?Mac", hasName: true},
		"setup":   {label: PairingLabel{VaultFingerprint: SetupVaultFingerprint}, vault: "setup", hasVault: true},
		"long":    {label: PairingLabel{VaultFingerprint: VaultFingerprint("v2"), DeviceName: long}, vault: VaultFingerprint("v2"), hasVault: true, hasName: true},
		"invalid": {label: PairingLabel{VaultFingerprint: "not a fingerprint; " + strings.Repeat("x", 80)}},
		"none":    {},
	} {
		conn := newFakeConn()
		p := pinnedProvider()
		p.Label = tc.label
		if err := p.pairOn(context.Background(), conn, func(Identity, string) bool { return true }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := conn.pairings[0]
		v, hasV := m["vault_fingerprint"]
		d, hasD := m["device_name"]
		if hasV != tc.hasVault || v != tc.vault || hasD != tc.hasName || len(v) > MaxPairingLabelBytes || len(d) > MaxPairingLabelBytes {
			t.Fatalf("%s: frame %v", name, m)
		}
		if tc.name != "" && d != tc.name {
			t.Fatalf("%s: device_name %q", name, d)
		}
	}
	if fp := VaultFingerprint("v1"); len(fp) != 16 || fp == VaultFingerprint("v2") || !fingerprintRe.MatchString(fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	if !strings.Contains((PairingLabel{VaultFingerprint: SetupVaultFingerprint}).Describe(), "setup") {
		t.Fatal("setup label")
	}
}
