package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/secure"
)

// A test-approver build marks every config it creates and refuses every
// config without a valid marker (bound to the vault and device IDs); the
// default build neither marks nor requires one.
func TestTestVaultMarker(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig("https://envbank.example", "vault", "device", "laptop", keys, []byte("local-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IsTestVault() != testBuild || (cfg.TestVault != "") != testBuild {
		t.Fatalf("test build %v created config marker %q", testBuild, cfg.TestVault)
	}
	if m := TestVaultMarker("vault", "device"); m == TestVaultMarker("vault2", "device") || m == TestVaultMarker("vault", "device2") || !strings.HasPrefix(m, "test-approver-v1:") {
		t.Fatal("marker is not bound to the vault and device")
	}
	dir := t.TempDir()
	save := func(name, marker string) string {
		c := *cfg
		c.TestVault = marker
		p := filepath.Join(dir, name)
		if err := c.Save(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	unmarked := save("unmarked.json", "")
	forged := save("forged.json", TestVaultMarker("other-vault", "device"))
	marked := save("marked.json", TestVaultMarker("vault", "device"))
	for _, p := range []string{unmarked, forged} {
		_, err := LoadConfig(p)
		if testBuild && !errors.Is(err, ErrNotTestVault) {
			t.Fatalf("test build loaded %s: %v", filepath.Base(p), err)
		}
		if !testBuild && err != nil {
			t.Fatalf("default build refused %s: %v", filepath.Base(p), err)
		}
	}
	if _, err := LoadConfig(marked); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marked); err != nil {
		t.Fatal(err)
	}
}
