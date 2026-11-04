package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestOwnerApprovalPinIsEncryptedAndNeverReplaced(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("pin-passphrase")
	cfg, err := NewConfig("https://envbank.example", "vault", "device", "laptop", keys, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	pin := append([]byte{4}, bytes.Repeat([]byte{7}, 64)...)
	if err = cfg.SetOwnerApprovalKey(pin[:10]); err == nil {
		t.Fatal("short pin accepted")
	}
	if err = cfg.SetOwnerApprovalKey(pin); err != nil {
		t.Fatal(err)
	}
	if err = cfg.SetOwnerApprovalKey(append([]byte{4}, bytes.Repeat([]byte{8}, 64)...)); err == nil {
		t.Fatal("existing owner pin silently replaced")
	}
	if err = cfg.Lock(keys.Secrets, passphrase); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err = cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "owner_approval_key") {
		t.Fatal("owner pin stored outside the encrypted payload")
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OwnerApprovalKey() != nil {
		t.Fatal("pin available before unlock")
	}
	if _, err = loaded.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.OwnerApprovalKey(), pin) {
		t.Fatal("pin did not round-trip through encrypted payload")
	}
	// A plain-file field cannot inject a pin: unknown public fields are ignored
	// and the encrypted payload remains authoritative.
	tampered := strings.Replace(string(raw), `"version"`, `"owner_approval_key":"BAAA","version"`, 1)
	if err = os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reloaded.Unlock(passphrase); err != nil || !bytes.Equal(reloaded.OwnerApprovalKey(), pin) {
		t.Fatal("public config field influenced the owner pin")
	}
}
