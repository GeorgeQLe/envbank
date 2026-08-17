package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestConfigV2EncryptsAccessCredentials(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("local-passphrase")
	cfg, err := NewConfig("https://envbank.example", "vault", "device", "laptop", keys, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	want := AccessCredentials{ClientID: "access-client-id", ClientSecret: "access-secret"}
	if err := cfg.SetAccessCredentials(want); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Lock(keys.Secrets, passphrase); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "device.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(raw) == false || stringContainsAny(string(raw), want.ClientID, want.ClientSecret) {
		t.Fatal("saved config exposed Access credentials")
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	got := loaded.AccessCredentials()
	if got == nil || *got != want {
		t.Fatalf("Access credentials = %#v", got)
	}
}

func TestUnlockedV1ConfigMigratesToV2(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("migration-passphrase")
	salt, err := secure.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Version: 1, Server: "https://envbank.example", VaultID: "vault",
		DeviceID: "device", DeviceName: "laptop", SigningPublic: keys.SigningPublic,
		WrappingPublic: keys.WrappingPublic, Salt: secure.Encode(salt), Iterations: secure.LocalIterations}
	key := secure.DeriveKey(passphrase, salt, cfg.Iterations)
	cfg.EncryptedSecret, err = secure.EncryptJSON(key, keys.Secrets, cfg.localAAD(1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.Unlock(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if got != keys.Secrets || cfg.Version != ConfigVersion || !cfg.Migrated() {
		t.Fatalf("v1 migration failed: version=%d migrated=%v", cfg.Version, cfg.Migrated())
	}
	if _, err := cfg.Unlock(passphrase); err != nil {
		t.Fatalf("migrated config cannot be unlocked: %v", err)
	}
}

func stringContainsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		for index := 0; index+len(candidate) <= len(value); index++ {
			if value[index:index+len(candidate)] == candidate {
				return true
			}
		}
	}
	return false
}
