//go:build darwin && cgo

package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// This opt-in test presents a real user-presence prompt and mutates only a
// randomized integration-test Keychain account.
func TestSystemStoreIntegration(t *testing.T) {
	if os.Getenv("ENVBANK_KEYCHAIN_INTEGRATION") != "1" {
		t.Skip("set ENVBANK_KEYCHAIN_INTEGRATION=1 to run the interactive Keychain check")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	account := "integration:" + hex.EncodeToString(random)
	wrongAccount := account + ":other-device"
	secret := []byte("envbank-integration-passphrase")
	store := SystemStore{}
	t.Cleanup(func() { _ = store.Delete(Service, account) })
	if err := store.Put(Service, account, secret); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(Service, account, "Authenticate EnvBank integration test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatal("Keychain returned the wrong secret")
	}
	if _, err := store.Get(Service, wrongAccount, "Authenticate EnvBank integration test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-device lookup returned %v", err)
	}
	if err := store.Delete(Service, account); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(Service, account, "Authenticate EnvBank integration test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted item lookup returned %v", err)
	}
}

// This separate opt-in path is successful only when the user cancels the
// system authentication sheet. It never treats cancellation as approval.
func TestSystemStoreCancellation(t *testing.T) {
	if os.Getenv("ENVBANK_KEYCHAIN_EXPECT_CANCEL") != "1" {
		t.Skip("set ENVBANK_KEYCHAIN_EXPECT_CANCEL=1 to exercise user cancellation")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	account := "integration-cancel:" + hex.EncodeToString(random)
	store := SystemStore{}
	t.Cleanup(func() { _ = store.Delete(Service, account) })
	if err := store.Put(Service, account, []byte("envbank-cancel-test")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(Service, account, "Cancel this EnvBank integration test prompt"); err == nil {
		t.Fatal("Keychain cancellation was unexpectedly accepted")
	}
}
