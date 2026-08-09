package vaultobject

import (
	"encoding/json"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestVaultObjectRoundTripAndDomainSeparation(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 7
	object := VaultObject{
		Kind: KindBundleSnapshot, Key: "bundle/example", Revision: 3,
		ModifiedAt: "2026-08-09T20:00:00Z",
		Payload:    json.RawMessage(`{"manifest_digest":"sentinel"}`),
	}
	id, blob, err := Encrypt("vault-a", key, object)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt("vault-a", key, protocol.EncryptedVaultObject{
		ID: id, Revision: object.Revision, ModifiedAt: object.ModifiedAt, Blob: blob,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != object.Kind || got.Key != object.Key || string(got.Payload) != string(object.Payload) {
		t.Fatalf("round trip = %#v", got)
	}
	if id == secure.RecordID(key, object.Key) || id == ID(key, KindProviderPlan, object.Key) {
		t.Fatal("object ID was not domain separated")
	}

	for name, substituted := range map[string]protocol.EncryptedVaultObject{
		"vault": {ID: id, Revision: object.Revision, ModifiedAt: object.ModifiedAt, Blob: blob},
		"kind": {ID: ID(key, KindProviderPlan, object.Key), Revision: object.Revision,
			ModifiedAt: object.ModifiedAt, Blob: blob},
	} {
		t.Run(name, func(t *testing.T) {
			vaultID := "vault-a"
			if name == "vault" {
				vaultID = "vault-b"
			}
			if _, err := Decrypt(vaultID, key, substituted); err == nil {
				t.Fatal("cross-domain ciphertext substitution was accepted")
			}
		})
	}
}

func TestVaultObjectRejectsClearMetadataSubstitution(t *testing.T) {
	key := make([]byte, 32)
	object := VaultObject{Kind: KindProviderPlan, Key: "plan", Revision: 1,
		ModifiedAt: "2026-08-09T20:00:00Z", Payload: json.RawMessage(`{}`)}
	id, blob, err := Encrypt("vault", key, object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt("vault", key, protocol.EncryptedVaultObject{
		ID: id, Revision: 2, ModifiedAt: object.ModifiedAt, Blob: blob,
	}); err == nil {
		t.Fatal("revision substitution was accepted")
	}
}

func TestDecryptAllRejectsDuplicateServerState(t *testing.T) {
	key := make([]byte, 32)
	object := VaultObject{Kind: KindBundleSnapshot, Key: "bundle", Revision: 1,
		ModifiedAt: "2026-08-09T20:00:00Z", Payload: json.RawMessage(`{}`)}
	id, blob, err := Encrypt("vault", key, object)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := protocol.EncryptedVaultObject{
		ID: id, Revision: object.Revision, ModifiedAt: object.ModifiedAt, Blob: blob,
	}
	if _, err := DecryptAll("vault", key, []protocol.EncryptedVaultObject{encrypted, encrypted}); err == nil {
		t.Fatal("duplicate encrypted object was accepted")
	}
}
