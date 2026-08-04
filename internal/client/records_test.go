package client

import (
	"testing"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

func TestExistingRecordMigratesWithNoBrowserOrigins(t *testing.T) {
	key, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	record := protocol.SecretRecord{Name: "TOKEN", Value: "secret", Revision: 1}
	id, blob, err := EncryptRecord("vault", key, record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecryptRecords("vault", key, []protocol.Record{{ID: id, Revision: 1, Blob: blob}})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || len(decoded[0].AllowedOrigins) != 0 {
		t.Fatalf("existing record unexpectedly gained browser access: %#v", decoded)
	}
}
