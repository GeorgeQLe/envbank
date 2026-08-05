package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

var testRecords = []protocol.SecretRecord{
	{
		Name: "B_TOKEN", Value: "second", CreatedAt: "2026-08-01T12:00:00Z",
		RotatedAt: "2026-08-02T12:00:00Z", RotateEveryDays: 30, Revision: 8,
		AllowedOrigins: []string{"https://example.com"},
	},
	{
		Name: "A_TOKEN", Value: "first", CreatedAt: "2026-07-01T12:00:00Z",
		RotatedAt: "2026-07-02T12:00:00Z", Revision: 3,
	},
}

func TestArtifactRoundTripSortsAndPreservesRecords(t *testing.T) {
	raw, err := Seal(testRecords, []byte("recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := Open(raw, []byte("recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	want := []protocol.SecretRecord{testRecords[1], testRecords[0]}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("records = %#v, want %#v", records, want)
	}
	if strings.Contains(string(raw), "first") || strings.Contains(string(raw), "A_TOKEN") {
		t.Fatal("artifact exposed plaintext record data")
	}
}

func TestArtifactRoundTripSupportsAnEmptyVault(t *testing.T) {
	raw, err := Seal([]protocol.SecretRecord{}, []byte("recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := Open(raw, []byte("recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if records == nil || len(records) != 0 {
		t.Fatalf("records = %#v, want a non-nil empty snapshot", records)
	}
}

func TestArtifactRejectsWrongPassphraseAndTampering(t *testing.T) {
	raw, err := Seal(testRecords, []byte("correct"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(raw, []byte("wrong")); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong passphrase error = %v", err)
	}

	var artifact Artifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte(artifact.Encrypted.Ciphertext)
	ciphertext[len(ciphertext)/2] ^= 1
	artifact.Encrypted.Ciphertext = string(ciphertext)
	tampered, _ := json.Marshal(artifact)
	if _, err := Open(tampered, []byte("correct")); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("ciphertext tamper error = %v", err)
	}

	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	salt, err := secure.Decode(artifact.KDF.Salt)
	if err != nil {
		t.Fatal(err)
	}
	salt[0] ^= 1
	artifact.KDF.Salt = secure.Encode(salt)
	tampered, _ = json.Marshal(artifact)
	if _, err := Open(tampered, []byte("correct")); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("header tamper error = %v", err)
	}
}

func TestArtifactRejectsUnsupportedUnsafeAndMalformedInputs(t *testing.T) {
	raw, err := Seal(testRecords, []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact Artifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.Version = 2
	changed, _ := json.Marshal(artifact)
	if _, err := Open(changed, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "unsupported recovery artifact version") {
		t.Fatalf("future version error = %v", err)
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.KDF.Iterations = 1
	changed, _ = json.Marshal(artifact)
	if _, err := Open(changed, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "unsafe recovery KDF") {
		t.Fatalf("unsafe KDF error = %v", err)
	}
	if _, err := Open(raw[:len(raw)/2], []byte("passphrase")); err == nil {
		t.Fatal("truncated artifact was accepted")
	}
	if _, err := Open(append(raw, []byte("{}")...), []byte("passphrase")); err == nil {
		t.Fatal("artifact with trailing data was accepted")
	}
}

func TestArtifactRejectsDuplicateAndInvalidRecords(t *testing.T) {
	duplicate := append([]protocol.SecretRecord(nil), testRecords[0], testRecords[0])
	raw := sealPayloadForTest(t, Payload{Records: duplicate}, []byte("passphrase"))
	if _, err := Open(raw, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "duplicate recovery record") {
		t.Fatalf("duplicate error = %v", err)
	}
	invalid := testRecords[0]
	invalid.Name = "NOT-AN-ENV"
	raw = sealPayloadForTest(t, Payload{Records: []protocol.SecretRecord{invalid}}, []byte("passphrase"))
	if _, err := Open(raw, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "invalid recovery record name") {
		t.Fatalf("invalid name error = %v", err)
	}
	raw = sealRawForTest(t, []byte(`{"records":[],"unexpected":true}`), []byte("passphrase"))
	if _, err := Open(raw, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("malformed payload error = %v", err)
	}
}

func TestArtifactReadSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.recovery")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxArtifact + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "exceeds 256 MiB") {
		t.Fatalf("size error = %v", err)
	}
}

func TestArtifactWriteIsPrivateAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.recovery")
	raw := []byte("artifact")
	if err := Write(path, raw); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	if err := Write(path, []byte("replacement")); err == nil ||
		!strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrite error = %v", err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(raw) {
		t.Fatalf("existing artifact changed to %q", stored)
	}
}

func sealPayloadForTest(t *testing.T, payload Payload, passphrase []byte) []byte {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return sealRawForTest(t, plaintext, passphrase)
}

func sealRawForTest(t *testing.T, plaintext, passphrase []byte) []byte {
	t.Helper()
	salt := make([]byte, 16)
	artifact := Artifact{
		Version: Version,
		KDF:     KDFHeader{Name: KDF, Salt: secure.Encode(salt), Iterations: Iterations},
		Cipher:  Cipher,
	}
	key := secure.DeriveKey(passphrase, salt, Iterations)
	var err error
	artifact.Encrypted, err = secure.Seal(key, plaintext, artifact.aad())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
