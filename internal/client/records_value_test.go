package client

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/protocol"
)

func TestDecodeJSONStringMatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{"", "plain", "postgresql://u:p@h/db?sslmode=require&x=<y>", "quote\" back\\ slash/ \n\r\t\b\f",
		"\x00\x01\x1f", "é ü 中文 🙂", "  ", string([]byte{0xff, 0xfe}), "\U0001F600tail"} {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var want string
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		got, ok := decodeJSONString(raw)
		if !ok || !bytes.Equal(got, []byte(want)) {
			t.Errorf("%q: got %q ok=%v, want %q", raw, got, ok, want)
		}
	}
	for _, bad := range []string{``, `"`, `x"`, `"\x"`, `"\u12"`, `"a"b"`, "\"\x01\""} {
		if _, ok := decodeJSONString([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDecryptRecordValueReadsOneRecord(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	const vault = "vault-1"
	enc := func(r protocol.SecretRecord) protocol.Record {
		id, blob, err := EncryptRecord(vault, key, r)
		if err != nil {
			t.Fatal(err)
		}
		return protocol.Record{ID: id, Revision: r.Revision, Blob: blob}
	}
	records := []protocol.Record{enc(protocol.SecretRecord{Name: "A", Value: "value-a", Revision: 3}), enc(protocol.SecretRecord{Name: "B", Value: "value-b\n", Revision: 1})}
	rec, ok := FindRecord(key, records, "B")
	if !ok || rec.Revision != 1 {
		t.Fatalf("find: %+v %v", rec, ok)
	}
	if _, ok := FindRecord(key, records, "C"); ok {
		t.Fatal("absent record found")
	}
	v, err := DecryptRecordValue(vault, key, rec, "B")
	if err != nil || string(v) != "value-b\n" {
		t.Fatalf("value %q: %v", v, err)
	}
	// Metadata the service reports must match what is inside the ciphertext.
	tampered := rec
	tampered.Revision = 2
	if _, err := DecryptRecordValue(vault, key, tampered, "B"); err == nil {
		t.Fatal("revision mismatch accepted")
	}
	if _, err := DecryptRecordValue(vault, key, records[0], "B"); err == nil {
		t.Fatal("another record's ciphertext accepted")
	}
}
