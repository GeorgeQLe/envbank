package client

import (
	"encoding/json"
	"errors"
	"sort"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

func DecryptRecords(vaultID string, vaultKey []byte, records []protocol.Record) ([]protocol.SecretRecord, error) {
	out := make([]protocol.SecretRecord, 0, len(records))
	for _, encrypted := range records {
		var record protocol.SecretRecord
		aad := []byte("envbank.record.v1\x00" + vaultID + "\x00" + encrypted.ID)
		if err := secure.DecryptJSON(vaultKey, encrypted.Blob, aad, &record); err != nil {
			return nil, errors.New("one or more records could not be decrypted")
		}
		if secure.RecordID(vaultKey, record.Name) != encrypted.ID || record.Revision != encrypted.Revision {
			return nil, errors.New("record integrity metadata does not match")
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func EncryptRecord(vaultID string, vaultKey []byte, record protocol.SecretRecord) (string, secure.Blob, error) {
	id := secure.RecordID(vaultKey, record.Name)
	aad := []byte("envbank.record.v1\x00" + vaultID + "\x00" + id)
	blob, err := secure.EncryptJSON(vaultKey, record, aad)
	return id, blob, err
}

func Due(records []protocol.SecretRecord, now time.Time) []protocol.SecretRecord {
	var due []protocol.SecretRecord
	for _, record := range records {
		if record.RotateEveryDays <= 0 {
			continue
		}
		rotatedAt, err := time.Parse(time.RFC3339, record.RotatedAt)
		if err != nil {
			continue
		}
		if !rotatedAt.Add(time.Duration(record.RotateEveryDays) * 24 * time.Hour).After(now) {
			due = append(due, record)
		}
	}
	return due
}

// FindRecord returns name's encrypted record, found by its keyed ID
// (secure.RecordID) without decrypting any record, and false if absent. Its
// Revision is the sync service's metadata: it is authenticated only when
// the record is decrypted (DecryptRecordValue).
func FindRecord(vaultKey []byte, records []protocol.Record, name string) (protocol.Record, bool) {
	id := secure.RecordID(vaultKey, name)
	for _, record := range records {
		if record.ID == id {
			return record, true
		}
	}
	return protocol.Record{}, false
}

// DecryptRecordValue decrypts one record and returns its value as bytes the
// caller wipes. Only this record is decrypted; the plaintext buffer and the
// JSON-encoded value are wiped before it returns, and the value never
// becomes a Go string. The name and revision inside the ciphertext must
// match.
func DecryptRecordValue(vaultID string, vaultKey []byte, encrypted protocol.Record, name string) ([]byte, error) {
	aad := []byte("envbank.record.v1\x00" + vaultID + "\x00" + encrypted.ID)
	plaintext, err := secure.Open(vaultKey, encrypted.Blob, aad)
	defer wipe(plaintext)
	if err != nil {
		return nil, errors.New("record could not be decrypted")
	}
	var wire struct {
		Name     string          `json:"name"`
		Value    json.RawMessage `json:"value"`
		Revision int64           `json:"revision"`
	}
	err = json.Unmarshal(plaintext, &wire)
	defer wipe(wire.Value)
	if err != nil || wire.Name != name || secure.RecordID(vaultKey, wire.Name) != encrypted.ID || wire.Revision != encrypted.Revision {
		return nil, errors.New("record integrity metadata does not match")
	}
	value, ok := decodeJSONString(wire.Value)
	if !ok {
		wipe(value)
		return nil, errors.New("record value is invalid")
	}
	return value, nil
}

// decodeJSONString decodes one JSON string literal into a new byte slice
// (never a Go string).
func decodeJSONString(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"' || c < 0x20:
			return out, false
		case c != '\\':
			out = append(out, c)
			continue
		}
		i++
		if i >= len(in) {
			return out, false
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in, i+1)
			if !ok {
				return out, false
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if i+6 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
					if r2, ok := hex4(in, i+3); ok {
						if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
							r = dec
							i += 6
						} else {
							r = utf8.RuneError
						}
					} else {
						return out, false
					}
				} else {
					r = utf8.RuneError
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return out, false
		}
	}
	return out, true
}

func hex4(in []byte, start int) (rune, bool) {
	if start+4 > len(in) {
		return 0, false
	}
	var r rune
	for _, c := range in[start : start+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
