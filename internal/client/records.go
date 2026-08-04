package client

import (
	"errors"
	"sort"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
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
