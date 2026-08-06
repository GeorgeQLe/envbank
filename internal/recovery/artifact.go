package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/GeorgeQLe/envbank/internal/browser"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

const (
	Version       = 1
	KDF           = "pbkdf2-hmac-sha256"
	Cipher        = "aes-256-gcm"
	Iterations    = 600_000
	MaxArtifact   = 256 << 20
	recoveryMagic = "envbank.recovery.v1"
)

type Artifact struct {
	Version   int         `json:"version"`
	KDF       KDFHeader   `json:"kdf"`
	Cipher    string      `json:"cipher"`
	Encrypted secure.Blob `json:"encrypted"`
}

type KDFHeader struct {
	Name       string `json:"name"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

type Payload struct {
	Records []protocol.SecretRecord `json:"records"`
}

func Seal(records []protocol.SecretRecord, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("recovery passphrase must not be empty")
	}
	records = cloneRecords(records)
	if err := validateRecords(records); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	plaintext, err := json.Marshal(Payload{Records: records})
	if err != nil {
		return nil, err
	}
	if len(plaintext) > MaxArtifact {
		return nil, errors.New("recovery payload exceeds 256 MiB")
	}
	salt, err := secure.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	artifact := Artifact{
		Version: Version,
		KDF: KDFHeader{
			Name:       KDF,
			Salt:       secure.Encode(salt),
			Iterations: Iterations,
		},
		Cipher: Cipher,
	}
	key := secure.DeriveKey(passphrase, salt, artifact.KDF.Iterations)
	artifact.Encrypted, err = secure.Seal(key, plaintext, artifact.aad())
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxArtifact {
		return nil, errors.New("recovery artifact exceeds 256 MiB")
	}
	return raw, nil
}

func Open(raw, passphrase []byte) ([]protocol.SecretRecord, error) {
	if len(raw) > MaxArtifact {
		return nil, errors.New("recovery artifact exceeds 256 MiB")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("recovery passphrase must not be empty")
	}
	var artifact Artifact
	if err := decodeStrict(raw, &artifact); err != nil {
		return nil, fmt.Errorf("invalid recovery artifact: %w", err)
	}
	salt, err := artifact.validateHeader()
	if err != nil {
		return nil, err
	}
	key := secure.DeriveKey(passphrase, salt, artifact.KDF.Iterations)
	plaintext, err := secure.Open(key, artifact.Encrypted, artifact.aad())
	if err != nil {
		return nil, errors.New("recovery artifact authentication failed")
	}
	if len(plaintext) > MaxArtifact {
		return nil, errors.New("recovery payload exceeds 256 MiB")
	}
	var payload Payload
	if err := decodeStrict(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("invalid recovery payload: %w", err)
	}
	if payload.Records == nil {
		return nil, errors.New("invalid recovery payload: records are required")
	}
	if err := validateRecords(payload.Records); err != nil {
		return nil, err
	}
	sort.Slice(payload.Records, func(i, j int) bool {
		return payload.Records[i].Name < payload.Records[j].Name
	})
	return payload.Records, nil
}

func Read(path string, passphrase []byte) ([]protocol.SecretRecord, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxArtifact+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > MaxArtifact {
		return nil, "", errors.New("recovery artifact exceeds 256 MiB")
	}
	records, err := Open(raw, passphrase)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return records, hex.EncodeToString(sum[:]), nil
}

func Write(path string, raw []byte) error {
	if len(raw) > MaxArtifact {
		return errors.New("recovery artifact exceeds 256 MiB")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing recovery artifact %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".envbank-recovery-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing recovery artifact %s", path)
		}
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func (a Artifact) validateHeader() ([]byte, error) {
	if a.Version != Version {
		return nil, fmt.Errorf("unsupported recovery artifact version %d", a.Version)
	}
	if a.KDF.Name != KDF || a.KDF.Iterations != Iterations {
		return nil, errors.New("unsupported or unsafe recovery KDF parameters")
	}
	if a.Cipher != Cipher {
		return nil, errors.New("unsupported recovery cipher")
	}
	salt, err := secure.Decode(a.KDF.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("invalid recovery KDF salt")
	}
	return salt, nil
}

func (a Artifact) aad() []byte {
	return []byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%d\x00%s",
		recoveryMagic, a.Version, a.KDF.Name, a.KDF.Salt, a.KDF.Iterations,
		a.Cipher))
}

func validateRecords(records []protocol.SecretRecord) error {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if !validEnvName(record.Name) {
			return fmt.Errorf("invalid recovery record name %q", record.Name)
		}
		if _, exists := seen[record.Name]; exists {
			return fmt.Errorf("duplicate recovery record name %q", record.Name)
		}
		seen[record.Name] = struct{}{}
		if record.Revision < 1 {
			return fmt.Errorf("invalid revision for recovery record %q", record.Name)
		}
		if record.RotateEveryDays < 0 {
			return fmt.Errorf("invalid rotation policy for recovery record %q", record.Name)
		}
		if _, err := time.Parse(time.RFC3339, record.CreatedAt); err != nil {
			return fmt.Errorf("invalid creation timestamp for recovery record %q", record.Name)
		}
		if _, err := time.Parse(time.RFC3339, record.RotatedAt); err != nil {
			return fmt.Errorf("invalid rotation timestamp for recovery record %q", record.Name)
		}
		origins := make(map[string]struct{}, len(record.AllowedOrigins))
		for _, origin := range record.AllowedOrigins {
			normalized, err := browser.NormalizeOrigin(origin)
			if err != nil || normalized != origin {
				return fmt.Errorf("invalid browser origin for recovery record %q", record.Name)
			}
			if _, exists := origins[origin]; exists {
				return fmt.Errorf("duplicate browser origin for recovery record %q", record.Name)
			}
			origins[origin] = struct{}{}
		}
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') &&
		(name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') &&
			(c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func cloneRecords(records []protocol.SecretRecord) []protocol.SecretRecord {
	cloned := make([]protocol.SecretRecord, len(records))
	copy(cloned, records)
	for i := range cloned {
		cloned[i].AllowedOrigins = append([]string(nil), cloned[i].AllowedOrigins...)
	}
	return cloned
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing data")
		}
		return err
	}
	return nil
}
