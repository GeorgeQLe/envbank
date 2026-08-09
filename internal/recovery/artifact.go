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
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

const (
	LegacyVersion = 1
	Version       = 2
	KDF           = "pbkdf2-hmac-sha256"
	Cipher        = "aes-256-gcm"
	Iterations    = 600_000
	MaxArtifact   = 256 << 20
	recoveryMagic = "envbank.recovery.v"
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
	Records []protocol.SecretRecord   `json:"records"`
	Objects []vaultobject.VaultObject `json:"objects"`
}

type Snapshot struct {
	Records []protocol.SecretRecord
	Objects []vaultobject.VaultObject
}

func Seal(records []protocol.SecretRecord, passphrase []byte) ([]byte, error) {
	return SealSnapshot(Snapshot{Records: records, Objects: []vaultobject.VaultObject{}}, passphrase)
}

func SealSnapshot(snapshot Snapshot, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("recovery passphrase must not be empty")
	}
	records := cloneRecords(snapshot.Records)
	if err := validateRecords(records); err != nil {
		return nil, err
	}
	objects := cloneObjects(snapshot.Objects)
	if objects == nil {
		objects = []vaultobject.VaultObject{}
	}
	if err := validateObjects(objects); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Kind == objects[j].Kind {
			return objects[i].Key < objects[j].Key
		}
		return objects[i].Kind < objects[j].Kind
	})
	plaintext, err := json.Marshal(Payload{Records: records, Objects: objects})
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
	snapshot, err := OpenSnapshot(raw, passphrase)
	if err != nil {
		return nil, err
	}
	return snapshot.Records, nil
}

func OpenSnapshot(raw, passphrase []byte) (Snapshot, error) {
	if len(raw) > MaxArtifact {
		return Snapshot{}, errors.New("recovery artifact exceeds 256 MiB")
	}
	if len(passphrase) == 0 {
		return Snapshot{}, errors.New("recovery passphrase must not be empty")
	}
	var artifact Artifact
	if err := decodeStrict(raw, &artifact); err != nil {
		return Snapshot{}, fmt.Errorf("invalid recovery artifact: %w", err)
	}
	salt, err := artifact.validateHeader()
	if err != nil {
		return Snapshot{}, err
	}
	key := secure.DeriveKey(passphrase, salt, artifact.KDF.Iterations)
	plaintext, err := secure.Open(key, artifact.Encrypted, artifact.aad())
	if err != nil {
		return Snapshot{}, errors.New("recovery artifact authentication failed")
	}
	if len(plaintext) > MaxArtifact {
		return Snapshot{}, errors.New("recovery payload exceeds 256 MiB")
	}
	var records []protocol.SecretRecord
	var objects []vaultobject.VaultObject
	if artifact.Version == LegacyVersion {
		var legacy struct {
			Records []protocol.SecretRecord `json:"records"`
		}
		if err := decodeStrict(plaintext, &legacy); err != nil {
			return Snapshot{}, fmt.Errorf("invalid recovery payload: %w", err)
		}
		records = legacy.Records
		objects = []vaultobject.VaultObject{}
	} else {
		var payload Payload
		if err := decodeStrict(plaintext, &payload); err != nil {
			return Snapshot{}, fmt.Errorf("invalid recovery payload: %w", err)
		}
		records, objects = payload.Records, payload.Objects
	}
	if records == nil {
		return Snapshot{}, errors.New("invalid recovery payload: records are required")
	}
	if objects == nil {
		return Snapshot{}, errors.New("invalid recovery payload: objects are required")
	}
	if err := validateRecords(records); err != nil {
		return Snapshot{}, err
	}
	if err := validateObjects(objects); err != nil {
		return Snapshot{}, err
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Kind == objects[j].Kind {
			return objects[i].Key < objects[j].Key
		}
		return objects[i].Kind < objects[j].Kind
	})
	return Snapshot{Records: records, Objects: objects}, nil
}

func Read(path string, passphrase []byte) ([]protocol.SecretRecord, string, error) {
	snapshot, artifactID, err := ReadSnapshot(path, passphrase)
	return snapshot.Records, artifactID, err
}

func ReadSnapshot(path string, passphrase []byte) (Snapshot, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxArtifact+1))
	if err != nil {
		return Snapshot{}, "", err
	}
	if len(raw) > MaxArtifact {
		return Snapshot{}, "", errors.New("recovery artifact exceeds 256 MiB")
	}
	snapshot, err := OpenSnapshot(raw, passphrase)
	if err != nil {
		return Snapshot{}, "", err
	}
	sum := sha256.Sum256(raw)
	return snapshot, hex.EncodeToString(sum[:]), nil
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
	if a.Version != LegacyVersion && a.Version != Version {
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
	return []byte(fmt.Sprintf("%s%d\x00%d\x00%s\x00%s\x00%d\x00%s",
		recoveryMagic, a.Version, a.Version, a.KDF.Name, a.KDF.Salt, a.KDF.Iterations,
		a.Cipher))
}

func validateObjects(objects []vaultobject.VaultObject) error {
	seen := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		if err := vaultobject.Validate(object); err != nil {
			return errors.New("invalid recovery vault object")
		}
		identity := object.Kind + "\x00" + object.Key
		if _, exists := seen[identity]; exists {
			return errors.New("duplicate recovery vault object")
		}
		seen[identity] = struct{}{}
	}
	return nil
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

func cloneObjects(objects []vaultobject.VaultObject) []vaultobject.VaultObject {
	cloned := make([]vaultobject.VaultObject, len(objects))
	copy(cloned, objects)
	for index := range cloned {
		cloned[index].Payload = append(json.RawMessage(nil), cloned[index].Payload...)
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
