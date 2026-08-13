// Package vaultobject encrypts typed bookkeeping objects separately from
// environment-variable records.
package vaultobject

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

const (
	KindBundleSnapshot       = "bundle-snapshot"
	KindBundlePrepare        = "bundle-prepare"
	KindProviderPlan         = "provider-plan"
	KindRolloutOperation     = "rollout-operation"
	KindReadinessAttestation = "readiness-attestation"
	KindAutomationPolicy     = "automation-policy"
	KindLifecycleOperation   = "lifecycle-operation"
	KindLifecycleLease       = "lifecycle-lease"
	KindOperationEvidence    = "operation-evidence"
	KindRollbackMaterial     = "rollback-material"

	MaxKindBytes    = 64
	MaxKeyBytes     = 512
	MaxPayloadBytes = 1 << 20
)

// VaultObject is the plaintext envelope available only to trusted clients.
// Revision is the object's sync revision; payload schemas may retain source
// revisions as durable evidence across recovery into a new vault.
type VaultObject struct {
	Kind       string          `json:"kind"`
	Key        string          `json:"key"`
	Revision   int64           `json:"revision"`
	ModifiedAt string          `json:"modified_at"`
	Payload    json.RawMessage `json:"payload"`
}

// ID derives an opaque identifier without revealing kind or logical key.
func ID(vaultKey []byte, kind, key string) string {
	mac := hmac.New(sha256.New, vaultKey)
	mac.Write([]byte("envbank.object.id.v1\x00"))
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(key))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Encrypt binds an object to its vault and opaque ID with object-specific
// authenticated data. The caller supplies the revision that the server will
// assign after a successful optimistic write.
func Encrypt(vaultID string, vaultKey []byte, object VaultObject) (string, secure.Blob, error) {
	if err := Validate(object); err != nil {
		return "", secure.Blob{}, err
	}
	id := ID(vaultKey, object.Kind, object.Key)
	blob, err := secure.EncryptJSON(vaultKey, object, aad(vaultID, id))
	return id, blob, err
}

// Decrypt authenticates and validates one server-returned object, including
// its derived ID and clear sync metadata.
func Decrypt(vaultID string, vaultKey []byte, encrypted protocol.EncryptedVaultObject) (VaultObject, error) {
	plaintext, err := secure.Open(vaultKey, encrypted.Blob, aad(vaultID, encrypted.ID))
	if err != nil {
		return VaultObject{}, errors.New("vault object could not be decrypted")
	}
	var object VaultObject
	if err := decodeStrict(plaintext, &object); err != nil {
		return VaultObject{}, errors.New("decrypted vault object is invalid")
	}
	if err := Validate(object); err != nil {
		return VaultObject{}, errors.New("decrypted vault object is invalid")
	}
	if ID(vaultKey, object.Kind, object.Key) != encrypted.ID ||
		object.Revision != encrypted.Revision || object.ModifiedAt != encrypted.ModifiedAt {
		return VaultObject{}, errors.New("vault object integrity metadata does not match")
	}
	return object, nil
}

func DecryptAll(vaultID string, vaultKey []byte, encrypted []protocol.EncryptedVaultObject) ([]VaultObject, error) {
	objects := make([]VaultObject, 0, len(encrypted))
	seenIDs := make(map[string]struct{}, len(encrypted))
	seenIdentities := make(map[string]struct{}, len(encrypted))
	for _, item := range encrypted {
		if _, exists := seenIDs[item.ID]; exists {
			return nil, errors.New("duplicate encrypted vault object")
		}
		seenIDs[item.ID] = struct{}{}
		object, err := Decrypt(vaultID, vaultKey, item)
		if err != nil {
			return nil, errors.New("one or more vault objects could not be decrypted")
		}
		identity := object.Kind + "\x00" + object.Key
		if _, exists := seenIdentities[identity]; exists {
			return nil, errors.New("duplicate decrypted vault object")
		}
		seenIdentities[identity] = struct{}{}
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Kind == objects[j].Kind {
			return objects[i].Key < objects[j].Key
		}
		return objects[i].Kind < objects[j].Kind
	})
	return objects, nil
}

func aad(vaultID, id string) []byte {
	return []byte("envbank.object.v1\x00" + vaultID + "\x00" + id)
}

// Validate checks the plaintext envelope without interpreting its typed
// payload. Payload-owning packages perform their own schema validation.
func Validate(object VaultObject) error {
	if len(object.Kind) == 0 || len(object.Kind) > MaxKindBytes {
		return fmt.Errorf("vault object kind must contain at most %d bytes", MaxKindBytes)
	}
	for _, character := range object.Kind {
		if character != '-' && (character < 'a' || character > 'z') {
			return errors.New("vault object kind must contain lowercase letters and hyphens")
		}
	}
	if len(object.Key) == 0 || len(object.Key) > MaxKeyBytes {
		return fmt.Errorf("vault object key must contain at most %d bytes", MaxKeyBytes)
	}
	if object.Revision < 1 {
		return errors.New("vault object revision must be positive")
	}
	parsed, err := time.Parse(time.RFC3339, object.ModifiedAt)
	if err != nil || parsed.UTC().Format(time.RFC3339) != object.ModifiedAt {
		return errors.New("vault object modified_at must be a canonical UTC timestamp")
	}
	if len(object.Payload) == 0 || len(object.Payload) > MaxPayloadBytes || !json.Valid(object.Payload) {
		return errors.New("vault object payload must be valid bounded JSON")
	}
	return nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
