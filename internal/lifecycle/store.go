package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

var ErrLeaseHeld = errors.New("one lifecycle operation is already active for this bundle")

type VaultStore struct {
	API      *client.API
	VaultKey []byte
	Now      func() time.Time
}

func (store *VaultStore) ready() error {
	if store == nil || store.API == nil || len(store.VaultKey) != 32 {
		return errors.New("lifecycle store is not unlocked")
	}
	return nil
}
func (store *VaultStore) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}

func (store *VaultStore) SavePolicy(_ context.Context, policy AutomationPolicy, expected int64) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	if err := policy.Validate(store.now()); err != nil {
		return 0, err
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindAutomationPolicy, policy.ID, policy, expected)
	return object.Revision, err
}
func (store *VaultStore) LoadPolicy(_ context.Context, id string) (AutomationPolicy, int64, error) {
	var policy AutomationPolicy
	revision, err := store.load(vaultobject.KindAutomationPolicy, id, &policy)
	if err != nil {
		return AutomationPolicy{}, 0, err
	}
	if policy.ID != id || policy.Validate(store.now()) != nil {
		return AutomationPolicy{}, 0, errors.New("encrypted automation policy is invalid")
	}
	return policy, revision, nil
}
func (store *VaultStore) SaveOperation(_ context.Context, operation Operation, expected int64) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	if err := operation.Validate(); err != nil {
		return 0, err
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindLifecycleOperation, operation.ID, operation, expected)
	return object.Revision, err
}
func (store *VaultStore) LoadOperation(_ context.Context, id string) (Operation, int64, error) {
	var operation Operation
	revision, err := store.load(vaultobject.KindLifecycleOperation, id, &operation)
	if err != nil {
		return Operation{}, 0, err
	}
	if operation.ID != id || operation.Validate() != nil {
		return Operation{}, 0, errors.New("encrypted lifecycle operation is invalid")
	}
	return operation, revision, nil
}

// AcquireLease uses the encrypted object's optimistic revision as a
// distributed mutex. At most one create/update can win on the server.
func (store *VaultStore) AcquireLease(ctx context.Context, bundle, owner string, ttl time.Duration) (Lease, int64, error) {
	if err := store.ready(); err != nil {
		return Lease{}, 0, err
	}
	if ttl <= 0 || ttl > 15*time.Minute {
		return Lease{}, 0, errors.New("lifecycle lease duration is invalid")
	}
	now := store.now()
	lease := Lease{Bundle: bundle, Owner: owner, AcquiredAt: now.Format(time.RFC3339), ExpiresAt: now.Add(ttl).Format(time.RFC3339)}
	if err := lease.Validate(now); err != nil {
		return Lease{}, 0, err
	}
	var current Lease
	revision, loadErr := store.load(vaultobject.KindLifecycleLease, bundle, &current)
	if loadErr == nil {
		expires, err := time.Parse(time.RFC3339, current.ExpiresAt)
		if err != nil {
			return Lease{}, 0, errors.New("encrypted lifecycle lease is invalid")
		}
		if now.Before(expires) {
			return Lease{}, 0, ErrLeaseHeld
		}
	}
	expected := int64(0)
	if loadErr == nil {
		expected = revision
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindLifecycleLease, bundle, lease, expected)
	if err != nil {
		return Lease{}, 0, ErrLeaseHeld
	}
	_ = ctx
	return lease, object.Revision, nil
}
func (store *VaultStore) ReleaseLease(_ context.Context, lease Lease, revision int64) error {
	if err := store.ready(); err != nil {
		return err
	}
	if revision < 1 || lease.Bundle == "" {
		return errors.New("lifecycle lease release is invalid")
	}
	current, currentRevision, err := store.loadLease(lease.Bundle)
	if err != nil {
		return err
	}
	if currentRevision != revision || current.Owner != lease.Owner {
		return ErrLeaseHeld
	}
	return store.API.DeleteObject(store.VaultKey, vaultobject.KindLifecycleLease, lease.Bundle, revision)
}
func (store *VaultStore) loadLease(bundle string) (Lease, int64, error) {
	var lease Lease
	revision, err := store.load(vaultobject.KindLifecycleLease, bundle, &lease)
	return lease, revision, err
}

func (store *VaultStore) AppendEvidence(_ context.Context, operationID string, evidence Evidence, public ed25519.PublicKey) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	chain := []Evidence{}
	revision := int64(0)
	if object, err := store.API.GetObject(store.VaultKey, vaultobject.KindOperationEvidence, operationID); err == nil {
		revision = object.Revision
		if decodeStrict(object.Payload, &chain) != nil {
			return 0, errors.New("encrypted evidence chain is invalid")
		}
	}
	proposed := append(append([]Evidence(nil), chain...), evidence)
	if err := VerifyEvidenceChain(proposed, public); err != nil {
		return 0, err
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindOperationEvidence, operationID, proposed, revision)
	return object.Revision, err
}

func (store *VaultStore) load(kind, key string, destination any) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	object, err := store.API.GetObject(store.VaultKey, kind, key)
	if err != nil {
		return 0, err
	}
	if decodeStrict(object.Payload, destination) != nil {
		return 0, errors.New("encrypted lifecycle object is invalid")
	}
	return object.Revision, nil
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
