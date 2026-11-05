package vercelworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/rollout"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

var ErrNotFound = errors.New("deployment operation not found")

type Store interface {
	rollout.Store
	Snapshot(context.Context, string) (bundle.Snapshot, int64, error)
	LoadPolicy(context.Context, string) (lifecycle.AutomationPolicy, int64, error)
	LoadDeployment(context.Context, string) (State, int64, error)
	SaveDeployment(context.Context, State, int64) (int64, error)
	AcquireLease(context.Context, string, string, time.Duration) (lifecycle.Lease, int64, error)
	ReleaseLease(context.Context, lifecycle.Lease, int64) error
}

// VaultStore reuses existing encrypted objects and optimistic revisions, not a
// separate database or plaintext journal.
type VaultStore struct {
	*rollout.EncryptedStore
	Lifecycle *lifecycle.VaultStore
}

func (store *VaultStore) Snapshot(_ context.Context, bundleID string) (bundle.Snapshot, int64, error) {
	return bundle.LoadSnapshot(store.API, store.VaultKey, bundleID)
}
func (store *VaultStore) LoadPolicy(ctx context.Context, id string) (lifecycle.AutomationPolicy, int64, error) {
	return store.Lifecycle.LoadPolicy(ctx, id)
}
func (store *VaultStore) AcquireLease(ctx context.Context, bundleID, owner string, ttl time.Duration) (lifecycle.Lease, int64, error) {
	return store.Lifecycle.AcquireLease(ctx, bundleID, owner, ttl)
}
func (store *VaultStore) ReleaseLease(ctx context.Context, lease lifecycle.Lease, revision int64) error {
	return store.Lifecycle.ReleaseLease(ctx, lease, revision)
}
func (store *VaultStore) LoadDeployment(_ context.Context, id string) (State, int64, error) {
	object, err := store.API.GetObject(store.VaultKey, vaultobject.KindDeploymentOperation, id)
	if err != nil {
		var status client.HTTPStatusError
		if errors.As(err, &status) && status.Status == 404 {
			return State{}, 0, ErrNotFound
		}
		return State{}, 0, errors.New("deployment journal unavailable")
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(object.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.ID != id || state.Validate() != nil {
		return State{}, 0, errors.New("deployment journal invalid")
	}
	return state, object.Revision, nil
}
func (store *VaultStore) SaveDeployment(_ context.Context, state State, expected int64) (int64, error) {
	if state.Validate() != nil {
		return 0, errors.New("deployment journal invalid")
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindDeploymentOperation, state.ID, state, expected)
	if err != nil {
		return 0, errors.New("deployment journal update failed")
	}
	return object.Revision, nil
}
