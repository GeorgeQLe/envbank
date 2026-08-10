package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

// Store keeps all plan and operation state behind the encrypted vault-object
// boundary and resolves record values only when an action is about to write.
type Store interface {
	SavePlan(context.Context, ProviderPlan, int64) (int64, error)
	LoadPlan(context.Context, string) (ProviderPlan, int64, error)
	SaveOperation(context.Context, Operation, int64) (int64, error)
	LoadOperation(context.Context, string) (Operation, int64, error)
	ValidateSnapshot(context.Context, ProviderPlan) error
	LoadRecord(context.Context, string, string, int64) ([]byte, error)
}

type EncryptedStore struct {
	API      *client.API
	VaultKey []byte
}

func (store *EncryptedStore) ready() error {
	if store == nil || store.API == nil || len(store.VaultKey) != 32 {
		return errors.New("rollout store is not unlocked")
	}
	return nil
}

func (store *EncryptedStore) SavePlan(_ context.Context, plan ProviderPlan, expected int64) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	created, err := time.Parse(time.RFC3339, plan.CreatedAt)
	if err != nil || plan.Validate(created) != nil {
		return 0, errors.New("provider plan is invalid")
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindProviderPlan, plan.ID(), plan, expected)
	return object.Revision, err
}

func (store *EncryptedStore) LoadPlan(_ context.Context, id string) (ProviderPlan, int64, error) {
	if err := store.ready(); err != nil {
		return ProviderPlan{}, 0, err
	}
	object, err := store.API.GetObject(store.VaultKey, vaultobject.KindProviderPlan, id)
	if err != nil {
		return ProviderPlan{}, 0, err
	}
	var plan ProviderPlan
	if err := decodeStrict(object.Payload, &plan); err != nil {
		return ProviderPlan{}, 0, errors.New("encrypted provider plan is invalid")
	}
	created, timeErr := time.Parse(time.RFC3339, plan.CreatedAt)
	if plan.ID() != id || timeErr != nil || plan.Validate(created) != nil {
		return ProviderPlan{}, 0, errors.New("encrypted provider plan is invalid")
	}
	return plan, object.Revision, nil
}

func (store *EncryptedStore) SaveOperation(_ context.Context, operation Operation, expected int64) (int64, error) {
	if err := store.ready(); err != nil {
		return 0, err
	}
	if err := operation.Validate(); err != nil {
		return 0, err
	}
	object, err := store.API.PutObject(store.VaultKey, vaultobject.KindRolloutOperation,
		operation.ID, operation, expected)
	return object.Revision, err
}

func (store *EncryptedStore) LoadOperation(_ context.Context, id string) (Operation, int64, error) {
	if err := store.ready(); err != nil {
		return Operation{}, 0, err
	}
	object, err := store.API.GetObject(store.VaultKey, vaultobject.KindRolloutOperation, id)
	if err != nil {
		return Operation{}, 0, err
	}
	var operation Operation
	if err := decodeStrict(object.Payload, &operation); err != nil || operation.ID != id || operation.Validate() != nil {
		return Operation{}, 0, errors.New("encrypted rollout operation is invalid")
	}
	return operation, object.Revision, nil
}

func (store *EncryptedStore) ValidateSnapshot(_ context.Context, plan ProviderPlan) error {
	if err := store.ready(); err != nil {
		return err
	}
	object, err := store.API.GetObject(store.VaultKey, vaultobject.KindBundleSnapshot, plan.Bundle)
	if err != nil {
		return err
	}
	var snapshot bundle.Snapshot
	if err := decodeStrict(object.Payload, &snapshot); err != nil || snapshot.Validate() != nil {
		return errors.New("encrypted bundle snapshot is invalid")
	}
	encrypted, err := store.API.ListRecords()
	if err != nil {
		return err
	}
	records, err := client.DecryptRecords(store.API.Config.VaultID, store.VaultKey, encrypted)
	if err != nil {
		return err
	}
	return validateSnapshotBindings(plan, object.Revision, snapshot, records)
}

func validateSnapshotBindings(plan ProviderPlan, objectRevision int64, snapshot bundle.Snapshot,
	records []protocol.SecretRecord) error {
	if objectRevision != plan.SnapshotRevision || snapshot.Bundle != plan.Bundle ||
		snapshot.ManifestDigest != plan.ManifestDigest {
		return errors.New("provider plan does not match the current bundle snapshot")
	}
	for _, action := range plan.Actions {
		if action.Record != "" && snapshot.RecordRevisions[action.Record] != action.ExpectedRecordRevision {
			return fmt.Errorf("provider plan record %s is stale", action.Record)
		}
	}
	for _, item := range plan.Names {
		if item.Record != "" && snapshot.RecordRevisions[item.Record] != item.ExpectedRecordRevision {
			return fmt.Errorf("provider plan record %s is stale", item.Record)
		}
	}
	revisions := make(map[string]int64, len(records))
	for _, record := range records {
		revisions[record.Name] = record.Revision
	}
	for _, action := range plan.Actions {
		if action.Record == "" {
			continue
		}
		physical := bundle.PhysicalName(plan.Bundle, action.Record)
		if revisions[physical] != action.ExpectedRecordRevision {
			return fmt.Errorf("provider plan record %s is stale", action.Record)
		}
	}
	for _, item := range plan.Names {
		if item.Record == "" {
			continue
		}
		physical := bundle.PhysicalName(plan.Bundle, item.Record)
		if revisions[physical] != item.ExpectedRecordRevision {
			return fmt.Errorf("provider plan record %s is stale", item.Record)
		}
	}
	return nil
}

func (store *EncryptedStore) LoadRecord(_ context.Context, bundleID, logical string, expected int64) ([]byte, error) {
	if err := store.ready(); err != nil {
		return nil, err
	}
	encrypted, err := store.API.ListRecords()
	if err != nil {
		return nil, err
	}
	records, err := client.DecryptRecords(store.API.Config.VaultID, store.VaultKey, encrypted)
	if err != nil {
		return nil, err
	}
	physical := bundle.PhysicalName(bundleID, logical)
	for _, record := range records {
		if record.Name == physical {
			if record.Revision != expected {
				return nil, fmt.Errorf("provider plan record %s is stale", logical)
			}
			return []byte(record.Value), nil
		}
	}
	return nil, fmt.Errorf("provider plan record %s is missing", logical)
}

func decodeStrict(raw json.RawMessage, destination any) error {
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
