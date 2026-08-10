package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

// LoadSnapshot retrieves and strictly validates one encrypted bundle snapshot.
func LoadSnapshot(api *client.API, vaultKey []byte, bundleID string) (Snapshot, int64, error) {
	if api == nil || len(vaultKey) != 32 || bundleID == "" {
		return Snapshot{}, 0, errors.New("bundle snapshot store is not unlocked")
	}
	object, err := api.GetObject(vaultKey, vaultobject.KindBundleSnapshot, bundleID)
	if err != nil {
		return Snapshot{}, 0, err
	}
	var snapshot Snapshot
	decoder := json.NewDecoder(bytes.NewReader(object.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, 0, errors.New("encrypted bundle snapshot is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || snapshot.Validate() != nil ||
		snapshot.Bundle != bundleID {
		return Snapshot{}, 0, errors.New("encrypted bundle snapshot is invalid")
	}
	return snapshot, object.Revision, nil
}
