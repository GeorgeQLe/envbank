package client

import (
	"encoding/json"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

func (a *API) ListObjects(vaultKey []byte) ([]vaultobject.VaultObject, error) {
	encrypted, err := a.ListVaultObjects()
	if err != nil {
		return nil, err
	}
	return vaultobject.DecryptAll(a.Config.VaultID, vaultKey, encrypted)
}

func (a *API) GetObject(vaultKey []byte, kind, key string) (vaultobject.VaultObject, error) {
	id := vaultobject.ID(vaultKey, kind, key)
	encrypted, err := a.GetVaultObject(id)
	if err != nil {
		return vaultobject.VaultObject{}, err
	}
	return vaultobject.Decrypt(a.Config.VaultID, vaultKey, encrypted)
}

// PutObject encrypts a typed payload and performs an optimistic create/update.
func (a *API) PutObject(vaultKey []byte, kind, key string, payload any, expectedRevision int64) (vaultobject.VaultObject, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return vaultobject.VaultObject{}, err
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	object := vaultobject.VaultObject{
		Kind: kind, Key: key, Revision: expectedRevision + 1,
		ModifiedAt: now().UTC().Format(time.RFC3339), Payload: raw,
	}
	id, blob, err := vaultobject.Encrypt(a.Config.VaultID, vaultKey, object)
	if err != nil {
		return vaultobject.VaultObject{}, err
	}
	stored, err := a.PutVaultObject(id, protocol.PutVaultObjectRequest{
		ExpectedRevision: expectedRevision, ModifiedAt: object.ModifiedAt, Blob: blob,
	})
	if err != nil {
		return vaultobject.VaultObject{}, err
	}
	return vaultobject.Decrypt(a.Config.VaultID, vaultKey, stored)
}

func (a *API) DeleteObject(vaultKey []byte, kind, key string, expectedRevision int64) error {
	return a.DeleteVaultObject(vaultobject.ID(vaultKey, kind, key), expectedRevision)
}
