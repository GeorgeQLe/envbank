package cloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/GeorgeQLe/envbank/internal/keychain"
)

func CredentialAccount(vaultID, bundleID string) (string, error) {
	if vaultID == "" || bundleID == "" {
		return "", errors.New("Cloudflare credential account is incomplete")
	}
	sum := sha256.Sum256([]byte("envbank.cloudflare.credential.v1\x00" + vaultID + "\x00" + bundleID))
	return "v1:" + hex.EncodeToString(sum[:]), nil
}

func LoadCredential(store keychain.Store, account string) ([]byte, error) {
	if store == nil || account == "" {
		return nil, errors.New("Cloudflare credential storage is not configured")
	}
	credential, err := store.Get(CredentialService, account, "Use the Cloudflare Worker deployment credential")
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, errors.New("Cloudflare API token is not bound; run cloudflare bind")
		}
		return nil, errors.New("Cloudflare API token could not be loaded")
	}
	return credential, nil
}
