package railway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/GeorgeQLe/envbank/internal/keychain"
)

const CredentialService = "com.envbank.provider.railway"

// CredentialAccount avoids putting the bundle name in Keychain metadata while
// keeping credentials isolated by vault and bundle.
func CredentialAccount(vaultID, bundleID string) (string, error) {
	if vaultID == "" || bundleID == "" {
		return "", errors.New("Railway credential account is incomplete")
	}
	sum := sha256.Sum256([]byte("envbank.railway.credential.v1\x00" + vaultID + "\x00" + bundleID))
	return "v1:" + hex.EncodeToString(sum[:]), nil
}

func LoadCredential(store keychain.Store, account string) ([]byte, error) {
	if store == nil || account == "" {
		return nil, errors.New("Railway credential storage is not configured")
	}
	credential, err := store.Get(CredentialService, account, "Use the Railway project credential for names-only planning")
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, errors.New("Railway project credential is not bound; run railway bind")
		}
		return nil, errors.New("Railway project credential could not be loaded")
	}
	return credential, nil
}
