package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	LocalIterations = 600_000
	formatVersion   = 1
)

type Blob struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type WrappedKey struct {
	Version      int    `json:"version"`
	EphemeralKey string `json:"ephemeral_key"`
	Blob         Blob   `json:"blob"`
}

type DeviceSecrets struct {
	SigningPrivate  string `json:"signing_private"`
	WrappingPrivate string `json:"wrapping_private"`
	VaultKey        string `json:"vault_key,omitempty"`
}

type DeviceKeys struct {
	SigningPublic  string
	WrappingPublic string
	Secrets        DeviceSecrets
}

func RandomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func NewDeviceKeys() (DeviceKeys, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceKeys{}, err
	}
	boxPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return DeviceKeys{}, err
	}
	return DeviceKeys{
		SigningPublic:  encode(signPub),
		WrappingPublic: encode(boxPriv.PublicKey().Bytes()),
		Secrets: DeviceSecrets{
			SigningPrivate:  encode(signPriv),
			WrappingPrivate: encode(boxPriv.Bytes()),
		},
	}, nil
}

func PublicFingerprint(signingPublic, wrappingPublic string) string {
	sum := sha256.Sum256([]byte("envbank.device.fingerprint.v1\x00" + signingPublic + "\x00" + wrappingPublic))
	return fmt.Sprintf("%x", sum[:8])
}

func DeriveKey(passphrase, salt []byte, iterations int) []byte {
	key, _ := pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, 32)
	return key
}

func Seal(key, plaintext, aad []byte) (Blob, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return Blob{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Blob{}, err
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return Blob{}, err
	}
	return Blob{
		Version:    formatVersion,
		Nonce:      encode(nonce),
		Ciphertext: encode(gcm.Seal(nil, nonce, plaintext, aad)),
	}, nil
}

func Open(key []byte, blob Blob, aad []byte) ([]byte, error) {
	if blob.Version != formatVersion {
		return nil, fmt.Errorf("unsupported encrypted format version %d", blob.Version)
	}
	nonce, err := decode(blob.Nonce)
	if err != nil {
		return nil, errors.New("invalid nonce encoding")
	}
	ciphertext, err := decode(blob.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid ciphertext encoding")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return plaintext, nil
}

func EncryptJSON(key []byte, value any, aad []byte) (Blob, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Blob{}, err
	}
	return Seal(key, raw, aad)
}

func DecryptJSON(key []byte, blob Blob, aad []byte, destination any) error {
	raw, err := Open(key, blob, aad)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return errors.New("decrypted data is invalid")
	}
	return nil
}

func RecordID(vaultKey []byte, name string) string {
	mac := hmac.New(sha256.New, vaultKey)
	mac.Write([]byte("envbank.record.id.v1\x00"))
	mac.Write([]byte(name))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func WrapVaultKey(vaultKey []byte, recipientPublic, vaultID, deviceID string) (WrappedKey, error) {
	pubBytes, err := decode(recipientPublic)
	if err != nil {
		return WrappedKey{}, errors.New("invalid wrapping public key")
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return WrappedKey{}, errors.New("invalid wrapping public key")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return WrappedKey{}, err
	}
	context := []byte("envbank.vault.wrap.v1\x00" + vaultID + "\x00" + deviceID)
	key, err := expandKey(shared, context)
	if err != nil {
		return WrappedKey{}, err
	}
	blob, err := Seal(key, vaultKey, context)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{Version: formatVersion, EphemeralKey: encode(ephemeral.PublicKey().Bytes()), Blob: blob}, nil
}

func UnwrapVaultKey(envelope WrappedKey, privateKey, vaultID, deviceID string) ([]byte, error) {
	if envelope.Version != formatVersion {
		return nil, fmt.Errorf("unsupported wrapped-key version %d", envelope.Version)
	}
	privBytes, err := decode(privateKey)
	if err != nil {
		return nil, errors.New("invalid local wrapping key")
	}
	ephemeralBytes, err := decode(envelope.EphemeralKey)
	if err != nil {
		return nil, errors.New("invalid ephemeral key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, errors.New("invalid local wrapping key")
	}
	pub, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, errors.New("invalid ephemeral key")
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	context := []byte("envbank.vault.wrap.v1\x00" + vaultID + "\x00" + deviceID)
	key, err := expandKey(shared, context)
	if err != nil {
		return nil, err
	}
	return Open(key, envelope.Blob, context)
}

func Sign(privateKey string, message []byte) (string, error) {
	raw, err := decode(privateKey)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", errors.New("invalid signing private key")
	}
	return encode(ed25519.Sign(ed25519.PrivateKey(raw), message)), nil
}

func Verify(publicKey string, message []byte, signature string) bool {
	pub, err := decode(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := decode(signature)
	return err == nil && ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

func Decode(value string) ([]byte, error) { return decode(value) }
func Encode(value []byte) string          { return encode(value) }

func expandKey(secret, context []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, string(context), 32)
}

func encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
