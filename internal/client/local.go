package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/GeorgeQLe/envbank/internal/secure"
)

const ConfigVersion = 2

// AccessCredentials are Cloudflare Access service-token credentials. They are
// only ever serialized inside EncryptedSecret.
type AccessCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type localSecretsV2 struct {
	Device secure.DeviceSecrets `json:"device"`
	Access *AccessCredentials   `json:"access,omitempty"`
}

type Config struct {
	Version          int         `json:"version"`
	Server           string      `json:"server"`
	VaultID          string      `json:"vault_id"`
	DeviceID         string      `json:"device_id"`
	DeviceName       string      `json:"device_name"`
	SigningPublic    string      `json:"signing_public"`
	WrappingPublic   string      `json:"wrapping_public"`
	RecoveryArtifact string      `json:"recovery_artifact,omitempty"`
	Salt             string      `json:"salt"`
	Iterations       int         `json:"iterations"`
	EncryptedSecret  secure.Blob `json:"encrypted_secret"`

	access   *AccessCredentials
	migrated bool
}

func NewConfig(server, vaultID, deviceID, deviceName string, keys secure.DeviceKeys, passphrase []byte) (*Config, error) {
	salt, err := secure.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Version: ConfigVersion, Server: server, VaultID: vaultID, DeviceID: deviceID,
		DeviceName: deviceName, SigningPublic: keys.SigningPublic,
		WrappingPublic: keys.WrappingPublic, Salt: secure.Encode(salt),
		Iterations: secure.LocalIterations,
	}
	if err := cfg.Lock(keys.Secrets, passphrase); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if (cfg.Version != 1 && cfg.Version != ConfigVersion) || cfg.Iterations < 100_000 || cfg.Iterations > 10_000_000 {
		return nil, errors.New("unsupported or unsafe config format")
	}
	return &cfg, nil
}

func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func (c *Config) Unlock(passphrase []byte) (secure.DeviceSecrets, error) {
	salt, err := secure.Decode(c.Salt)
	if err != nil {
		return secure.DeviceSecrets{}, errors.New("invalid config salt")
	}
	key := secure.DeriveKey(passphrase, salt, c.Iterations)
	if c.Version == 1 {
		var device secure.DeviceSecrets
		if err := secure.DecryptJSON(key, c.EncryptedSecret, c.localAAD(1), &device); err != nil {
			return secure.DeviceSecrets{}, errors.New("could not unlock config")
		}
		c.Version = ConfigVersion
		c.access = nil
		c.EncryptedSecret, err = secure.EncryptJSON(key, localSecretsV2{Device: device}, c.localAAD(ConfigVersion))
		if err != nil {
			c.Version = 1
			return secure.DeviceSecrets{}, errors.New("could not migrate config")
		}
		c.migrated = true
		return device, nil
	}
	var secrets localSecretsV2
	if err := secure.DecryptJSON(key, c.EncryptedSecret, c.localAAD(ConfigVersion), &secrets); err != nil {
		return secure.DeviceSecrets{}, errors.New("could not unlock config")
	}
	if secrets.Access != nil {
		if err := secrets.Access.Validate(); err != nil {
			return secure.DeviceSecrets{}, errors.New("encrypted Access credentials are invalid")
		}
		copy := *secrets.Access
		c.access = &copy
	} else {
		c.access = nil
	}
	return secrets.Device, nil
}

func (c *Config) Lock(secrets secure.DeviceSecrets, passphrase []byte) error {
	salt, err := secure.Decode(c.Salt)
	if err != nil {
		return errors.New("invalid config salt")
	}
	key := secure.DeriveKey(passphrase, salt, c.Iterations)
	if c.Version == 1 {
		c.EncryptedSecret, err = secure.EncryptJSON(key, secrets, c.localAAD(1))
		return err
	}
	c.Version = ConfigVersion
	payload := localSecretsV2{Device: secrets}
	if c.access != nil {
		copy := *c.access
		payload.Access = &copy
	}
	c.EncryptedSecret, err = secure.EncryptJSON(key, payload, c.localAAD(ConfigVersion))
	return err
}

func (c *Config) localAAD(version int) []byte {
	aad := fmt.Sprintf("envbank.local.v%d\x00", version) + c.Server + "\x00" + c.VaultID + "\x00" + c.DeviceID
	if c.RecoveryArtifact != "" {
		aad += "\x00recovery\x00" + c.RecoveryArtifact
	}
	return []byte(aad)
}

func (credentials AccessCredentials) Validate() error {
	if credentials.ClientID == "" || credentials.ClientSecret == "" ||
		len(credentials.ClientID) > 512 || len(credentials.ClientSecret) > 4096 ||
		strings.TrimSpace(credentials.ClientID) != credentials.ClientID ||
		strings.TrimSpace(credentials.ClientSecret) != credentials.ClientSecret {
		return errors.New("Cloudflare Access credentials are invalid")
	}
	for _, value := range []string{credentials.ClientID, credentials.ClientSecret} {
		for _, current := range value {
			if unicode.IsControl(current) {
				return errors.New("Cloudflare Access credentials are invalid")
			}
		}
	}
	return nil
}

// SetAccessCredentials updates the in-memory encrypted payload. The caller
// must have unlocked the config and must Lock and Save it afterwards.
func (c *Config) SetAccessCredentials(credentials AccessCredentials) error {
	if c.Version != ConfigVersion {
		return errors.New("config must be unlocked before binding Access credentials")
	}
	if err := credentials.Validate(); err != nil {
		return err
	}
	copy := credentials
	c.access = &copy
	return nil
}

func (c *Config) RemoveAccessCredentials() {
	c.access = nil
}

func (c *Config) AccessCredentials() *AccessCredentials {
	if c.access == nil {
		return nil
	}
	copy := *c.access
	return &copy
}

func (c *Config) Migrated() bool { return c.migrated }
