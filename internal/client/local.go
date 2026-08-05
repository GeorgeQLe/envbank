package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

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
}

func NewConfig(server, vaultID, deviceID, deviceName string, keys secure.DeviceKeys, passphrase []byte) (*Config, error) {
	salt, err := secure.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Version: 1, Server: server, VaultID: vaultID, DeviceID: deviceID,
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
	if cfg.Version != 1 || cfg.Iterations < 100_000 || cfg.Iterations > 10_000_000 {
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
	var secrets secure.DeviceSecrets
	if err := secure.DecryptJSON(key, c.EncryptedSecret, c.localAAD(), &secrets); err != nil {
		return secure.DeviceSecrets{}, errors.New("could not unlock config")
	}
	return secrets, nil
}

func (c *Config) Lock(secrets secure.DeviceSecrets, passphrase []byte) error {
	salt, err := secure.Decode(c.Salt)
	if err != nil {
		return errors.New("invalid config salt")
	}
	key := secure.DeriveKey(passphrase, salt, c.Iterations)
	c.EncryptedSecret, err = secure.EncryptJSON(key, secrets, c.localAAD())
	return err
}

func (c *Config) localAAD() []byte {
	aad := "envbank.local.v1\x00" + c.Server + "\x00" + c.VaultID + "\x00" + c.DeviceID
	if c.RecoveryArtifact != "" {
		aad += "\x00recovery\x00" + c.RecoveryArtifact
	}
	return []byte(aad)
}
