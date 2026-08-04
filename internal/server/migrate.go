package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func readLegacyState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, nil
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode legacy server state: %w", err)
	}
	if state.Version != 1 {
		return nil, fmt.Errorf("unsupported server state version %d", state.Version)
	}
	return &state, nil
}

func migrateLegacyState(path string, state State) (*Server, error) {
	migrationPath := path + ".migrating"
	if err := os.Remove(migrationPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	service, err := openDatabase(databaseDSN(migrationPath))
	if err != nil {
		return nil, err
	}
	if err := importLegacyState(service.db, state); err != nil {
		service.Close()
		_ = os.Remove(migrationPath)
		return nil, err
	}
	if err := service.Close(); err != nil {
		return nil, err
	}
	backupPath := path + ".json.bak"
	if _, err := os.Stat(backupPath); err == nil {
		_ = os.Remove(migrationPath)
		return nil, fmt.Errorf("legacy state backup already exists at %s", backupPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(path, backupPath); err != nil {
		_ = os.Remove(migrationPath)
		return nil, err
	}
	if err := os.Rename(migrationPath, path); err != nil {
		_ = os.Rename(backupPath, path)
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return openDatabase(databaseDSN(path))
}

func importLegacyState(db *sql.DB, state State) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, vault := range state.Vaults {
		if _, err := tx.Exec("INSERT INTO vaults(id, name, created_at) VALUES (?, ?, ?)",
			vault.ID, vault.Name, vault.CreatedAt); err != nil {
			return fmt.Errorf("import vault: %w", err)
		}
		for _, device := range vault.Devices {
			if err := insertDevice(tx, vault.ID, device); err != nil {
				return fmt.Errorf("import device: %w", err)
			}
		}
		for _, enrollment := range vault.Enrollments {
			var envelope []byte
			if enrollment.Envelope != nil {
				envelope, err = json.Marshal(enrollment.Envelope)
				if err != nil {
					return err
				}
			}
			device := enrollment.Device
			if _, err := tx.Exec(`INSERT INTO enrollments(
				vault_id, device_id, name, signing_public, wrapping_public, fingerprint,
				created_at, approved, envelope
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, vault.ID, device.ID, device.Name,
				device.SigningPublic, device.WrappingPublic, device.Fingerprint,
				device.CreatedAt, enrollment.Approved, envelope); err != nil {
				return fmt.Errorf("import enrollment: %w", err)
			}
		}
		for _, record := range vault.Records {
			blob, err := json.Marshal(record.Blob)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO records(vault_id, id, revision, blob, modified_at)
				VALUES (?, ?, ?, ?, ?)`, vault.ID, record.ID, record.Revision, blob,
				record.ModifiedAt); err != nil {
				return fmt.Errorf("import record: %w", err)
			}
		}
	}
	for key, createdAt := range state.Nonces {
		parts := bytes.SplitN([]byte(key), []byte{0}, 3)
		if len(parts) != 3 {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO nonces(
			vault_id, device_id, nonce, created_at
		) VALUES (?, ?, ?, ?)`, string(parts[0]), string(parts[1]), string(parts[2]), createdAt); err != nil {
			return fmt.Errorf("import nonce: %w", err)
		}
	}
	return tx.Commit()
}
