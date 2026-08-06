package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	_ "modernc.org/sqlite"
)

type State struct {
	Version int               `json:"version"`
	Vaults  map[string]*Vault `json:"vaults"`
	Nonces  map[string]string `json:"nonces"`
}

type Vault struct {
	ID          string                           `json:"id"`
	Name        string                           `json:"name"`
	Devices     map[string]protocol.PublicDevice `json:"devices"`
	Enrollments map[string]*Enrollment           `json:"enrollments"`
	Records     map[string]protocol.Record       `json:"records"`
	CreatedAt   string                           `json:"created_at"`
}

type Enrollment struct {
	Device    protocol.PublicDevice `json:"device"`
	Approved  bool                  `json:"approved"`
	Envelope  *secure.WrappedKey    `json:"envelope,omitempty"`
	RevokedAt string                `json:"revoked_at,omitempty"`
}

type Server struct {
	db       *sql.DB
	now      func() time.Time
	maxBytes int64
}

// Open opens or creates a SQLite database. An existing version-1 JSON state
// file is migrated in place after a backup is created beside it.
func Open(path string) (*Server, error) {
	if path == "" {
		return openDatabase("file::memory:?cache=shared&_busy_timeout=5000&_foreign_keys=on&_txlock=immediate")
	}
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	legacy, err := readLegacyState(path)
	if err != nil {
		return nil, err
	}
	if legacy != nil {
		return migrateLegacyState(path, *legacy)
	}
	service, err := openDatabase(databaseDSN(path))
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		service.Close()
		return nil, err
	}
	return service, nil
}

func databaseDSN(path string) string {
	dsn := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := dsn.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "wal")
	query.Set("_synchronous", "full")
	query.Set("_txlock", "immediate")
	dsn.RawQuery = query.Encode()
	return dsn.String()
}

func openDatabase(dsn string) (*Server, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A service process serializes its own transactions on one connection.
	// SQLite coordinates that connection with other service processes.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open server database: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Server{db: db, now: time.Now, maxBytes: 1 << 20}, nil
}

func (s *Server) Close() error {
	return s.db.Close()
}

func migrateSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if version > 5 {
		return fmt.Errorf("unsupported server database version %d", version)
	}
	if version == 1 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin database migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`ALTER TABLE devices ADD COLUMN revoked_at TEXT;
PRAGMA user_version = 2;`); err != nil {
			return fmt.Errorf("migrate database schema to version 2: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit database migration: %w", err)
		}
		version = 2
	}
	if version == 2 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin database migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(accessEventsSchema + "\nPRAGMA user_version = 3;"); err != nil {
			return fmt.Errorf("migrate database schema to version 3: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit database migration: %w", err)
		}
		version = 3
	}
	if version == 3 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin database migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(invitationMigrationSchema); err != nil {
			return fmt.Errorf("migrate database schema to version 4: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit database migration: %w", err)
		}
		version = 4
	}
	if version == 4 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin database migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`UPDATE nonces
SET created_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
PRAGMA user_version = 5;`); err != nil {
			return fmt.Errorf("migrate database schema to version 5: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit database migration: %w", err)
		}
		return nil
	}
	if version == 5 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	defer tx.Rollback()
	const schema = `
CREATE TABLE vaults (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE devices (
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	name TEXT NOT NULL,
	signing_public TEXT NOT NULL,
	wrapping_public TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT,
	PRIMARY KEY (vault_id, id)
);
CREATE TABLE enrollments (
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL,
	name TEXT NOT NULL,
	signing_public TEXT NOT NULL,
	wrapping_public TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	created_at TEXT NOT NULL,
	approved INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
	envelope BLOB,
	PRIMARY KEY (vault_id, device_id)
);
CREATE TABLE records (
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	blob BLOB NOT NULL,
	modified_at TEXT NOT NULL,
	PRIMARY KEY (vault_id, id)
);
CREATE TABLE nonces (
	vault_id TEXT NOT NULL,
	device_id TEXT NOT NULL,
	nonce TEXT NOT NULL,
	created_at TEXT NOT NULL,
	PRIMARY KEY (vault_id, device_id, nonce)
);
CREATE INDEX nonces_created_at ON nonces(created_at);
` + accessEventsSchema + invitationTableSchema + `
PRAGMA user_version = 5;`
	if _, err := tx.Exec(schema); err != nil {
		return fmt.Errorf("create database schema: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/v1/vaults" && r.Method == http.MethodPost {
		s.createVault(w, r)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "vaults" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	vaultID := parts[2]
	switch {
	case len(parts) == 4 && parts[3] == "invitations" && r.Method == http.MethodPost:
		s.createInvitation(w, r, vaultID)
	case len(parts) == 4 && parts[3] == "invitations" && r.Method == http.MethodGet:
		s.listInvitations(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "invitations" && r.Method == http.MethodGet:
		s.getInvitation(w, r, vaultID, parts[4])
	case len(parts) == 6 && parts[3] == "invitations" &&
		(parts[5] == "approve" || parts[5] == "reject" || parts[5] == "cancel") &&
		r.Method == http.MethodPost:
		s.transitionInvitation(w, r, vaultID, parts[4], parts[5])
	case len(parts) == 4 && parts[3] == "enrollments" && r.Method == http.MethodPost:
		s.requestEnrollment(w, r, vaultID)
	case len(parts) == 4 && parts[3] == "enrollments" && r.Method == http.MethodGet:
		s.listEnrollments(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "enrollments" && r.Method == http.MethodGet:
		s.getEnrollment(w, r, vaultID, parts[4])
	case len(parts) == 5 && parts[3] == "enrollments" && parts[4] != "" && r.Method == http.MethodPost:
		s.approveEnrollment(w, r, vaultID, parts[4])
	case len(parts) == 4 && parts[3] == "devices" && r.Method == http.MethodGet:
		s.listDevices(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "devices" && r.Method == http.MethodDelete:
		s.revokeDevice(w, r, vaultID, parts[4])
	case len(parts) == 4 && parts[3] == "records" && r.Method == http.MethodGet:
		s.listRecords(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "records" && r.Method == http.MethodPut:
		s.putRecord(w, r, vaultID, parts[4])
	case len(parts) == 4 && parts[3] == "access-events" && r.Method == http.MethodGet:
		s.listAccessEvents(w, r, vaultID)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	var request protocol.CreateVaultRequest
	if !decodeJSON(w, r, s.maxBytes, &request) {
		return
	}
	if request.Name == "" || request.Device.Name == "" ||
		request.Device.SigningPublic == "" || request.Device.WrappingPublic == "" {
		writeError(w, http.StatusBadRequest, "vault and device fields are required")
		return
	}
	if !validPublicDeviceKeys(request.Device.SigningPublic, request.Device.WrappingPublic) {
		writeError(w, http.StatusBadRequest, "invalid device public keys")
		return
	}
	vaultID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	deviceID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	now := s.now().UTC().Format(time.RFC3339)
	request.Device.ID = deviceID
	request.Device.CreatedAt = now
	request.Device.Fingerprint = secure.PublicFingerprint(request.Device.SigningPublic, request.Device.WrappingPublic)

	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO vaults(id, name, created_at) VALUES (?, ?, ?)", vaultID, request.Name, now); err != nil {
		writePersistError(w)
		return
	}
	if err := insertDevice(tx, vaultID, request.Device); err != nil {
		writePersistError(w)
		return
	}
	if !commit(w, tx) {
		return
	}
	writeJSON(w, http.StatusCreated, protocol.CreateVaultResponse{VaultID: vaultID, DeviceID: deviceID})
}

func (s *Server) requestEnrollment(w http.ResponseWriter, r *http.Request, vaultID string) {
	defer r.Body.Close()
	body, bodyErr := io.ReadAll(io.LimitReader(r.Body, s.maxBytes+1))
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	if !vaultExists(tx, vaultID) {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}
	var request protocol.EnrollmentRequest
	if bodyErr != nil || int64(len(body)) > s.maxBytes {
		s.bestEffortPublicRejection(w, tx, vaultID, http.StatusBadRequest,
			"request body is too large")
		return
	}
	if json.Unmarshal(body, &request) != nil {
		s.bestEffortPublicRejection(w, tx, vaultID, http.StatusBadRequest, "invalid JSON")
		return
	}
	if request.Name == "" ||
		request.SigningPublic == "" || request.WrappingPublic == "" {
		s.bestEffortPublicRejection(w, tx, vaultID, http.StatusBadRequest,
			"device fields are required")
		return
	}
	if !validPublicDeviceKeys(request.SigningPublic, request.WrappingPublic) {
		s.bestEffortPublicRejection(w, tx, vaultID, http.StatusBadRequest,
			"invalid device public keys")
		return
	}
	deviceID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	now := s.now().UTC().Format(time.RFC3339)
	device := protocol.PublicDevice{
		ID: deviceID, Name: request.Name, SigningPublic: request.SigningPublic,
		WrappingPublic: request.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(request.SigningPublic, request.WrappingPublic),
		CreatedAt:      now,
	}
	_, err = tx.Exec(`INSERT INTO enrollments(
		vault_id, device_id, name, signing_public, wrapping_public, fingerprint, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		vaultID, device.ID, device.Name, device.SigningPublic, device.WrappingPublic,
		device.Fingerprint, device.CreatedAt)
	if err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		targetIdentityID: device.ID, operation: "enrollment_request", outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, protocol.EnrollmentStatus{Device: device})
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "enrollment_list", false)
	if !authenticated {
		return
	}
	rows, err := tx.Query(`SELECT e.device_id, e.name, e.signing_public, e.wrapping_public,
		e.fingerprint, e.created_at, e.approved, d.revoked_at
		FROM enrollments e
		LEFT JOIN devices d ON d.vault_id = e.vault_id AND d.id = e.device_id
		WHERE e.vault_id = ? ORDER BY e.created_at, e.device_id`, vaultID)
	if err != nil {
		writePersistError(w)
		return
	}
	defer rows.Close()
	out := []protocol.EnrollmentStatus{}
	for rows.Next() {
		var status protocol.EnrollmentStatus
		var revokedAt sql.NullString
		if err := rows.Scan(&status.Device.ID, &status.Device.Name, &status.Device.SigningPublic,
			&status.Device.WrappingPublic, &status.Device.Fingerprint, &status.Device.CreatedAt,
			&status.Approved, &revokedAt); err != nil {
			writePersistError(w)
			return
		}
		status.RevokedAt = revokedAt.String
		out = append(out, status)
	}
	if rows.Err() != nil {
		writePersistError(w)
		return
	}
	if err := rows.Close(); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request, vaultID, enrollmentID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "enrollment_status", true)
	if !authenticated {
		return
	}
	enrollment, err := getEnrollmentTx(tx, vaultID, enrollmentID)
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusNotFound,
			"enrollment not found", "not_found")
		return
	}
	if err != nil {
		writePersistError(w)
		return
	}
	if auth.identityID != enrollment.Device.ID {
		if !s.finishEvent(w, tx, vaultID, eventDetails{
			identityID: auth.identityID, identityVerified: true,
			targetIdentityID: enrollmentID, operation: auth.operation,
			outcome: "denied", reason: "invalid_request",
		}) {
			return
		}
		writeError(w, http.StatusUnauthorized, "device mismatch")
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: enrollmentID, operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollmentStatus{
		Device: enrollment.Device, Approved: enrollment.Approved, Envelope: enrollment.Envelope,
		RevokedAt: enrollment.RevokedAt,
	})
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request, vaultID, enrollmentID string) {
	body, ok := readBody(w, r, s.maxBytes)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "enrollment_approval", false)
	if !authenticated {
		return
	}
	var request protocol.EnrollmentApproval
	if err := json.Unmarshal(body, &request); err != nil {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusBadRequest,
			"invalid JSON", "invalid_request")
		return
	}
	envelope, err := json.Marshal(request.Envelope)
	if err != nil {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusBadRequest,
			"invalid envelope", "invalid_request")
		return
	}
	enrollment, err := getEnrollmentTx(tx, vaultID, enrollmentID)
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusNotFound,
			"enrollment not found", "not_found")
		return
	}
	if err != nil {
		writePersistError(w)
		return
	}
	if enrollment.Approved {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusConflict,
			"enrollment already approved", "already_approved")
		return
	}
	var invitationExists int
	err = tx.QueryRow(`SELECT 1 FROM invitations
		WHERE vault_id = ? AND device_id = ?`, vaultID, enrollmentID).Scan(&invitationExists)
	if err == nil {
		s.rejectEvent(w, tx, vaultID, auth, enrollmentID, http.StatusConflict,
			"invitation must use versioned approval endpoint", "terminal_conflict")
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writePersistError(w)
		return
	}
	if _, err := tx.Exec(`UPDATE enrollments SET approved = 1, envelope = ?
		WHERE vault_id = ? AND device_id = ? AND approved = 0`, envelope, vaultID, enrollmentID); err != nil {
		writePersistError(w)
		return
	}
	if err := insertDevice(tx, vaultID, enrollment.Device); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: enrollmentID, operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollmentStatus{Device: enrollment.Device, Approved: true})
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "record_list", false)
	if !authenticated {
		return
	}
	rows, err := tx.Query("SELECT id, revision, blob, modified_at FROM records WHERE vault_id = ?", vaultID)
	if err != nil {
		writePersistError(w)
		return
	}
	defer rows.Close()
	out := []protocol.Record{}
	for rows.Next() {
		var record protocol.Record
		var blob []byte
		if err := rows.Scan(&record.ID, &record.Revision, &blob, &record.ModifiedAt); err != nil ||
			json.Unmarshal(blob, &record.Blob) != nil {
			writePersistError(w)
			return
		}
		out = append(out, record)
	}
	if rows.Err() != nil {
		writePersistError(w)
		return
	}
	if err := rows.Close(); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "device_list", false)
	if !authenticated {
		return
	}
	rows, err := tx.Query(`SELECT id, name, signing_public, wrapping_public, fingerprint,
		created_at, revoked_at FROM devices WHERE vault_id = ? ORDER BY created_at, id`, vaultID)
	if err != nil {
		writePersistError(w)
		return
	}
	defer rows.Close()
	out := []protocol.DeviceStatus{}
	for rows.Next() {
		var status protocol.DeviceStatus
		var revokedAt sql.NullString
		if err := rows.Scan(&status.Device.ID, &status.Device.Name, &status.Device.SigningPublic,
			&status.Device.WrappingPublic, &status.Device.Fingerprint, &status.Device.CreatedAt,
			&revokedAt); err != nil {
			writePersistError(w)
			return
		}
		status.RevokedAt = revokedAt.String
		out = append(out, status)
	}
	if rows.Err() != nil {
		writePersistError(w)
		return
	}
	if err := rows.Close(); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, vaultID, deviceID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "device_revocation", false)
	if !authenticated {
		return
	}
	target, err := getDeviceStatusTx(tx, vaultID, deviceID, false)
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusNotFound,
			"device not found", "not_found")
		return
	}
	if err != nil {
		writePersistError(w)
		return
	}
	if target.RevokedAt != "" {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusConflict,
			"device already revoked", "already_revoked")
		return
	}
	var active int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE vault_id = ? AND revoked_at IS NULL`, vaultID).Scan(&active); err != nil {
		writePersistError(w)
		return
	}
	if active <= 1 {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusConflict,
			"cannot revoke the final active device", "final_active_device")
		return
	}
	target.RevokedAt = s.now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`UPDATE devices SET revoked_at = ?
		WHERE vault_id = ? AND id = ? AND revoked_at IS NULL`,
		target.RevokedAt, vaultID, deviceID)
	if err != nil {
		writePersistError(w)
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writePersistError(w)
		return
	}
	if updated != 1 {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusConflict,
			"device already revoked", "already_revoked")
		return
	}
	if _, err := tx.Exec("DELETE FROM nonces WHERE vault_id = ? AND device_id = ?",
		vaultID, deviceID); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: deviceID, operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (s *Server) putRecord(w http.ResponseWriter, r *http.Request, vaultID, recordID string) {
	body, ok := readBody(w, r, s.maxBytes)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "record_update", false)
	if !authenticated {
		return
	}
	var request protocol.PutRecordRequest
	if err := json.Unmarshal(body, &request); err != nil {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest,
			"invalid JSON", "invalid_request")
		return
	}
	blob, err := json.Marshal(request.Blob)
	if err != nil {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest,
			"invalid encrypted record", "invalid_request")
		return
	}
	var current int64
	err = tx.QueryRow("SELECT revision FROM records WHERE vault_id = ? AND id = ?", vaultID, recordID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writePersistError(w)
		return
	}
	if current != request.ExpectedRevision {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusConflict,
			fmt.Sprintf("revision conflict: current revision is %d", current), "revision_conflict")
		return
	}
	record := protocol.Record{
		ID: recordID, Revision: current + 1, Blob: request.Blob,
		ModifiedAt: s.now().UTC().Format(time.RFC3339),
	}
	if current == 0 {
		_, err = tx.Exec(`INSERT INTO records(vault_id, id, revision, blob, modified_at)
			VALUES (?, ?, ?, ?, ?)`, vaultID, record.ID, record.Revision, blob, record.ModifiedAt)
	} else {
		_, err = tx.Exec(`UPDATE records SET revision = ?, blob = ?, modified_at = ?
			WHERE vault_id = ? AND id = ? AND revision = ?`,
			record.Revision, blob, record.ModifiedAt, vaultID, record.ID, current)
	}
	if err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) listAccessEvents(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "event_list", false)
	if !authenticated {
		return
	}
	limit, before, err := parseAccessEventPage(
		r.URL.Query().Get("limit"), r.URL.Query().Get("before"))
	if err != nil {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest,
			err.Error(), "invalid_request")
		return
	}
	if err := s.insertAccessEvent(tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		operation: auth.operation, outcome: "succeeded",
	}); err != nil {
		writePersistError(w)
		return
	}

	query := `SELECT sequence, id, vault_id, timestamp, identity_id,
		identity_verified, target_identity_id, operation, outcome, reason
		FROM access_events WHERE vault_id = ?`
	args := []any{vaultID}
	if before != 0 {
		query += " AND sequence < ?"
		args = append(args, before)
	}
	query += " ORDER BY sequence DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := tx.Query(query, args...)
	if err != nil {
		writePersistError(w)
		return
	}
	events := make([]protocol.AccessEvent, 0, limit)
	var lastSequence int64
	var hasMore bool
	for rows.Next() {
		sequence, event, err := scanAccessEvent(rows)
		if err != nil {
			_ = rows.Close()
			writePersistError(w)
			return
		}
		if len(events) == limit {
			hasMore = true
			break
		}
		events = append(events, event)
		lastSequence = sequence
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writePersistError(w)
		return
	}
	if err := rows.Close(); err != nil {
		writePersistError(w)
		return
	}
	if !commit(w, tx) {
		return
	}
	page := protocol.AccessEventPage{Events: events}
	if hasMore {
		page.NextCursor = encodeEventCursor(lastSequence)
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) begin(w http.ResponseWriter) (*sql.Tx, bool) {
	tx, err := s.db.Begin()
	if err != nil {
		writePersistError(w)
		return nil, false
	}
	return tx, true
}

type authenticatedRequest struct {
	identityID string
	operation  string
}

// authenticateDevice verifies identity before applying authorization policy.
// A valid signature is attributed even when its device is pending or revoked.
func (s *Server) authenticateDevice(
	w http.ResponseWriter,
	r *http.Request,
	tx *sql.Tx,
	vaultID string,
	body []byte,
	operation string,
	allowPending bool,
) (*authenticatedRequest, bool) {
	if !vaultExists(tx, vaultID) {
		writeError(w, http.StatusNotFound, "vault not found")
		return nil, false
	}

	claimedID := r.Header.Get(protocol.HeaderDevice)
	var device protocol.PublicDevice
	var authorizationReason string
	status, err := getDeviceStatusTx(tx, vaultID, claimedID, false)
	switch {
	case err == nil:
		device = status.Device
		if status.RevokedAt != "" {
			authorizationReason = "revoked_device"
		}
	case !errors.Is(err, sql.ErrNoRows):
		writePersistError(w)
		return nil, false
	default:
		enrollment, enrollmentErr := getEnrollmentTx(tx, vaultID, claimedID)
		if enrollmentErr == nil {
			device = enrollment.Device
			if !allowPending {
				authorizationReason = "pending_device"
			}
		} else if !errors.Is(enrollmentErr, sql.ErrNoRows) {
			writePersistError(w)
			return nil, false
		}
	}

	if device.ID == "" {
		s.authenticationFailure(w, tx, vaultID, eventDetails{
			operation: operation, outcome: "denied", reason: "unknown_device",
		}, false, http.StatusUnauthorized, "unknown device")
		return nil, false
	}

	timestamp := r.Header.Get(protocol.HeaderTimestamp)
	nonce := r.Header.Get(protocol.HeaderNonce)
	signature := r.Header.Get(protocol.HeaderSignature)
	message := protocol.SignatureMessage(r.Method, r.URL.RequestURI(), timestamp, nonce, body)
	if signature == "" || !secure.Verify(device.SigningPublic, message, signature) {
		s.authenticationFailure(w, tx, vaultID, eventDetails{
			identityID: device.ID, operation: operation, outcome: "denied",
			reason: "invalid_signature",
		}, false, http.StatusUnauthorized, "invalid request signature")
		return nil, false
	}

	serverNow := s.now().UTC()
	if protocol.ValidateTimestamp(timestamp, serverNow) != nil ||
		protocol.ValidateNonce(nonce) != nil {
		s.authenticationFailure(w, tx, vaultID, eventDetails{
			identityID: device.ID, identityVerified: true, operation: operation,
			outcome: "denied", reason: "stale_timestamp",
		}, true, http.StatusUnauthorized, "invalid authentication headers")
		return nil, false
	}

	result, err := tx.Exec(`INSERT INTO nonces(vault_id, device_id, nonce, created_at)
		VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`, vaultID, device.ID, nonce,
		serverNow.Format(time.RFC3339))
	if err != nil {
		writePersistError(w)
		return nil, false
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		writePersistError(w)
		return nil, false
	}
	if inserted == 0 {
		s.authenticationFailure(w, tx, vaultID, eventDetails{
			identityID: device.ID, identityVerified: true, operation: operation,
			outcome: "denied", reason: "replay",
		}, true, http.StatusUnauthorized, "replayed request")
		return nil, false
	}
	cutoff := serverNow.Add(-10 * time.Minute).Format(time.RFC3339)
	if _, err := tx.Exec("DELETE FROM nonces WHERE created_at < ?", cutoff); err != nil {
		writePersistError(w)
		return nil, false
	}
	if authorizationReason != "" {
		s.authenticationFailure(w, tx, vaultID, eventDetails{
			identityID: device.ID, identityVerified: true, operation: operation,
			outcome: "denied", reason: authorizationReason,
		}, true, http.StatusUnauthorized, "unknown device")
		return nil, false
	}
	return &authenticatedRequest{identityID: device.ID, operation: operation}, true
}

func (s *Server) authenticationFailure(
	w http.ResponseWriter,
	tx *sql.Tx,
	vaultID string,
	event eventDetails,
	verified bool,
	status int,
	message string,
) {
	if err := s.insertAccessEvent(tx, vaultID, event); err != nil {
		_ = tx.Rollback()
		if verified {
			writePersistError(w)
			return
		}
		writeError(w, status, message)
		return
	}
	if err := tx.Commit(); err != nil {
		if verified {
			writePersistError(w)
			return
		}
	}
	writeError(w, status, message)
}

func (s *Server) finishEvent(w http.ResponseWriter, tx *sql.Tx, vaultID string, event eventDetails) bool {
	if err := s.insertAccessEvent(tx, vaultID, event); err != nil {
		writePersistError(w)
		return false
	}
	return commit(w, tx)
}

func (s *Server) rejectEvent(
	w http.ResponseWriter,
	tx *sql.Tx,
	vaultID string,
	auth *authenticatedRequest,
	targetID string,
	status int,
	message string,
	reason string,
) {
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: targetID, operation: auth.operation,
		outcome: "rejected", reason: reason,
	}) {
		return
	}
	writeError(w, status, message)
}

func (s *Server) bestEffortPublicRejection(
	w http.ResponseWriter,
	tx *sql.Tx,
	vaultID string,
	status int,
	message string,
) {
	if err := s.insertAccessEvent(tx, vaultID, eventDetails{
		operation: "enrollment_request", outcome: "rejected", reason: "invalid_request",
	}); err != nil {
		_ = tx.Rollback()
		writeError(w, status, message)
		return
	}
	_ = tx.Commit()
	writeError(w, status, message)
}

func getDeviceStatusTx(tx *sql.Tx, vaultID, deviceID string, activeOnly bool) (protocol.DeviceStatus, error) {
	var status protocol.DeviceStatus
	var revokedAt sql.NullString
	query := `SELECT id, name, signing_public, wrapping_public, fingerprint, created_at,
		revoked_at FROM devices WHERE vault_id = ? AND id = ?`
	if activeOnly {
		query += " AND revoked_at IS NULL"
	}
	err := tx.QueryRow(query, vaultID, deviceID).
		Scan(&status.Device.ID, &status.Device.Name, &status.Device.SigningPublic,
			&status.Device.WrappingPublic, &status.Device.Fingerprint, &status.Device.CreatedAt,
			&revokedAt)
	status.RevokedAt = revokedAt.String
	return status, err
}

func getEnrollmentTx(tx *sql.Tx, vaultID, deviceID string) (*Enrollment, error) {
	enrollment := &Enrollment{}
	var envelope []byte
	var revokedAt sql.NullString
	err := tx.QueryRow(`SELECT e.device_id, e.name, e.signing_public, e.wrapping_public,
		e.fingerprint, e.created_at, e.approved, e.envelope, d.revoked_at
		FROM enrollments e
		LEFT JOIN devices d ON d.vault_id = e.vault_id AND d.id = e.device_id
		WHERE e.vault_id = ? AND e.device_id = ?`, vaultID, deviceID).
		Scan(&enrollment.Device.ID, &enrollment.Device.Name, &enrollment.Device.SigningPublic,
			&enrollment.Device.WrappingPublic, &enrollment.Device.Fingerprint,
			&enrollment.Device.CreatedAt, &enrollment.Approved, &envelope, &revokedAt)
	if err != nil {
		return nil, err
	}
	enrollment.RevokedAt = revokedAt.String
	if len(envelope) > 0 {
		enrollment.Envelope = &secure.WrappedKey{}
		if err := json.Unmarshal(envelope, enrollment.Envelope); err != nil {
			return nil, err
		}
	}
	return enrollment, nil
}

func insertDevice(tx *sql.Tx, vaultID string, device protocol.PublicDevice) error {
	_, err := tx.Exec(`INSERT INTO devices(
		vault_id, id, name, signing_public, wrapping_public, fingerprint, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, vaultID, device.ID, device.Name,
		device.SigningPublic, device.WrappingPublic, device.Fingerprint, device.CreatedAt)
	return err
}

func vaultExists(tx *sql.Tx, vaultID string) bool {
	var exists int
	return tx.QueryRow("SELECT 1 FROM vaults WHERE id = ?", vaultID).Scan(&exists) == nil
}

func commit(w http.ResponseWriter, tx *sql.Tx) bool {
	if err := tx.Commit(); err != nil {
		writePersistError(w)
		return false
	}
	return true
}

func writePersistError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "could not persist state")
}

func randomID() (string, error) {
	raw, err := secure.RandomBytes(18)
	if err != nil {
		return "", err
	}
	return secure.Encode(raw), nil
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		writeError(w, http.StatusBadRequest, "request body is too large")
		return nil, false
	}
	return raw, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, destination any) bool {
	raw, ok := readBody(w, r, limit)
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
