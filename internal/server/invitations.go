package server

import (
	"bytes"
	"crypto/ecdh"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

const (
	invitationLifetime    = 10 * time.Minute
	invitationMaxAttempts = 5
)

const invitationTableSchema = `
CREATE TABLE IF NOT EXISTS invitations (
	vault_id TEXT NOT NULL,
	device_id TEXT NOT NULL,
	protocol_version INTEGER NOT NULL,
	state TEXT NOT NULL CHECK (state IN (
		'pending', 'approved', 'cancelled', 'rejected', 'expired',
		'attempts_exhausted'
	)),
	expires_at TEXT NOT NULL,
	failed_attempts INTEGER NOT NULL DEFAULT 0
		CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
	terminal_at TEXT,
	terminal_actor TEXT,
	PRIMARY KEY (vault_id, device_id),
	FOREIGN KEY (vault_id, device_id)
		REFERENCES enrollments(vault_id, device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS invitations_vault_state_expiry
	ON invitations(vault_id, state, expires_at);
`

// SQLite cannot widen a CHECK constraint in place, so version 4 rebuilds the
// access-event table while copying its stable sequence and public event IDs.
const invitationMigrationSchema = `
ALTER TABLE access_events RENAME TO access_events_v3;
DROP INDEX access_events_vault_sequence;
DROP INDEX access_events_pruning;
` + accessEventsSchema + `
INSERT INTO access_events(
	sequence, id, vault_id, timestamp, identity_id, identity_verified,
	target_identity_id, operation, outcome, reason
)
SELECT sequence, id, vault_id, timestamp, identity_id, identity_verified,
	target_identity_id, operation, outcome, reason
FROM access_events_v3 ORDER BY sequence;
DROP TABLE access_events_v3;
` + invitationTableSchema + `
PRAGMA user_version = 4;
`

type invitationRow struct {
	status         protocol.InvitationStatus
	failedAttempts int
	terminalActor  string
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request, vaultID string) {
	defer r.Body.Close()
	body, bodyErr := readLimitedBody(r, s.maxBytes)
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	if !vaultExists(tx, vaultID) {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}
	var request protocol.InvitationRequest
	if bodyErr != nil || decodeStrictJSON(body, &request) != nil {
		s.bestEffortInvitationCreationRejection(w, tx, vaultID, "invalid invitation request")
		return
	}
	if request.Version != protocol.InvitationProtocolVersion {
		s.bestEffortInvitationCreationRejection(w, tx, vaultID, "unsupported invitation version")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 64 ||
		strings.IndexFunc(request.Name, unicode.IsControl) >= 0 ||
		request.SigningPublic == "" || request.WrappingPublic == "" {
		s.bestEffortInvitationCreationRejection(w, tx, vaultID, "device fields are required")
		return
	}
	if !validPublicDeviceKeys(request.SigningPublic, request.WrappingPublic) {
		s.bestEffortInvitationCreationRejection(w, tx, vaultID, "invalid device public keys")
		return
	}
	deviceID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	now := s.now().UTC()
	device := protocol.PublicDevice{
		ID: deviceID, Name: request.Name, SigningPublic: request.SigningPublic,
		WrappingPublic: request.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(request.SigningPublic, request.WrappingPublic),
		CreatedAt:      now.Format(time.RFC3339),
	}
	if _, err := tx.Exec(`INSERT INTO enrollments(
		vault_id, device_id, name, signing_public, wrapping_public, fingerprint, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, vaultID, device.ID, device.Name,
		device.SigningPublic, device.WrappingPublic, device.Fingerprint,
		device.CreatedAt); err != nil {
		writePersistError(w)
		return
	}
	expiresAt := now.Add(invitationLifetime).Format(time.RFC3339)
	if _, err := tx.Exec(`INSERT INTO invitations(
		vault_id, device_id, protocol_version, state, expires_at
	) VALUES (?, ?, ?, ?, ?)`, vaultID, device.ID, request.Version,
		protocol.InvitationPending, expiresAt); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		targetIdentityID: device.ID, operation: "invitation_creation", outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, protocol.InvitationStatus{
		Version: request.Version, Device: device, State: protocol.InvitationPending,
		ExpiresAt: expiresAt, AttemptsRemaining: invitationMaxAttempts,
	})
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "invitation_list", false)
	if !authenticated {
		return
	}
	if !s.expireInvitations(w, tx, vaultID, "") {
		return
	}
	rows, err := tx.Query(`SELECT i.device_id, e.name, e.signing_public,
		e.wrapping_public, e.fingerprint, e.created_at, i.protocol_version,
		i.state, i.expires_at, i.failed_attempts, i.terminal_at, i.terminal_actor
		FROM invitations i JOIN enrollments e
			ON e.vault_id = i.vault_id AND e.device_id = i.device_id
		WHERE i.vault_id = ? ORDER BY e.created_at, i.device_id`, vaultID)
	if err != nil {
		writePersistError(w)
		return
	}
	out := []protocol.InvitationStatus{}
	for rows.Next() {
		row, err := scanInvitation(rows)
		if err != nil {
			_ = rows.Close()
			writePersistError(w)
			return
		}
		out = append(out, row.status)
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

func (s *Server) getInvitation(w http.ResponseWriter, r *http.Request, vaultID, deviceID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "invitation_status", true)
	if !authenticated {
		return
	}
	row, err := getInvitationTx(tx, vaultID, deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusNotFound,
			"invitation not found", "not_found")
		return
	}
	if err != nil {
		writePersistError(w)
		return
	}
	active := actorIsActive(tx, vaultID, auth.identityID)
	if !active && auth.identityID != deviceID {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusUnauthorized,
			"device cannot inspect invitation", "incorrect_actor")
		return
	}
	if !s.expireInvitation(w, tx, vaultID, &row) {
		return
	}
	if row.status.State == protocol.InvitationApproved && auth.identityID == deviceID {
		enrollment, err := getEnrollmentTx(tx, vaultID, deviceID)
		if err != nil {
			writePersistError(w)
			return
		}
		row.status.Envelope = enrollment.Envelope
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: deviceID, operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, row.status)
}

func (s *Server) transitionInvitation(
	w http.ResponseWriter,
	r *http.Request,
	vaultID, deviceID, action string,
) {
	body, ok := readBody(w, r, s.maxBytes)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	operation := map[string]string{
		"approve": "invitation_approval",
		"reject":  "invitation_rejection",
		"cancel":  "invitation_cancellation",
	}[action]
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, operation, true)
	if !authenticated {
		return
	}
	row, err := getInvitationTx(tx, vaultID, deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusNotFound,
			"invitation not found", "not_found")
		return
	}
	if err != nil {
		writePersistError(w)
		return
	}
	if !s.expireInvitation(w, tx, vaultID, &row) {
		return
	}
	if row.status.State != protocol.InvitationPending {
		s.rejectEvent(w, tx, vaultID, auth, deviceID, http.StatusConflict,
			"invitation is "+row.status.State, terminalReason(row.status.State))
		return
	}

	var transition protocol.InvitationTransition
	var approval protocol.InvitationApproval
	var decodeErr error
	if action == "approve" {
		decodeErr = decodeStrictJSON(body, &approval)
		transition = protocol.InvitationTransition{
			Version: approval.Version, DeviceID: approval.DeviceID,
			Fingerprint: approval.Fingerprint,
		}
	} else {
		decodeErr = decodeStrictJSON(body, &transition)
	}
	active := actorIsActive(tx, vaultID, auth.identityID)
	roleOK := (action == "cancel" && auth.identityID == deviceID && !active) ||
		(action != "cancel" && active)
	bindingOK := decodeErr == nil &&
		transition.Version == row.status.Version &&
		transition.DeviceID == row.status.Device.ID &&
		transition.Fingerprint == row.status.Device.Fingerprint
	envelopeOK := action != "approve" || validEnvelope(approval.Envelope)
	if !roleOK || !bindingOK || !envelopeOK {
		reason := "binding_mismatch"
		message := "invitation transition binding mismatch"
		if !roleOK {
			reason, message = "incorrect_actor", "device cannot perform invitation transition"
		} else if decodeErr != nil {
			reason, message = "invalid_request", "invalid invitation transition"
		} else if transition.Version != row.status.Version {
			reason, message = "unsupported_version", "invitation version mismatch"
		}
		s.failInvitationAttempt(w, tx, vaultID, auth, &row, operation, reason, message)
		return
	}

	now := s.now().UTC().Format(time.RFC3339)
	nextState := map[string]string{
		"approve": protocol.InvitationApproved,
		"reject":  protocol.InvitationRejected,
		"cancel":  protocol.InvitationCancelled,
	}[action]
	if action == "approve" {
		envelope, err := json.Marshal(approval.Envelope)
		if err != nil {
			s.failInvitationAttempt(w, tx, vaultID, auth, &row, operation,
				"invalid_request", "invalid wrapped envelope")
			return
		}
		result, err := tx.Exec(`UPDATE invitations SET state = ?, terminal_at = ?,
			terminal_actor = ? WHERE vault_id = ? AND device_id = ? AND state = ?`,
			nextState, now, auth.identityID, vaultID, deviceID, protocol.InvitationPending)
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
				"invitation already transitioned", "terminal_conflict")
			return
		}
		result, err = tx.Exec(`UPDATE enrollments SET approved = 1, envelope = ?
			WHERE vault_id = ? AND device_id = ? AND approved = 0`,
			envelope, vaultID, deviceID)
		if err != nil {
			writePersistError(w)
			return
		}
		updated, err = result.RowsAffected()
		if err != nil || updated != 1 {
			writePersistError(w)
			return
		}
		if err := insertDevice(tx, vaultID, row.status.Device); err != nil {
			writePersistError(w)
			return
		}
	} else {
		result, err := tx.Exec(`UPDATE invitations SET state = ?, terminal_at = ?,
			terminal_actor = ? WHERE vault_id = ? AND device_id = ? AND state = ?`,
			nextState, now, auth.identityID, vaultID, deviceID, protocol.InvitationPending)
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
				"invitation already transitioned", "terminal_conflict")
			return
		}
	}
	row.status.State, row.status.TerminalAt, row.terminalActor =
		nextState, now, auth.identityID
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: deviceID, operation: operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, row.status)
}

func (s *Server) failInvitationAttempt(
	w http.ResponseWriter,
	tx *sql.Tx,
	vaultID string,
	auth *authenticatedRequest,
	row *invitationRow,
	operation, reason, message string,
) {
	row.failedAttempts++
	state := protocol.InvitationPending
	var terminalAt, terminalActor any
	if row.failedAttempts >= invitationMaxAttempts {
		state = protocol.InvitationAttemptsExhausted
		now := s.now().UTC().Format(time.RFC3339)
		terminalAt, terminalActor = now, auth.identityID
		row.status.TerminalAt, row.terminalActor = now, auth.identityID
		reason = "attempt_exhaustion"
	}
	result, err := tx.Exec(`UPDATE invitations SET failed_attempts = ?, state = ?,
		terminal_at = ?, terminal_actor = ?
		WHERE vault_id = ? AND device_id = ? AND state = ?`,
		row.failedAttempts, state, terminalAt, terminalActor, vaultID,
		row.status.Device.ID, protocol.InvitationPending)
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
		s.rejectEvent(w, tx, vaultID, auth, row.status.Device.ID, http.StatusConflict,
			"invitation already transitioned", "terminal_conflict")
		return
	}
	row.status.State = state
	row.status.AttemptsRemaining = invitationMaxAttempts - row.failedAttempts
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true,
		targetIdentityID: row.status.Device.ID, operation: operation,
		outcome: "rejected", reason: reason,
	}) {
		return
	}
	if state == protocol.InvitationAttemptsExhausted {
		writeError(w, http.StatusConflict, "invitation attempts exhausted")
		return
	}
	writeError(w, http.StatusBadRequest, message)
}

func (s *Server) expireInvitation(
	w http.ResponseWriter,
	tx *sql.Tx,
	vaultID string,
	row *invitationRow,
) bool {
	if row.status.State != protocol.InvitationPending {
		return true
	}
	expiresAt, err := time.Parse(time.RFC3339, row.status.ExpiresAt)
	if err != nil {
		writePersistError(w)
		return false
	}
	if s.now().Before(expiresAt) {
		return true
	}
	now := s.now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`UPDATE invitations SET state = ?, terminal_at = ?,
		terminal_actor = 'server' WHERE vault_id = ? AND device_id = ? AND state = ?`,
		protocol.InvitationExpired, now, vaultID, row.status.Device.ID,
		protocol.InvitationPending)
	if err != nil {
		writePersistError(w)
		return false
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writePersistError(w)
		return false
	}
	if updated == 1 {
		if err := s.insertAccessEvent(tx, vaultID, eventDetails{
			targetIdentityID: row.status.Device.ID, operation: "invitation_expiry",
			outcome: "succeeded", reason: "expired",
		}); err != nil {
			writePersistError(w)
			return false
		}
	}
	row.status.State, row.status.TerminalAt, row.terminalActor =
		protocol.InvitationExpired, now, "server"
	return true
}

func (s *Server) expireInvitations(w http.ResponseWriter, tx *sql.Tx, vaultID, deviceID string) bool {
	query := `SELECT i.device_id, e.name, e.signing_public, e.wrapping_public,
		e.fingerprint, e.created_at, i.protocol_version, i.state, i.expires_at,
		i.failed_attempts, i.terminal_at, i.terminal_actor
		FROM invitations i JOIN enrollments e
			ON e.vault_id = i.vault_id AND e.device_id = i.device_id
		WHERE i.vault_id = ? AND i.state = ?`
	args := []any{vaultID, protocol.InvitationPending}
	if deviceID != "" {
		query += " AND i.device_id = ?"
		args = append(args, deviceID)
	}
	rows, err := tx.Query(query, args...)
	if err != nil {
		writePersistError(w)
		return false
	}
	var pending []invitationRow
	for rows.Next() {
		row, err := scanInvitation(rows)
		if err != nil {
			_ = rows.Close()
			writePersistError(w)
			return false
		}
		pending = append(pending, row)
	}
	if err := rows.Close(); err != nil {
		writePersistError(w)
		return false
	}
	for i := range pending {
		if !s.expireInvitation(w, tx, vaultID, &pending[i]) {
			return false
		}
	}
	return true
}

func getInvitationTx(tx *sql.Tx, vaultID, deviceID string) (invitationRow, error) {
	row := tx.QueryRow(`SELECT i.device_id, e.name, e.signing_public,
		e.wrapping_public, e.fingerprint, e.created_at, i.protocol_version,
		i.state, i.expires_at, i.failed_attempts, i.terminal_at, i.terminal_actor
		FROM invitations i JOIN enrollments e
			ON e.vault_id = i.vault_id AND e.device_id = i.device_id
		WHERE i.vault_id = ? AND i.device_id = ?`, vaultID, deviceID)
	return scanInvitation(row)
}

type invitationScanner interface {
	Scan(...any) error
}

func scanInvitation(scanner invitationScanner) (invitationRow, error) {
	var row invitationRow
	var terminalAt, terminalActor sql.NullString
	err := scanner.Scan(&row.status.Device.ID, &row.status.Device.Name,
		&row.status.Device.SigningPublic, &row.status.Device.WrappingPublic,
		&row.status.Device.Fingerprint, &row.status.Device.CreatedAt,
		&row.status.Version, &row.status.State, &row.status.ExpiresAt,
		&row.failedAttempts, &terminalAt, &terminalActor)
	row.status.AttemptsRemaining = invitationMaxAttempts - row.failedAttempts
	row.status.TerminalAt, row.terminalActor = terminalAt.String, terminalActor.String
	return row, err
}

func actorIsActive(tx *sql.Tx, vaultID, deviceID string) bool {
	_, err := getDeviceStatusTx(tx, vaultID, deviceID, true)
	return err == nil
}

func validEnvelope(envelope secure.WrappedKey) bool {
	ephemeral, ephemeralErr := secure.Decode(envelope.EphemeralKey)
	nonce, nonceErr := secure.Decode(envelope.Blob.Nonce)
	ciphertext, ciphertextErr := secure.Decode(envelope.Blob.Ciphertext)
	if envelope.Version != 1 || envelope.Blob.Version != 1 ||
		ephemeralErr != nil || nonceErr != nil || ciphertextErr != nil ||
		len(ephemeral) != 32 || len(nonce) != 12 || len(ciphertext) < 16 {
		return false
	}
	_, err := ecdh.X25519().NewPublicKey(ephemeral)
	return err == nil
}

func validPublicDeviceKeys(signingPublic, wrappingPublic string) bool {
	return secure.ValidatePublicDeviceKeys(signingPublic, wrappingPublic) == nil
}

func decodeStrictJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

func terminalReason(state string) string {
	switch state {
	case protocol.InvitationExpired:
		return "expired"
	case protocol.InvitationAttemptsExhausted:
		return "attempt_exhaustion"
	default:
		return "terminal_conflict"
	}
}

func readLimitedBody(r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return body, errors.New("request body is too large")
	}
	return body, nil
}

func (s *Server) bestEffortInvitationCreationRejection(
	w http.ResponseWriter, tx *sql.Tx, vaultID, message string,
) {
	reason := "invalid_request"
	if message == "unsupported invitation version" {
		reason = "unsupported_version"
	}
	if err := s.insertAccessEvent(tx, vaultID, eventDetails{
		operation: "invitation_creation", outcome: "rejected", reason: reason,
	}); err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusBadRequest, message)
		return
	}
	_ = tx.Commit()
	writeError(w, http.StatusBadRequest, message)
}
