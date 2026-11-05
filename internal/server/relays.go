package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

// Cross-device relay storage. The service keeps only an opaque descriptor
// (encrypted under a vault-key-derived subkey) and at most one opaque
// envelope (sealed to the target device), plus routing metadata. Ciphertext
// is cleared when the envelope is consumed, the request is cancelled, or it
// expires; the remaining tombstone blocks id reuse and bounds creation rate.
const relaysSchema = `
CREATE TABLE IF NOT EXISTS relays (
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	target_device_id TEXT NOT NULL,
	sender_device_id TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('pending', 'sealed', 'consumed', 'cancelled', 'expired')),
	descriptor BLOB NOT NULL,
	envelope BLOB,
	PRIMARY KEY (vault_id, id)
);
CREATE INDEX IF NOT EXISTS relays_vault_expiry ON relays(vault_id, expires_at);
`

// Version 7 widens the access-event CHECK constraints for relay operations
// and adds the relay table.
const relayMigrationSchema = `
ALTER TABLE access_events RENAME TO access_events_v6;
DROP INDEX access_events_vault_sequence;
DROP INDEX access_events_pruning;
` + accessEventsSchema + `
INSERT INTO access_events(
	sequence, id, vault_id, timestamp, identity_id, identity_verified,
	target_identity_id, operation, outcome, reason
)
SELECT sequence, id, vault_id, timestamp, identity_id, identity_verified,
	target_identity_id, operation, outcome, reason
FROM access_events_v6 ORDER BY sequence;
DROP TABLE access_events_v6;
` + relaysSchema + `
PRAGMA user_version = 7;
`

// RelayLimits bound relay storage per vault and device.
var RelayLimits = struct {
	CreateBodyBytes   int64
	SealBodyBytes     int64
	DescriptorBytes   int
	ActivePerVault    int
	ActivePerTarget   int
	CreatedPerHour    int
	ClockSkew         time.Duration
	TombstoneRetained time.Duration
}{
	CreateBodyBytes:   16 << 10,
	SealBodyBytes:     160 << 10,
	DescriptorBytes:   8 << 10,
	ActivePerVault:    8,
	ActivePerTarget:   2,
	CreatedPerHour:    20,
	ClockSkew:         30 * time.Second,
	TombstoneRetained: time.Hour,
}

type relayRow struct {
	request  protocol.RelayRequest
	envelope []byte
}

func (s *Server) routeRelay(w http.ResponseWriter, r *http.Request, vaultID string, parts []string) bool {
	switch {
	case len(parts) == 4 && r.Method == http.MethodPost:
		s.createRelay(w, r, vaultID)
	case len(parts) == 4 && r.Method == http.MethodGet:
		s.listRelays(w, r, vaultID)
	case len(parts) == 6 && parts[5] == "seal" && r.Method == http.MethodPost:
		s.sealRelay(w, r, vaultID, parts[4])
	case len(parts) == 6 && parts[5] == "consume" && r.Method == http.MethodPost:
		s.consumeRelay(w, r, vaultID, parts[4])
	case len(parts) == 5 && r.Method == http.MethodDelete:
		s.cancelRelay(w, r, vaultID, parts[4])
	default:
		return false
	}
	return true
}

func (s *Server) createRelay(w http.ResponseWriter, r *http.Request, vaultID string) {
	body, ok := readBody(w, r, RelayLimits.CreateBodyBytes)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "relay_creation", false)
	if !authenticated {
		return
	}
	now := s.now().UTC()
	if !s.expireRelays(w, tx, vaultID, now) {
		return
	}
	var request protocol.RelayCreateRequest
	if strictJSON(body, &request) != nil {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest, "invalid relay request", "invalid_request")
		return
	}
	if request.Version != protocol.RelayProtocolVersion {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest, "unsupported relay version", "unsupported_version")
		return
	}
	expires, err := time.Parse(time.RFC3339, request.ExpiresAt)
	if protocol.ValidateNonce(request.ID) != nil || err != nil ||
		expires.UTC().Format(time.RFC3339) != request.ExpiresAt ||
		!expires.After(now) || expires.Sub(now) > protocol.RelayMaxTTL+RelayLimits.ClockSkew ||
		!validOpaqueBlob(request.Descriptor, RelayLimits.DescriptorBytes) ||
		request.SenderDeviceID == "" || request.SenderDeviceID == auth.identityID {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest, "invalid relay request", "invalid_request")
		return
	}
	if _, err := getDeviceStatusTx(tx, vaultID, request.SenderDeviceID, true); errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusNotFound, "sender device not found", "not_found")
		return
	} else if err != nil {
		writePersistError(w)
		return
	}
	nowText := now.Format(time.RFC3339)
	var activeVault, activeTarget, recent int
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(target_device_id = ?), 0)
		FROM relays WHERE vault_id = ? AND state IN ('pending', 'sealed') AND expires_at > ?`,
		auth.identityID, vaultID, nowText).Scan(&activeVault, &activeTarget); err != nil {
		writePersistError(w)
		return
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM relays
		WHERE vault_id = ? AND target_device_id = ? AND created_at > ?`, vaultID, auth.identityID,
		now.Add(-time.Hour).Format(time.RFC3339)).Scan(&recent); err != nil {
		writePersistError(w)
		return
	}
	if activeVault >= RelayLimits.ActivePerVault || activeTarget >= RelayLimits.ActivePerTarget ||
		recent >= RelayLimits.CreatedPerHour {
		s.rejectEvent(w, tx, vaultID, auth, request.SenderDeviceID, http.StatusTooManyRequests,
			"too many relay requests", "rate_limited")
		return
	}
	descriptor, err := json.Marshal(request.Descriptor)
	if err != nil {
		writePersistError(w)
		return
	}
	result, err := tx.Exec(`INSERT INTO relays(
		vault_id, id, target_device_id, sender_device_id, created_at, expires_at, state, descriptor
	) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?) ON CONFLICT DO NOTHING`, vaultID, request.ID,
		auth.identityID, request.SenderDeviceID, nowText, request.ExpiresAt, descriptor)
	if err != nil {
		writePersistError(w)
		return
	}
	if inserted, err := result.RowsAffected(); err != nil {
		writePersistError(w)
		return
	} else if inserted != 1 {
		s.rejectEvent(w, tx, vaultID, auth, request.SenderDeviceID, http.StatusConflict,
			"relay request already exists", "terminal_conflict")
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true, targetIdentityID: request.SenderDeviceID,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, protocol.RelayRequest{
		Version: protocol.RelayProtocolVersion, ID: request.ID, TargetDeviceID: auth.identityID,
		SenderDeviceID: request.SenderDeviceID, CreatedAt: nowText, ExpiresAt: request.ExpiresAt,
		State: protocol.RelayPending, Descriptor: request.Descriptor,
	})
}

// listRelays returns pending, unexpired requests the caller sends or receives.
func (s *Server) listRelays(w http.ResponseWriter, r *http.Request, vaultID string) {
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, nil, "relay_list", false)
	if !authenticated {
		return
	}
	now := s.now().UTC()
	if !s.expireRelays(w, tx, vaultID, now) {
		return
	}
	rows, err := tx.Query(`SELECT id, target_device_id, sender_device_id, created_at, expires_at,
		state, descriptor, envelope FROM relays
		WHERE vault_id = ? AND state = 'pending' AND expires_at > ?
		AND (sender_device_id = ? OR target_device_id = ?)
		ORDER BY created_at, id`, vaultID, now.Format(time.RFC3339), auth.identityID, auth.identityID)
	if err != nil {
		writePersistError(w)
		return
	}
	defer rows.Close()
	out := []protocol.RelayRequest{}
	for rows.Next() {
		row, err := scanRelay(rows)
		if err != nil {
			writePersistError(w)
			return
		}
		out = append(out, row.request)
	}
	if rows.Err() != nil || rows.Close() != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true, operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) sealRelay(w http.ResponseWriter, r *http.Request, vaultID, relayID string) {
	body, ok := readBody(w, r, RelayLimits.SealBodyBytes)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "relay_seal", false)
	if !authenticated {
		return
	}
	now := s.now().UTC()
	if !s.expireRelays(w, tx, vaultID, now) {
		return
	}
	row, found := s.relayForActor(w, tx, vaultID, relayID, auth, false)
	if !found {
		return
	}
	switch row.request.State {
	case protocol.RelayPending:
	case protocol.RelayExpired:
		s.rejectEvent(w, tx, vaultID, auth, row.request.TargetDeviceID, http.StatusGone, "relay request expired", "expired")
		return
	default:
		s.rejectEvent(w, tx, vaultID, auth, row.request.TargetDeviceID, http.StatusConflict,
			"relay request is no longer pending", "terminal_conflict")
		return
	}
	var request protocol.RelaySealRequest
	if strictJSON(body, &request) != nil || request.Version != protocol.RelayProtocolVersion ||
		!validRelayEnvelope(request.Envelope, relayID, auth.identityID) {
		s.rejectEvent(w, tx, vaultID, auth, row.request.TargetDeviceID, http.StatusBadRequest,
			"invalid relay envelope", "invalid_request")
		return
	}
	envelope, err := json.Marshal(request.Envelope)
	if err != nil {
		writePersistError(w)
		return
	}
	result, err := tx.Exec(`UPDATE relays SET state = 'sealed', envelope = ?
		WHERE vault_id = ? AND id = ? AND state = 'pending'`, envelope, vaultID, relayID)
	if err != nil {
		writePersistError(w)
		return
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true, targetIdentityID: row.request.TargetDeviceID,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// consumeRelay hands the envelope to the target exactly once.
func (s *Server) consumeRelay(w http.ResponseWriter, r *http.Request, vaultID, relayID string) {
	body, ok := readBody(w, r, 1024)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "relay_consume", false)
	if !authenticated {
		return
	}
	if len(bytes.TrimSpace(body)) != 0 {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusBadRequest, "invalid relay request", "invalid_request")
		return
	}
	now := s.now().UTC()
	if !s.expireRelays(w, tx, vaultID, now) {
		return
	}
	row, found := s.relayForActor(w, tx, vaultID, relayID, auth, true)
	if !found {
		return
	}
	response := protocol.RelayConsumeResponse{Version: protocol.RelayProtocolVersion, State: row.request.State}
	switch row.request.State {
	case protocol.RelayPending:
	case protocol.RelaySealed:
		var envelope protocol.RelayEnvelope
		if json.Unmarshal(row.envelope, &envelope) != nil {
			writePersistError(w)
			return
		}
		result, err := tx.Exec(`UPDATE relays SET state = 'consumed', envelope = NULL, descriptor = X''
			WHERE vault_id = ? AND id = ? AND state = 'sealed'`, vaultID, relayID)
		if err != nil {
			writePersistError(w)
			return
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			writePersistError(w)
			return
		}
		response.State = protocol.RelayConsumed
		response.Envelope = &envelope
	case protocol.RelayExpired:
		s.rejectEvent(w, tx, vaultID, auth, row.request.SenderDeviceID, http.StatusGone, "relay request expired", "expired")
		return
	default:
		s.rejectEvent(w, tx, vaultID, auth, row.request.SenderDeviceID, http.StatusGone,
			"relay request is no longer available", "terminal_conflict")
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true, targetIdentityID: row.request.SenderDeviceID,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) cancelRelay(w http.ResponseWriter, r *http.Request, vaultID, relayID string) {
	body, ok := readBody(w, r, 1024)
	if !ok {
		return
	}
	tx, ok := s.begin(w)
	if !ok {
		return
	}
	defer tx.Rollback()
	auth, authenticated := s.authenticateDevice(w, r, tx, vaultID, body, "relay_cancellation", false)
	if !authenticated {
		return
	}
	now := s.now().UTC()
	if !s.expireRelays(w, tx, vaultID, now) {
		return
	}
	row, found := s.relayForActor(w, tx, vaultID, relayID, auth, true)
	if !found {
		return
	}
	if row.request.State != protocol.RelayPending && row.request.State != protocol.RelaySealed {
		s.rejectEvent(w, tx, vaultID, auth, row.request.SenderDeviceID, http.StatusConflict,
			"relay request is no longer pending", "terminal_conflict")
		return
	}
	if _, err := tx.Exec(`UPDATE relays SET state = 'cancelled', envelope = NULL, descriptor = X''
		WHERE vault_id = ? AND id = ?`, vaultID, relayID); err != nil {
		writePersistError(w)
		return
	}
	if !s.finishEvent(w, tx, vaultID, eventDetails{
		identityID: auth.identityID, identityVerified: true, targetIdentityID: row.request.SenderDeviceID,
		operation: auth.operation, outcome: "succeeded",
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// relayForActor loads a relay that the caller may act on as target (or as
// sender when asTarget is false). Others see not_found / incorrect_actor.
func (s *Server) relayForActor(w http.ResponseWriter, tx *sql.Tx, vaultID, relayID string,
	auth *authenticatedRequest, asTarget bool,
) (relayRow, bool) {
	row, err := scanRelay(tx.QueryRow(`SELECT id, target_device_id, sender_device_id, created_at,
		expires_at, state, descriptor, envelope FROM relays WHERE vault_id = ? AND id = ?`, vaultID, relayID))
	if errors.Is(err, sql.ErrNoRows) {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusNotFound, "relay request not found", "not_found")
		return relayRow{}, false
	}
	if err != nil {
		writePersistError(w)
		return relayRow{}, false
	}
	actor := row.request.SenderDeviceID
	if asTarget {
		actor = row.request.TargetDeviceID
	}
	if actor != auth.identityID {
		s.rejectEvent(w, tx, vaultID, auth, "", http.StatusForbidden, "relay request belongs to another device", "incorrect_actor")
		return relayRow{}, false
	}
	return row, true
}

// expireRelays clears ciphertext of expired requests and drops old tombstones.
func (s *Server) expireRelays(w http.ResponseWriter, tx *sql.Tx, vaultID string, now time.Time) bool {
	if _, err := tx.Exec(`UPDATE relays SET state = 'expired', envelope = NULL, descriptor = X''
		WHERE vault_id = ? AND state IN ('pending', 'sealed') AND expires_at <= ?`,
		vaultID, now.Format(time.RFC3339)); err != nil {
		writePersistError(w)
		return false
	}
	if _, err := tx.Exec(`DELETE FROM relays WHERE vault_id = ? AND expires_at < ?`,
		vaultID, now.Add(-RelayLimits.TombstoneRetained).Format(time.RFC3339)); err != nil {
		writePersistError(w)
		return false
	}
	return true
}

func scanRelay(row rowScanner) (relayRow, error) {
	var out relayRow
	var descriptor []byte
	var envelope []byte
	request := &out.request
	if err := row.Scan(&request.ID, &request.TargetDeviceID, &request.SenderDeviceID, &request.CreatedAt,
		&request.ExpiresAt, &request.State, &descriptor, &envelope); err != nil {
		return out, err
	}
	request.Version = protocol.RelayProtocolVersion
	if len(descriptor) > 0 {
		if err := json.Unmarshal(descriptor, &request.Descriptor); err != nil {
			return out, err
		}
	}
	out.envelope = envelope
	return out, nil
}

func validOpaqueBlob(blob secure.Blob, maxCiphertext int) bool {
	if !validEncryptedVaultObject(blob) {
		return false
	}
	ciphertext, _ := secure.Decode(blob.Ciphertext)
	return len(ciphertext) <= maxCiphertext
}

func validRelayEnvelope(env protocol.RelayEnvelope, relayID, senderID string) bool {
	if env.Version != protocol.RelayProtocolVersion || env.RequestID != relayID || env.SenderDeviceID != senderID ||
		env.Sealed.Version != 1 || !validOpaqueBlob(env.Sealed.Blob, int(RelayLimits.SealBodyBytes)) {
		return false
	}
	for _, field := range []struct {
		value string
		size  int
	}{{env.Sealed.EphemeralKey, 32}, {env.Signature, 64}, {env.VaultMAC, 32}} {
		raw, err := secure.Decode(field.value)
		if err != nil || len(raw) != field.size || secure.Encode(raw) != field.value {
			return false
		}
	}
	return true
}

func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
