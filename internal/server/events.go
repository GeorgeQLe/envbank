package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
)

const accessEventsSchema = `
CREATE TABLE access_events (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE,
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
	timestamp TEXT NOT NULL,
	identity_id TEXT,
	identity_verified INTEGER NOT NULL CHECK (identity_verified IN (0, 1)),
	target_identity_id TEXT,
	operation TEXT NOT NULL CHECK (operation IN (
		'enrollment_request', 'enrollment_list', 'enrollment_status',
		'enrollment_approval', 'device_list', 'device_revocation',
		'record_list', 'record_update', 'event_list',
		'invitation_creation', 'invitation_list', 'invitation_status',
		'invitation_approval', 'invitation_rejection', 'invitation_cancellation',
		'invitation_expiry'
	)),
	outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'rejected', 'denied')),
	reason TEXT CHECK (reason IS NULL OR reason IN (
		'invalid_signature', 'stale_timestamp', 'replay', 'revoked_device',
		'pending_device', 'invalid_request', 'unknown_device', 'not_found',
		'revision_conflict', 'already_revoked', 'already_approved',
		'final_active_device', 'binding_mismatch', 'terminal_conflict',
		'attempt_exhaustion', 'incorrect_actor', 'unsupported_version',
		'expired'
	))
);
CREATE INDEX access_events_vault_sequence ON access_events(vault_id, sequence DESC);
CREATE INDEX access_events_pruning
	ON access_events(vault_id, identity_verified, timestamp, sequence);
`

const (
	eventMaxAge             = 90 * 24 * time.Hour
	maxVerifiedEvents       = 10_000
	maxUnverifiedEvents     = 2_000
	defaultAccessEventLimit = 100
	maxAccessEventLimit     = 500
)

type eventDetails struct {
	identityID       string
	identityVerified bool
	targetIdentityID string
	operation        string
	outcome          string
	reason           string
}

func (s *Server) insertAccessEvent(tx *sql.Tx, vaultID string, event eventDetails) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	now := s.now().UTC()
	var identityID, targetIdentityID, reason any
	if event.identityID != "" {
		identityID = event.identityID
	}
	if event.targetIdentityID != "" {
		targetIdentityID = event.targetIdentityID
	}
	if event.reason != "" {
		reason = event.reason
	}
	if _, err := tx.Exec(`INSERT INTO access_events(
		id, vault_id, timestamp, identity_id, identity_verified,
		target_identity_id, operation, outcome, reason
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, vaultID, now.Format(time.RFC3339Nano),
		identityID, event.identityVerified, targetIdentityID, event.operation,
		event.outcome, reason); err != nil {
		return err
	}
	return pruneAccessEvents(tx, vaultID, now)
}

func pruneAccessEvents(tx *sql.Tx, vaultID string, now time.Time) error {
	cutoff := now.Add(-eventMaxAge).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM access_events
		WHERE vault_id = ? AND timestamp < ?`, vaultID, cutoff); err != nil {
		return err
	}
	for _, cap := range []struct {
		verified bool
		limit    int
	}{
		{true, maxVerifiedEvents},
		{false, maxUnverifiedEvents},
	} {
		if _, err := tx.Exec(`DELETE FROM access_events
			WHERE vault_id = ? AND identity_verified = ? AND sequence NOT IN (
				SELECT sequence FROM access_events
				WHERE vault_id = ? AND identity_verified = ?
				ORDER BY sequence DESC LIMIT ?
			)`, vaultID, cap.verified, vaultID, cap.verified, cap.limit); err != nil {
			return err
		}
	}
	return nil
}

func encodeEventCursor(sequence int64) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(sequence))
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func decodeEventCursor(value string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 8 {
		return 0, errors.New("invalid cursor")
	}
	sequence := binary.BigEndian.Uint64(raw)
	if sequence == 0 || sequence > uint64(^uint64(0)>>1) {
		return 0, errors.New("invalid cursor")
	}
	return int64(sequence), nil
}

func parseAccessEventPage(rLimit, rBefore string) (int, int64, error) {
	limit := defaultAccessEventLimit
	if rLimit != "" {
		parsed, err := strconv.Atoi(rLimit)
		if err != nil || parsed < 1 || parsed > maxAccessEventLimit {
			return 0, 0, errors.New("limit must be between 1 and 500")
		}
		limit = parsed
	}
	var before int64
	if rBefore != "" {
		var err error
		before, err = decodeEventCursor(rBefore)
		if err != nil {
			return 0, 0, err
		}
	}
	return limit, before, nil
}

func scanAccessEvent(rows *sql.Rows) (int64, protocol.AccessEvent, error) {
	var sequence int64
	var event protocol.AccessEvent
	var identityID, targetIdentityID, reason sql.NullString
	err := rows.Scan(&sequence, &event.ID, &event.VaultID, &event.Timestamp,
		&identityID, &event.IdentityVerified, &targetIdentityID, &event.Operation,
		&event.Outcome, &reason)
	event.IdentityID = identityID.String
	event.TargetIdentityID = targetIdentityID.String
	event.Reason = reason.String
	return sequence, event, err
}
