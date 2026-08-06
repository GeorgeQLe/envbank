package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/secure"
)

const (
	HeaderDevice    = "X-EnvBank-Device"
	HeaderTimestamp = "X-EnvBank-Timestamp"
	HeaderNonce     = "X-EnvBank-Nonce"
	HeaderSignature = "X-EnvBank-Signature"
)

type PublicDevice struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SigningPublic  string `json:"signing_public"`
	WrappingPublic string `json:"wrapping_public"`
	Fingerprint    string `json:"fingerprint"`
	CreatedAt      string `json:"created_at"`
}

type DeviceStatus struct {
	Device    PublicDevice `json:"device"`
	RevokedAt string       `json:"revoked_at,omitempty"`
}

type CreateVaultRequest struct {
	Name   string       `json:"name"`
	Device PublicDevice `json:"device"`
}

type CreateVaultResponse struct {
	VaultID  string `json:"vault_id"`
	DeviceID string `json:"device_id"`
}

type EnrollmentRequest struct {
	Name           string `json:"name"`
	SigningPublic  string `json:"signing_public"`
	WrappingPublic string `json:"wrapping_public"`
}

type EnrollmentApproval struct {
	Envelope secure.WrappedKey `json:"envelope"`
}

type EnrollmentStatus struct {
	Device    PublicDevice       `json:"device"`
	Approved  bool               `json:"approved"`
	Envelope  *secure.WrappedKey `json:"envelope,omitempty"`
	RevokedAt string             `json:"revoked_at,omitempty"`
}

const (
	InvitationProtocolVersion = 1

	InvitationPending           = "pending"
	InvitationApproved          = "approved"
	InvitationCancelled         = "cancelled"
	InvitationRejected          = "rejected"
	InvitationExpired           = "expired"
	InvitationAttemptsExhausted = "attempts_exhausted"
)

type InvitationRequest struct {
	Version        int    `json:"version"`
	Name           string `json:"name"`
	SigningPublic  string `json:"signing_public"`
	WrappingPublic string `json:"wrapping_public"`
}

type InvitationApproval struct {
	Version     int               `json:"version"`
	DeviceID    string            `json:"device_id"`
	Fingerprint string            `json:"fingerprint"`
	Envelope    secure.WrappedKey `json:"envelope"`
}

type InvitationTransition struct {
	Version     int    `json:"version"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
}

type InvitationStatus struct {
	Version           int                `json:"version"`
	Device            PublicDevice       `json:"device"`
	State             string             `json:"state"`
	ExpiresAt         string             `json:"expires_at"`
	AttemptsRemaining int                `json:"attempts_remaining"`
	TerminalAt        string             `json:"terminal_at,omitempty"`
	Envelope          *secure.WrappedKey `json:"envelope,omitempty"`
}

type Record struct {
	ID         string      `json:"id"`
	Revision   int64       `json:"revision"`
	Blob       secure.Blob `json:"blob"`
	ModifiedAt string      `json:"modified_at"`
}

type PutRecordRequest struct {
	ExpectedRevision int64       `json:"expected_revision"`
	Blob             secure.Blob `json:"blob"`
}

type AccessEvent struct {
	ID               string `json:"id"`
	VaultID          string `json:"vault_id"`
	Timestamp        string `json:"timestamp"`
	IdentityID       string `json:"identity_id,omitempty"`
	IdentityVerified bool   `json:"identity_verified"`
	TargetIdentityID string `json:"target_identity_id,omitempty"`
	Operation        string `json:"operation"`
	Outcome          string `json:"outcome"`
	Reason           string `json:"reason,omitempty"`
}

type AccessEventPage struct {
	Events     []AccessEvent `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type SecretRecord struct {
	Name            string   `json:"name"`
	Value           string   `json:"value"`
	CreatedAt       string   `json:"created_at"`
	RotatedAt       string   `json:"rotated_at"`
	RotateEveryDays int      `json:"rotate_every_days,omitempty"`
	Revision        int64    `json:"revision"`
	AllowedOrigins  []string `json:"allowed_origins,omitempty"`
}

func SignatureMessage(method, path, timestamp, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		"envbank.request.v1",
		method,
		path,
		timestamp,
		nonce,
		base64.RawURLEncoding.EncodeToString(sum[:]),
	}, "\n"))
}

func ValidateTimestamp(value string, now time.Time) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return fmt.Errorf("invalid request timestamp")
	}
	delta := now.Sub(parsed)
	if delta < 0 {
		delta = -delta
	}
	if delta > 5*time.Minute {
		return fmt.Errorf("request timestamp outside allowed window")
	}
	return nil
}

func ValidateNonce(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 18 ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("invalid request nonce")
	}
	return nil
}
