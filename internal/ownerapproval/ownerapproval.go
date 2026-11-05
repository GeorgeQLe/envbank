// Package ownerapproval adds a hardware owner signature to signed automation
// policies. It is deliberately separate from vault transport authentication:
// the enrolled device Ed25519 key authenticates vault access and signs the
// stored policy object, while the owner P-256 key lives in the macOS Secure
// Enclave, requires fresh user presence for every signature and is pinned by
// the owner inside the passphrase-encrypted local config.
//
// A process holding the device key (for example a configured MCP backend) can
// re-sign a policy with Ed25519 but cannot produce a valid owner signature
// over a changed statement. Verify never falls back to a device-only, TTY or
// software approval.
//
// Limits: a verifier cannot remotely attest that the pinned key is hardware
// resident. The pin is protected by the local passphrase, not by hardware; an
// attacker with the passphrase and arbitrary same-user code can substitute it.
package ownerapproval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// PublicKeySize is the uncompressed SEC1/X9.63 P-256 public key length, the
// format SecKeyCopyExternalRepresentation returns for EC public keys.
const PublicKeySize = 65

// MaxApprovalLifetime bounds expiry relative to the owner signing time, so a
// signature cannot authorize a longer window than the owner reviewed.
const MaxApprovalLifetime = 24 * time.Hour

// clockSkew tolerates small clock differences between signer and verifier.
const clockSkew = 2 * time.Minute

var (
	ErrUnavailable  = errors.New("hardware owner approval is unavailable on this host")
	ErrNotEnrolled  = errors.New("hardware owner approval key is not enrolled")
	ErrKeyMismatch  = errors.New("hardware owner approval key does not match the owner pin")
	ErrCancelled    = errors.New("hardware owner approval was cancelled or not authenticated")
	ErrEntitlement  = errors.New("hardware owner approval requires a signed EnvBank build with a data-protection Keychain entitlement")
	ErrInvalidProof = errors.New("hardware owner approval is invalid")
)

// Signer produces an ASN.1 DER ECDSA P-256 signature over SHA-256(message).
// Production uses only the Secure Enclave implementation. Reason is shown in
// the system authentication dialog and must not contain secrets.
type Signer interface {
	PublicKey() []byte
	Sign(ctx context.Context, message []byte, reason string) ([]byte, error)
}

// ParsePublicKey validates an owner pin as an on-curve uncompressed P-256 point.
func ParsePublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != PublicKeySize || raw[0] != 4 {
		return nil, ErrInvalidProof
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return public, nil
}

// ValidPublicKey reports whether raw is a usable owner pin.
func ValidPublicKey(raw []byte) bool {
	_, err := ParsePublicKey(raw)
	return err == nil
}

// KeyID is the lowercase hex, domain-separated SHA-256 of the uncompressed
// public key. It identifies a public key only; it is never secret material.
func KeyID(raw []byte) string {
	sum := sha256.Sum256(append([]byte("envbank.owner-approval.key.v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

type ecdsaSignature struct{ R, S *big.Int }

// CanonicalSignature parses strict DER and returns the low-S encoding. ECDSA
// signatures are malleable (s and n-s both verify); evidence stores one form.
func CanonicalSignature(der []byte) ([]byte, error) {
	var signature ecdsaSignature
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return nil, ErrInvalidProof
	}
	n := elliptic.P256().Params().N
	if signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || signature.R.Cmp(n) >= 0 || signature.S.Cmp(n) >= 0 {
		return nil, ErrInvalidProof
	}
	reencoded, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(reencoded, der) {
		return nil, ErrInvalidProof
	}
	half := new(big.Int).Rsh(n, 1)
	if signature.S.Cmp(half) > 0 {
		signature.S = new(big.Int).Sub(n, signature.S)
	}
	return asn1.Marshal(signature)
}

func canonical(der []byte) bool {
	normalized, err := CanonicalSignature(der)
	return err == nil && bytes.Equal(normalized, der)
}

// Verify requires a hardware owner approval over the complete policy from the
// exact owner-pinned key. The pin comes only from owner-controlled local
// config, never from a request, manifest or the policy itself.
func Verify(policy lifecycle.AutomationPolicy, pinned []byte, now time.Time) error {
	public, err := ParsePublicKey(pinned)
	if err != nil {
		return errors.New("hardware owner approval key is not pinned")
	}
	owner := policy.OwnerApproval
	if owner == nil {
		return errors.New("hardware owner approval is required")
	}
	if owner.Version != lifecycle.OwnerApprovalVersion || owner.Algorithm != lifecycle.OwnerApprovalAlgorithm || owner.Presence != lifecycle.OwnerApprovalPresence {
		return ErrInvalidProof
	}
	if !bytes.Equal(owner.PublicKey, pinned) || owner.KeyID != KeyID(pinned) {
		return ErrKeyMismatch
	}
	signedAt, err := time.Parse(time.RFC3339, owner.SignedAt)
	if err != nil || signedAt.UTC().Format(time.RFC3339) != owner.SignedAt || signedAt.After(now.Add(clockSkew)) {
		return ErrInvalidProof
	}
	expires, err := time.Parse(time.RFC3339, policy.ExpiresAt)
	if err != nil || !expires.After(signedAt) || expires.After(signedAt.Add(MaxApprovalLifetime)) || !now.Before(expires) {
		return ErrInvalidProof
	}
	if !canonical(owner.Signature) {
		return ErrInvalidProof
	}
	statement, err := policy.OwnerStatement(*owner)
	if err != nil {
		return ErrInvalidProof
	}
	digest := sha256.Sum256(statement)
	if !ecdsa.VerifyASN1(public, digest[:], owner.Signature) {
		return ErrInvalidProof
	}
	return nil
}

// Approve attaches a fresh owner signature and then device-signs the policy.
// The signer's key must equal the pin before any user-presence prompt. The
// caller supplies every other policy field, including ExpiresAt.
func Approve(ctx context.Context, policy *lifecycle.AutomationPolicy, device ed25519.PrivateKey, signer Signer, pinned []byte, now time.Time, reason string) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if policy == nil || len(device) != ed25519.PrivateKeySize || signer == nil {
		return ErrInvalidProof
	}
	if !ValidPublicKey(pinned) {
		return ErrNotEnrolled
	}
	if !bytes.Equal(signer.PublicKey(), pinned) {
		return ErrKeyMismatch
	}
	policy.OwnerApproval = nil
	policy.Signature = nil
	policy.PublicKey = append([]byte(nil), device.Public().(ed25519.PublicKey)...)
	owner := lifecycle.OwnerApproval{Version: lifecycle.OwnerApprovalVersion, Algorithm: lifecycle.OwnerApprovalAlgorithm, Presence: lifecycle.OwnerApprovalPresence, KeyID: KeyID(pinned), PublicKey: append([]byte(nil), pinned...), SignedAt: now.UTC().Format(time.RFC3339)}
	statement, err := policy.OwnerStatement(owner)
	if err != nil {
		return ErrInvalidProof
	}
	raw, err := signer.Sign(ctx, statement, reason)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if err != nil {
		return err
	}
	signature, err := CanonicalSignature(raw)
	if err != nil {
		return ErrInvalidProof
	}
	owner.Signature = signature
	policy.OwnerApproval = &owner
	if err = policy.Sign(device); err != nil {
		policy.OwnerApproval = nil
		return ErrInvalidProof
	}
	if err = Verify(*policy, pinned, now); err != nil {
		policy.OwnerApproval = nil
		policy.Signature = nil
		return ErrInvalidProof
	}
	return nil
}

// SameAuthority reports whether renewal b differs from a only in expiry and
// the fresh signatures/time that a renewal necessarily changes. The owner key
// identity and attributes must stay identical, so renewal cannot swap keys or
// drop the hardware proof.
func SameAuthority(a, b lifecycle.AutomationPolicy) bool {
	if (a.OwnerApproval == nil) != (b.OwnerApproval == nil) {
		return false
	}
	normalize := func(p lifecycle.AutomationPolicy) lifecycle.AutomationPolicy {
		p.ExpiresAt, p.Signature = "", nil
		if p.OwnerApproval != nil {
			owner := *p.OwnerApproval
			owner.Signature, owner.SignedAt = nil, ""
			p.OwnerApproval = &owner
		}
		return p
	}
	x, ex := json.Marshal(normalize(a))
	y, ey := json.Marshal(normalize(b))
	return ex == nil && ey == nil && bytes.Equal(x, y)
}
