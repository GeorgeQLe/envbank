// Package relay delivers one owner-typed secret from one enrolled device (the
// sender) to another enrolled device's owner-held broker (the target) through
// the untrusted sync service.
//
// The target creates a request. Its descriptor (sink, reason, both devices'
// public keys, a fresh nonce and an expiry of at most five minutes) is signed
// with the target's Ed25519 key and encrypted under a subkey derived from the
// vault key, so the service can neither read nor forge it. The sender opens
// the descriptor, checks both devices against the vault's device list, and
// shows a short authentication string (SAS) that the owner compares with the
// target's screen. The value is then sealed to the target's X25519 wrapping
// key with the same construction as enrollment envelopes
// (secure.SealToDevice), bound to the request, signed with the sender's
// Ed25519 key and authenticated with a vault-key-derived HMAC. The target
// accepts one envelope per request, once, before expiry.
//
// No new primitives are introduced: X25519, HKDF-SHA-256, AES-256-GCM,
// Ed25519 and HMAC-SHA-256 come from internal/secure.
package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

const (
	// SinkIngest stores the value in the target's vault under Sink.Name.
	SinkIngest = "ingest"

	Version       = 1
	NonceBytes    = 32
	MinValueBytes = 8
	MaxValueBytes = 64 << 10
	MaxReasonLen  = 300
	maxIDLen      = 128
	maxNameLen    = 128
)

// Fixed errors. None carries caller input, key material or values.
var (
	ErrInvalid     = errors.New("RELAY_INVALID")
	ErrExpired     = errors.New("RELAY_EXPIRED")
	ErrNotEnrolled = errors.New("RELAY_DEVICE_NOT_ENROLLED")
	ErrAuth        = errors.New("RELAY_AUTHENTICATION_FAILED")
	ErrUsed        = errors.New("RELAY_ALREADY_USED")
	ErrValueSize   = errors.New("RELAY_VALUE_SIZE")
)

// Device is the public identity of an enrolled device.
type Device struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SigningPublic  string `json:"signing_public"`
	WrappingPublic string `json:"wrapping_public"`
}

// Fingerprint is the enrollment fingerprint of the device's public keys.
func (d Device) Fingerprint() string {
	return secure.PublicFingerprint(d.SigningPublic, d.WrappingPublic)
}

// Sink is where the target delivers the value. Only vault ingest exists.
type Sink struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Descriptor is the request content, readable only by vault-key holders.
type Descriptor struct {
	Version   int    `json:"version"`
	VaultID   string `json:"vault_id"`
	RequestID string `json:"request_id"`
	Nonce     string `json:"nonce"`
	Target    Device `json:"target"`
	Sender    Device `json:"sender"`
	Sink      Sink   `json:"sink"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type signedDescriptor struct {
	Descriptor json.RawMessage `json:"descriptor"`
	Signature  string          `json:"signature"`
}

// Request is a verified descriptor. It accepts at most one envelope.
type Request struct {
	Descriptor
	digest  [32]byte
	expires time.Time

	mu   sync.Mutex
	used bool
}

// Expires is the request's expiry.
func (r *Request) Expires() time.Time { return r.expires }

// SAS is the six-digit short authentication string both devices display. It
// is derived from the request id, the fresh nonce and both devices' public
// keys, so a substituted device or request shows a different code.
func (r *Request) SAS() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"envbank.relay.sas.v1", r.VaultID, r.RequestID, r.Nonce,
		r.Target.SigningPublic, r.Target.WrappingPublic,
		r.Sender.SigningPublic, r.Sender.WrappingPublic,
	}, "\x00")))
	n := binary.BigEndian.Uint64(sum[:8]) % 1_000_000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}

// NewRequest builds and signs a request from target to sender for sink. It
// assigns a random request id and nonce and an expiry of ttl (at most
// protocol.RelayMaxTTL).
func NewRequest(vaultID string, vaultKey []byte, target Device, targetSigningPrivate string,
	sender Device, sink Sink, reason string, now time.Time, ttl time.Duration,
) (protocol.RelayCreateRequest, *Request, error) {
	if ttl <= 0 || ttl > protocol.RelayMaxTTL {
		return protocol.RelayCreateRequest{}, nil, ErrInvalid
	}
	id, err := secure.RandomBytes(18)
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	nonce, err := secure.RandomBytes(NonceBytes)
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	now = now.UTC().Truncate(time.Second)
	d := Descriptor{
		Version: Version, VaultID: vaultID, RequestID: secure.Encode(id), Nonce: secure.Encode(nonce),
		Target: target, Sender: sender, Sink: sink, Reason: reason,
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(ttl).Format(time.RFC3339),
	}
	if err := d.validate(); err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	signature, err := secure.Sign(targetSigningPrivate, descriptorSignatureMessage(raw))
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, ErrInvalid
	}
	// The signer must be the target identity named in the descriptor.
	if !secure.Verify(target.SigningPublic, descriptorSignatureMessage(raw), signature) {
		return protocol.RelayCreateRequest{}, nil, ErrInvalid
	}
	plain, err := json.Marshal(signedDescriptor{Descriptor: raw, Signature: signature})
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	key, err := descriptorKey(vaultKey, vaultID)
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	defer secure.Wipe(key)
	blob, err := secure.Seal(key, plain, descriptorAAD(d.VaultID, d.RequestID, target.ID, sender.ID, d.ExpiresAt))
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	request, err := newVerified(d, raw)
	if err != nil {
		return protocol.RelayCreateRequest{}, nil, err
	}
	return protocol.RelayCreateRequest{
		Version: protocol.RelayProtocolVersion, ID: d.RequestID, SenderDeviceID: sender.ID,
		ExpiresAt: d.ExpiresAt, Descriptor: blob,
	}, request, nil
}

// OpenRequest decrypts and verifies a server-delivered request on the sender.
// The descriptor must authenticate under the vault key, be signed by the
// target it names, agree with the server's metadata, name self as sender, and
// be unexpired. The caller must still check the target with VerifyEnrolled.
func OpenRequest(vaultID string, vaultKey []byte, server protocol.RelayRequest, self Device, now time.Time) (*Request, error) {
	if server.Version != protocol.RelayProtocolVersion || server.State != protocol.RelayPending {
		return nil, ErrInvalid
	}
	key, err := descriptorKey(vaultKey, vaultID)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(key)
	plain, err := secure.Open(key, server.Descriptor,
		descriptorAAD(vaultID, server.ID, server.TargetDeviceID, server.SenderDeviceID, server.ExpiresAt))
	if err != nil {
		return nil, ErrAuth
	}
	var signed signedDescriptor
	if err := json.Unmarshal(plain, &signed); err != nil {
		return nil, ErrInvalid
	}
	var d Descriptor
	if err := strictUnmarshal(signed.Descriptor, &d); err != nil {
		return nil, ErrInvalid
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	if !secure.Verify(d.Target.SigningPublic, descriptorSignatureMessage(signed.Descriptor), signed.Signature) {
		return nil, ErrAuth
	}
	if d.VaultID != vaultID || d.RequestID != server.ID || d.Target.ID != server.TargetDeviceID ||
		d.Sender.ID != server.SenderDeviceID || d.ExpiresAt != server.ExpiresAt {
		return nil, ErrAuth
	}
	if d.Sender.ID != self.ID || d.Sender.SigningPublic != self.SigningPublic ||
		d.Sender.WrappingPublic != self.WrappingPublic {
		return nil, ErrNotEnrolled
	}
	request, err := newVerified(d, signed.Descriptor)
	if err != nil {
		return nil, err
	}
	if !now.Before(request.expires) {
		return nil, ErrExpired
	}
	return request, nil
}

// VerifyEnrolled requires dev to be an active device of the vault with
// exactly these public keys and a matching fingerprint.
func VerifyEnrolled(dev Device, devices []protocol.DeviceStatus) error {
	for _, status := range devices {
		if status.Device.ID != dev.ID {
			continue
		}
		listed := status.Device
		if status.RevokedAt != "" || listed.SigningPublic != dev.SigningPublic ||
			listed.WrappingPublic != dev.WrappingPublic ||
			secure.ValidatePublicDeviceKeys(listed.SigningPublic, listed.WrappingPublic) != nil ||
			listed.Fingerprint != dev.Fingerprint() {
			return ErrNotEnrolled
		}
		return nil
	}
	return ErrNotEnrolled
}

// Seal encrypts value for the request's target on the sender.
func Seal(r *Request, vaultKey []byte, senderSigningPrivate string, value []byte, now time.Time) (protocol.RelayEnvelope, error) {
	if len(value) < MinValueBytes || len(value) > MaxValueBytes || !utf8.Valid(value) {
		return protocol.RelayEnvelope{}, ErrValueSize
	}
	if !now.Before(r.expires) {
		return protocol.RelayEnvelope{}, ErrExpired
	}
	context := r.sealContext()
	sealed, err := secure.SealToDevice(r.Target.WrappingPublic, context, value)
	if err != nil {
		return protocol.RelayEnvelope{}, ErrInvalid
	}
	env := protocol.RelayEnvelope{
		Version: Version, RequestID: r.RequestID, SenderDeviceID: r.Sender.ID, Sealed: sealed,
	}
	message := envelopeMessage(context, env)
	env.Signature, err = secure.Sign(senderSigningPrivate, message)
	if err != nil {
		return protocol.RelayEnvelope{}, ErrInvalid
	}
	if !secure.Verify(r.Sender.SigningPublic, message, env.Signature) {
		return protocol.RelayEnvelope{}, ErrInvalid // signer is not the descriptor's sender
	}
	macKey, err := macKey(vaultKey, r.VaultID)
	if err != nil {
		return protocol.RelayEnvelope{}, err
	}
	defer secure.Wipe(macKey)
	env.VaultMAC = secure.Encode(secure.MAC(macKey, message))
	return env, nil
}

// Open verifies and decrypts the envelope on the target, at most once per
// request. The caller should wipe the returned value after use.
func Open(r *Request, vaultKey []byte, targetWrappingPrivate string, env protocol.RelayEnvelope, now time.Time) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used {
		return nil, ErrUsed
	}
	if !now.Before(r.expires) {
		return nil, ErrExpired
	}
	if env.Version != Version || env.RequestID != r.RequestID || env.SenderDeviceID != r.Sender.ID {
		return nil, ErrAuth
	}
	context := r.sealContext()
	message := envelopeMessage(context, env)
	macKey, err := macKey(vaultKey, r.VaultID)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(macKey)
	mac, err := secure.Decode(env.VaultMAC)
	if err != nil || !hmac.Equal(mac, secure.MAC(macKey, message)) {
		return nil, ErrAuth
	}
	if !secure.Verify(r.Sender.SigningPublic, message, env.Signature) {
		return nil, ErrAuth
	}
	value, err := secure.OpenFromDevice(env.Sealed, targetWrappingPrivate, context)
	if err != nil {
		return nil, ErrAuth
	}
	r.used = true // a valid envelope consumes the request even if the owner declines
	if len(value) < MinValueBytes || len(value) > MaxValueBytes || !utf8.Valid(value) {
		secure.Wipe(value)
		return nil, ErrValueSize
	}
	return value, nil
}

func newVerified(d Descriptor, raw []byte) (*Request, error) {
	expires, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Request{Descriptor: d, digest: sha256.Sum256(raw), expires: expires}, nil
}

func (d Descriptor) validate() error {
	if d.Version != Version || !validID(d.VaultID) || protocol.ValidateNonce(d.RequestID) != nil {
		return ErrInvalid
	}
	nonce, err := secure.Decode(d.Nonce)
	if err != nil || len(nonce) != NonceBytes || secure.Encode(nonce) != d.Nonce {
		return ErrInvalid
	}
	for _, dev := range []Device{d.Target, d.Sender} {
		if !validID(dev.ID) || len(dev.Name) > maxNameLen || !utf8.ValidString(dev.Name) ||
			secure.ValidatePublicDeviceKeys(dev.SigningPublic, dev.WrappingPublic) != nil {
			return ErrInvalid
		}
	}
	if d.Target.ID == d.Sender.ID || d.Target.SigningPublic == d.Sender.SigningPublic ||
		d.Target.WrappingPublic == d.Sender.WrappingPublic {
		return ErrInvalid
	}
	if d.Sink.Kind != SinkIngest || !ValidName(d.Sink.Name) {
		return ErrInvalid
	}
	if len(d.Reason) > MaxReasonLen || !utf8.ValidString(d.Reason) {
		return ErrInvalid
	}
	created, err1 := time.Parse(time.RFC3339, d.CreatedAt)
	expires, err2 := time.Parse(time.RFC3339, d.ExpiresAt)
	if err1 != nil || err2 != nil || created.UTC().Format(time.RFC3339) != d.CreatedAt ||
		expires.UTC().Format(time.RFC3339) != d.ExpiresAt || !expires.After(created) ||
		expires.Sub(created) > protocol.RelayMaxTTL {
		return ErrInvalid
	}
	return nil
}

// ValidName accepts environment-variable style secret names.
func ValidName(name string) bool {
	if name == "" || len(name) > 128 || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c != '-' && c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func descriptorKey(vaultKey []byte, vaultID string) ([]byte, error) {
	return secure.DeriveSubkey(vaultKey, []byte("envbank.relay.descriptor-key.v1\x00"+vaultID))
}

func macKey(vaultKey []byte, vaultID string) ([]byte, error) {
	return secure.DeriveSubkey(vaultKey, []byte("envbank.relay.mac-key.v1\x00"+vaultID))
}

func descriptorAAD(vaultID, requestID, targetID, senderID, expiresAt string) []byte {
	return []byte(strings.Join([]string{"envbank.relay.descriptor.v1", vaultID, requestID, targetID, senderID, expiresAt}, "\x00"))
}

func descriptorSignatureMessage(raw []byte) []byte {
	return append([]byte("envbank.relay.request.v1\n"), raw...)
}

// sealContext is the HKDF info and AES-GCM AAD of the value envelope. It binds
// vault, request, both devices, sink, expiry, nonce and the exact descriptor.
func (r *Request) sealContext() []byte {
	return []byte(strings.Join([]string{
		"envbank.relay.seal.v1", r.VaultID, r.RequestID, r.Target.ID, r.Sender.ID,
		r.Sink.Kind, r.Sink.Name, r.ExpiresAt, r.Nonce, secure.Encode(r.digest[:]),
	}, "\x00"))
}

func envelopeMessage(context []byte, env protocol.RelayEnvelope) []byte {
	sum := sha256.Sum256(context)
	return []byte(strings.Join([]string{
		"envbank.relay.envelope.v1", secure.Encode(sum[:]), strconv.Itoa(env.Version),
		env.RequestID, env.SenderDeviceID, strconv.Itoa(env.Sealed.Version), env.Sealed.EphemeralKey,
		strconv.Itoa(env.Sealed.Blob.Version), env.Sealed.Blob.Nonce, env.Sealed.Blob.Ciphertext,
	}, "\n"))
}

func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return ErrInvalid
	}
	return nil
}
