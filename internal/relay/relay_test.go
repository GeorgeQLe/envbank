package relay

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

type party struct {
	dev  Device
	keys secure.DeviceKeys
}

func newParty(t *testing.T, id, name string) party {
	t.Helper()
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	return party{dev: Device{ID: id, Name: name, SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic}, keys: keys}
}

type fixture struct {
	vaultID  string
	vaultKey []byte
	target   party
	sender   party
	now      time.Time
	create   protocol.RelayCreateRequest
	server   protocol.RelayRequest
	onTarget *Request
	onSender *Request
	value    []byte
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{vaultID: "vault-1", target: newParty(t, "target-dev", "laptop"), sender: newParty(t, "sender-dev", "phone"),
		now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), value: []byte("relay-test-value-not-a-secret-0001")}
	var err error
	if f.vaultKey, err = secure.RandomBytes(32); err != nil {
		t.Fatal(err)
	}
	f.create, f.onTarget, err = NewRequest(f.vaultID, f.vaultKey, f.target.dev, f.target.keys.Secrets.SigningPrivate,
		f.sender.dev, Sink{Kind: SinkIngest, Name: "DEPLOY_TOKEN"}, "deploy preview", f.now, protocol.RelayMaxTTL)
	if err != nil {
		t.Fatal(err)
	}
	f.server = protocol.RelayRequest{Version: 1, ID: f.create.ID, TargetDeviceID: f.target.dev.ID,
		SenderDeviceID: f.create.SenderDeviceID, CreatedAt: f.onTarget.CreatedAt, ExpiresAt: f.create.ExpiresAt,
		State: protocol.RelayPending, Descriptor: f.create.Descriptor}
	if f.onSender, err = OpenRequest(f.vaultID, f.vaultKey, f.server, f.sender.dev, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) seal(t *testing.T) protocol.RelayEnvelope {
	t.Helper()
	env, err := Seal(f.onSender, f.vaultKey, f.sender.keys.Secrets.SigningPrivate, f.value, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (f *fixture) open(env protocol.RelayEnvelope) ([]byte, error) {
	return Open(f.onTarget, f.vaultKey, f.target.keys.Secrets.WrappingPrivate, env, f.now.Add(2*time.Minute))
}

func TestRelayRoundTripAndSAS(t *testing.T) {
	f := setup(t)
	if f.onTarget.SAS() != f.onSender.SAS() || !regexp.MustCompile(`^\d{3} \d{3}$`).MatchString(f.onTarget.SAS()) {
		t.Fatalf("SAS mismatch or format: %q vs %q", f.onTarget.SAS(), f.onSender.SAS())
	}
	if !f.onTarget.Expires().Equal(f.now.Add(protocol.RelayMaxTTL)) {
		t.Fatalf("expiry %v", f.onTarget.Expires())
	}
	got, err := f.open(f.seal(t))
	if err != nil || string(got) != string(f.value) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	// The descriptor and envelope never contain the value or the sink name in clear.
	raw := f.create.Descriptor.Ciphertext + f.create.Descriptor.Nonce
	if strings.Contains(raw, "DEPLOY_TOKEN") || strings.Contains(raw, "deploy preview") {
		t.Fatal("descriptor leaks metadata")
	}
}

func TestRelaySASChangesWithEitherDeviceOrRequest(t *testing.T) {
	f := setup(t)
	base := f.onTarget.SAS()
	other := newParty(t, "other", "x")
	for name, mutate := range map[string]func(r *Request){
		"target key": func(r *Request) { r.Target.SigningPublic = other.dev.SigningPublic },
		"sender key": func(r *Request) { r.Sender.WrappingPublic = other.dev.WrappingPublic },
		"request id": func(r *Request) { r.RequestID = "AAAAAAAAAAAAAAAAAAAAAAAA" },
		"nonce":      func(r *Request) { r.Nonce = strings.Repeat("B", 43) },
	} {
		r := &Request{Descriptor: f.onTarget.Descriptor}
		mutate(r)
		if r.SAS() == base {
			t.Fatalf("SAS unchanged after mutating %s", name)
		}
	}
}

// Each bound field is authenticated by the AEAD itself: an envelope sealed
// under a context differing in one field fails even with a valid signature
// and vault MAC over the target's own context.
func TestRelayEnvelopeRejectsEachTamperedAADField(t *testing.T) {
	f := setup(t)
	mutations := map[string]func(d *Descriptor){
		"vault id":   func(d *Descriptor) { d.VaultID = "vault-2" },
		"request id": func(d *Descriptor) { d.RequestID = "AAAAAAAAAAAAAAAAAAAAAAAA" },
		"target id":  func(d *Descriptor) { d.Target.ID = "someone-else" },
		"sender id":  func(d *Descriptor) { d.Sender.ID = "someone-else" },
		"sink kind":  func(d *Descriptor) { d.Sink.Kind = "passphrase" },
		"sink name":  func(d *Descriptor) { d.Sink.Name = "OTHER_NAME" },
		"expiry":     func(d *Descriptor) { d.ExpiresAt = "2026-11-04T12:04:00Z" },
		"nonce":      func(d *Descriptor) { d.Nonce = strings.Repeat("C", 43) },
	}
	for name, mutate := range mutations {
		mutated := &Request{Descriptor: f.onTarget.Descriptor, digest: f.onTarget.digest, expires: f.onTarget.expires}
		mutate(&mutated.Descriptor)
		sealed, err := secure.SealToDevice(f.target.dev.WrappingPublic, mutated.sealContext(), f.value)
		if err != nil {
			t.Fatal(err)
		}
		env := f.forge(t, sealed, f.sender.keys.Secrets.SigningPrivate, f.vaultKey)
		if _, err := f.open(env); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: tampered context accepted (%v)", name, err)
		}
		if f.onTarget.used {
			t.Fatalf("%s: rejected envelope consumed the request", name)
		}
	}
	// The exact descriptor bytes are bound too.
	mutated := &Request{Descriptor: f.onTarget.Descriptor, expires: f.onTarget.expires}
	mutated.digest[0] = 1
	sealed, _ := secure.SealToDevice(f.target.dev.WrappingPublic, mutated.sealContext(), f.value)
	if _, err := f.open(f.forge(t, sealed, f.sender.keys.Secrets.SigningPrivate, f.vaultKey)); !errors.Is(err, ErrAuth) {
		t.Fatalf("descriptor digest not bound: %v", err)
	}
	// Sanity: the forging helper itself produces an acceptable envelope.
	good, _ := secure.SealToDevice(f.target.dev.WrappingPublic, f.onTarget.sealContext(), f.value)
	if v, err := f.open(f.forge(t, good, f.sender.keys.Secrets.SigningPrivate, f.vaultKey)); err != nil || string(v) != string(f.value) {
		t.Fatalf("control envelope rejected: %v", err)
	}
}

// forge builds an envelope around sealed, signed and MACed over the target's
// true context, as a key-holding attacker could.
func (f *fixture) forge(t *testing.T, sealed secure.WrappedKey, signingPrivate string, vaultKey []byte) protocol.RelayEnvelope {
	t.Helper()
	env := protocol.RelayEnvelope{Version: Version, RequestID: f.onTarget.RequestID, SenderDeviceID: f.sender.dev.ID, Sealed: sealed}
	message := envelopeMessage(f.onTarget.sealContext(), env)
	var err error
	if env.Signature, err = secure.Sign(signingPrivate, message); err != nil {
		t.Fatal(err)
	}
	key, _ := macKey(vaultKey, f.vaultID)
	env.VaultMAC = secure.Encode(secure.MAC(key, message))
	return env
}

func TestRelayEnvelopeRejectsTamperedFieldsKeysAndSigners(t *testing.T) {
	f := setup(t)
	stranger := newParty(t, "stranger", "evil")
	otherVaultKey, _ := secure.RandomBytes(32)
	good, _ := secure.SealToDevice(f.target.dev.WrappingPublic, f.onTarget.sealContext(), f.value)
	toStranger, _ := secure.SealToDevice(stranger.dev.WrappingPublic, f.onTarget.sealContext(), f.value)
	cases := map[string]protocol.RelayEnvelope{
		"wrong signer":        f.forge(t, good, stranger.keys.Secrets.SigningPrivate, f.vaultKey),
		"target as signer":    f.forge(t, good, f.target.keys.Secrets.SigningPrivate, f.vaultKey),
		"wrong vault key MAC": f.forge(t, good, f.sender.keys.Secrets.SigningPrivate, otherVaultKey),
		"sealed to other key": f.forge(t, toStranger, f.sender.keys.Secrets.SigningPrivate, f.vaultKey),
		"version":             func() protocol.RelayEnvelope { e := f.seal(t); e.Version = 2; return e }(),
		"request id":          func() protocol.RelayEnvelope { e := f.seal(t); e.RequestID = "x"; return e }(),
		"sender id":           func() protocol.RelayEnvelope { e := f.seal(t); e.SenderDeviceID = "x"; return e }(),
		"ciphertext": func() protocol.RelayEnvelope {
			e := f.seal(t)
			e.Sealed.Blob.Ciphertext = flip(e.Sealed.Blob.Ciphertext)
			return e
		}(),
		"blob nonce": func() protocol.RelayEnvelope {
			e := f.seal(t)
			e.Sealed.Blob.Nonce = flip(e.Sealed.Blob.Nonce)
			return e
		}(),
		"ephemeral key": func() protocol.RelayEnvelope {
			e := f.seal(t)
			e.Sealed.EphemeralKey = stranger.dev.WrappingPublic
			return e
		}(),
		"signature":            func() protocol.RelayEnvelope { e := f.seal(t); e.Signature = flip(e.Signature); return e }(),
		"mac":                  func() protocol.RelayEnvelope { e := f.seal(t); e.VaultMAC = flip(e.VaultMAC); return e }(),
		"stripped mac":         func() protocol.RelayEnvelope { e := f.seal(t); e.VaultMAC = ""; return e }(),
		"stripped signature":   func() protocol.RelayEnvelope { e := f.seal(t); e.Signature = ""; return e }(),
		"envelope for another": f.sealFor(t, setup(t)),
	}
	for name, env := range cases {
		if _, err := f.open(env); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Wrong recipient key on the target side.
	if _, err := Open(f.onTarget, f.vaultKey, stranger.keys.Secrets.WrappingPrivate, f.seal(t), f.now.Add(time.Minute)); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong recipient key: %v", err)
	}
	// The sender's Seal refuses a signing key that is not the descriptor's sender.
	if _, err := Seal(f.onSender, f.vaultKey, stranger.keys.Secrets.SigningPrivate, f.value, f.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("seal with wrong signer: %v", err)
	}
}

// sealFor seals a valid envelope for another request, then retargets its ids.
func (f *fixture) sealFor(t *testing.T, other *fixture) protocol.RelayEnvelope {
	env := other.seal(t)
	env.RequestID, env.SenderDeviceID = f.onTarget.RequestID, f.sender.dev.ID
	return env
}

func flip(s string) string {
	raw, _ := secure.Decode(s)
	if len(raw) == 0 {
		return "AA"
	}
	raw[len(raw)/2] ^= 1
	return secure.Encode(raw)
}

func TestRelayExpiryAndReplay(t *testing.T) {
	f := setup(t)
	env := f.seal(t)
	if _, err := Open(f.onTarget, f.vaultKey, f.target.keys.Secrets.WrappingPrivate, env, f.onTarget.Expires()); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired open: %v", err)
	}
	if _, err := Seal(f.onSender, f.vaultKey, f.sender.keys.Secrets.SigningPrivate, f.value, f.onTarget.Expires()); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired seal: %v", err)
	}
	if _, err := OpenRequest(f.vaultID, f.vaultKey, f.server, f.sender.dev, f.onTarget.Expires().Add(time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired request: %v", err)
	}
	if _, err := f.open(env); err != nil {
		t.Fatal(err)
	}
	if _, err := f.open(env); !errors.Is(err, ErrUsed) {
		t.Fatalf("replayed envelope: %v", err)
	}
	if _, err := f.open(f.seal(t)); !errors.Is(err, ErrUsed) {
		t.Fatalf("second envelope for a used request: %v", err)
	}
	if _, _, err := NewRequest(f.vaultID, f.vaultKey, f.target.dev, f.target.keys.Secrets.SigningPrivate, f.sender.dev,
		Sink{Kind: SinkIngest, Name: "X"}, "", f.now, protocol.RelayMaxTTL+time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long ttl: %v", err)
	}
}

func TestOpenRequestVerifiesServerMetadataSignatureAndSender(t *testing.T) {
	f := setup(t)
	at := f.now.Add(time.Minute)
	otherKey, _ := secure.RandomBytes(32)
	stranger := newParty(t, "stranger", "evil")
	if _, err := OpenRequest(f.vaultID, otherKey, f.server, f.sender.dev, at); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong vault key: %v", err)
	}
	if _, err := OpenRequest("vault-2", f.vaultKey, f.server, f.sender.dev, at); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong vault id: %v", err)
	}
	for name, mutate := range map[string]func(r *protocol.RelayRequest){
		"id":      func(r *protocol.RelayRequest) { r.ID = "AAAAAAAAAAAAAAAAAAAAAAAA" },
		"target":  func(r *protocol.RelayRequest) { r.TargetDeviceID = "stranger" },
		"sender":  func(r *protocol.RelayRequest) { r.SenderDeviceID = "stranger" },
		"expires": func(r *protocol.RelayRequest) { r.ExpiresAt = "2026-11-04T12:09:00Z" },
		"blob":    func(r *protocol.RelayRequest) { r.Descriptor.Ciphertext = flip(r.Descriptor.Ciphertext) },
	} {
		server := f.server
		mutate(&server)
		if _, err := OpenRequest(f.vaultID, f.vaultKey, server, f.sender.dev, at); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s tamper: %v", name, err)
		}
	}
	// A vault-key holder that signs as someone other than the named target.
	create, _, err := NewRequest(f.vaultID, f.vaultKey, f.target.dev, stranger.keys.Secrets.SigningPrivate, f.sender.dev,
		Sink{Kind: SinkIngest, Name: "X"}, "", f.now, time.Minute)
	if !errors.Is(err, ErrInvalid) || create.ID != "" {
		t.Fatalf("request signed by a non-target key was built: %v", err)
	}
	// Sender identity must be self.
	if _, err := OpenRequest(f.vaultID, f.vaultKey, f.server, stranger.dev, at); err == nil {
		t.Fatal("request opened by a non-sender")
	}
	self := f.sender.dev
	self.WrappingPublic = stranger.dev.WrappingPublic
	if _, err := OpenRequest(f.vaultID, f.vaultKey, f.server, self, at); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("sender key mismatch: %v", err)
	}
	pending := f.server
	pending.State = protocol.RelaySealed
	if _, err := OpenRequest(f.vaultID, f.vaultKey, pending, f.sender.dev, at); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-pending request: %v", err)
	}
}

func TestVerifyEnrolled(t *testing.T) {
	f := setup(t)
	status := func(d Device, revoked string) protocol.DeviceStatus {
		return protocol.DeviceStatus{Device: protocol.PublicDevice{ID: d.ID, Name: d.Name, SigningPublic: d.SigningPublic,
			WrappingPublic: d.WrappingPublic, Fingerprint: d.Fingerprint()}, RevokedAt: revoked}
	}
	if err := VerifyEnrolled(f.sender.dev, []protocol.DeviceStatus{status(f.target.dev, ""), status(f.sender.dev, "")}); err != nil {
		t.Fatal(err)
	}
	stranger := newParty(t, f.sender.dev.ID, "phone")
	badFingerprint := status(f.sender.dev, "")
	badFingerprint.Device.Fingerprint = "0000000000000000"
	for name, list := range map[string][]protocol.DeviceStatus{
		"absent":          {status(f.target.dev, "")},
		"revoked":         {status(f.sender.dev, "2026-11-04T11:00:00Z")},
		"substituted key": {status(stranger.dev, "")},
		"bad fingerprint": {badFingerprint},
	} {
		if err := VerifyEnrolled(f.sender.dev, list); !errors.Is(err, ErrNotEnrolled) {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRelayValueBounds(t *testing.T) {
	f := setup(t)
	for _, v := range [][]byte{[]byte("short"), make([]byte, MaxValueBytes+1), {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8}} {
		if _, err := Seal(f.onSender, f.vaultKey, f.sender.keys.Secrets.SigningPrivate, v, f.now); !errors.Is(err, ErrValueSize) {
			t.Fatalf("value of %d bytes: %v", len(v), err)
		}
	}
}
