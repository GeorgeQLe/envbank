package ownerinput

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// XPCVersion is the XPC transport version (docs/owner-input-xpc.md).
const XPCVersion = "envbank.owner-input-xpc/v1"

// Default service names and identifiers.
const (
	BrokerServiceName = "dev.georgele.chromux.owner-input"
	ServiceIdentifier = "dev.georgele.chromux.owner-input"
)

// xpcRawReply is a reply on the agent connection: its flattened fields and,
// separately, the `value` data (copied into Go memory; the C copy is zeroed).
// A value appears in Fields only as an empty 'X' record.
type xpcRawReply struct {
	Fields   []xpcField
	Value    []byte
	HasValue bool
}

var cdhashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// XPCProvider talks to the Chromux owner-input service over XPC. macOS checks
// the service's code signature on every message (Developer ID, pinned team and
// identifier, not debuggable); after pairing, the exact service build is added
// to the requirement as a cdhash.
type XPCProvider struct {
	Service    string
	TeamID     string
	Identifier string
	// Label names this broker's vault and device in the pairing frame, so
	// the host's Touch ID text says which broker is asking (optional).
	Label PairingLabel

	mu     sync.Mutex
	cdhash string // pinned after pairing
}

// Requirement returns the peer code-signing requirement for the service.
func (p *XPCProvider) Requirement() (string, error) {
	if !teamRe.MatchString(p.TeamID) || !identRe.MatchString(p.Identifier) {
		return "", errors.New("owner-input: pinned team id and identifier are required")
	}
	req := fmt.Sprintf(`anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "%s" and identifier "%s" and !(entitlement["com.apple.security.get-task-allow"] exists)`, p.TeamID, p.Identifier)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cdhash != "" {
		req += fmt.Sprintf(` and cdhash H"%s"`, p.cdhash)
	}
	return req, nil
}

// PairingLabel is the optional broker identity sent with a pairing:
// vault_fingerprint (a short hash of the vault ID, or "setup" before a vault
// exists) and device_name (this device's EnvBank name, sanitized). Both are
// at most MaxPairingLabelBytes; neither is secret or authoritative.
type PairingLabel struct {
	VaultFingerprint string
	DeviceName       string
}

// MaxPairingLabelBytes bounds each pairing label field.
const MaxPairingLabelBytes = 64

// SetupVaultFingerprint is the vault_fingerprint of a broker in setup mode.
const SetupVaultFingerprint = "setup"

var fingerprintRe = regexp.MustCompile(`^([0-9a-f]{16}|setup)$`)

// VaultFingerprint is the short public fingerprint of a vault ID shown in
// pairing prompts: 16 hex digits of a domain-separated SHA-256.
func VaultFingerprint(vaultID string) string {
	sum := sha256.Sum256([]byte("envbank vault fingerprint v1\x00" + vaultID))
	return hex.EncodeToString(sum[:8])
}

// CleanDeviceName renders a device name as one plain line of at most
// MaxPairingLabelBytes bytes (control and format characters replaced).
func CleanDeviceName(name string) string {
	s := approval.Clean(name, MaxPairingLabelBytes)
	for len(s) > MaxPairingLabelBytes {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// fields returns the label's pairing-frame fields; an invalid fingerprint is
// omitted rather than sent.
func (l PairingLabel) fields() []xpcField {
	var f []xpcField
	if fingerprintRe.MatchString(l.VaultFingerprint) {
		f = append(f, xpcField{'S', "vault_fingerprint", l.VaultFingerprint})
	}
	if d := CleanDeviceName(l.DeviceName); d != "" {
		f = append(f, xpcField{'S', "device_name", d})
	}
	return f
}

// Describe is the label as shown in the broker's own pairing prompt.
func (l PairingLabel) Describe() string {
	v := "unknown vault"
	switch {
	case l.VaultFingerprint == SetupVaultFingerprint:
		v = "setup mode, no vault yet"
	case fingerprintRe.MatchString(l.VaultFingerprint):
		v = "vault " + l.VaultFingerprint
	}
	if d := CleanDeviceName(l.DeviceName); d != "" {
		return v + ", device " + approval.Quote(d, MaxPairingLabelBytes)
	}
	return v
}

// OutcomeConfirmed is the only pairing outcome that pairs: the service shows
// the code in Chromux and replies "confirmed" only after the owner confirmed
// it there with Touch ID. ("displayed" no longer pairs.)
const OutcomeConfirmed = "confirmed"

// pairingReplyKeys are the keys a pairing reply may carry, with their types
// as flattened by the agent connection ('D' is a dictionary).
var pairingReplyKeys = map[string]byte{"v": 'S', "nonce": 'S', "outcome": 'S', "service_cdhash": 'S', "provider": 'D'}

// pairOn pairs on conn, the long-lived connection the broker will register
// on. Both sides must confirm: the service replies "confirmed" only after the
// owner confirmed the code in Chromux with Touch ID, and then confirm asks
// the owner again in the broker terminal (Touch ID). On success the service
// build is pinned by cdhash; a later pairing must be the same build.
func (p *XPCProvider) pairOn(ctx context.Context, conn agentConn, confirm func(id Identity, code string) bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	expires := time.Now().Add(requestTTL).UTC()
	frame := []xpcField{{'S', "v", XPCVersion}, {'S', "kind", "pairing"}, {'S', "nonce", nonce},
		{'S', "pairing_code", code}, {'S', "expires_at", expires.Format(time.RFC3339)}}
	r, err := conn.Request(append(frame, p.Label.fields()...), time.Until(expires)+responseWaitExtra)
	if err != nil {
		return err
	}
	if r.HasValue {
		wipe(r.Value)
		return errors.New(CodeProtocol)
	}
	got := map[string]string{}
	for _, f := range r.Fields {
		want, ok := pairingReplyKeys[f.Key]
		if _, dup := got[f.Key]; !ok || want != f.Type || dup {
			return errors.New(CodeProtocol) // unknown keys, wrong types or a value
		}
		got[f.Key] = f.Value
	}
	if got["v"] != XPCVersion || got["nonce"] != nonce || ctx.Err() != nil {
		return errors.New(CodeProtocol)
	}
	cd := got["service_cdhash"]
	if got["outcome"] != OutcomeConfirmed || !cdhashRe.MatchString(cd) {
		return errors.New(CodeNotPaired)
	}
	p.mu.Lock()
	pinned := p.cdhash
	p.mu.Unlock()
	if pinned != "" && pinned != cd {
		return errors.New(CodePeerUnverified)
	}
	if !confirm(Identity{TeamID: p.TeamID, Identifier: p.Identifier, CDHash: cd, HardenedRuntime: true}, code) || ctx.Err() != nil {
		return errors.New(CodeNotPaired)
	}
	p.mu.Lock()
	p.cdhash = cd
	p.mu.Unlock()
	return nil
}

// entryReplyKeys are the keys an entry reply may carry ('X' is the `value`
// data, which is delivered separately).
var entryReplyKeys = map[string]byte{"v": 'S', "nonce": 'S', "outcome": 'S', "service_cdhash": 'S', "provider": 'D', "value": 'X'}

// Entry asks the owner for a value in Chromux's secure window. It is sent
// only on the agent channel's long-lived connection, and only while that
// connection holds a host-confirmed pairing (the service refuses entry on any
// other broker connection). Without one it fails fast (OWNER_INPUT_NOT_PAIRED)
// and the caller falls back to the terminal. outcome is entered, declined,
// cancelled, expired, busy or unavailable; the value is non-nil only on
// entered and must be wiped by the caller.
func (a *AgentChannel) Entry(ctx context.Context, purpose, title, detail, subject string, minBytes, maxBytes int, confirm bool, onCode func(string)) ([]byte, string, error) {
	if minBytes < 1 || maxBytes > maxValue || minBytes > maxBytes {
		return nil, "", errors.New(CodeProtocol)
	}
	conn, ok := a.pairedConn()
	if !ok || a.Provider == nil || !a.Provider.Pinned() {
		return nil, "", errors.New(CodeNotPaired)
	}
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().Add(requestTTL).UTC()
	if onCode != nil {
		onCode(RequestCode(nonce))
	}
	confirmFlag := "0"
	if confirm {
		confirmFlag = "1"
	}
	r, err := conn.Request([]xpcField{
		{'S', "v", XPCVersion}, {'S', "kind", "entry"}, {'S', "nonce", nonce}, {'S', "purpose", purpose},
		{'S', "title", clipRunes(title, 80)}, {'S', "detail", clipRunes(detail, 300)}, {'S', "subject", clipRunes(subject, 128)},
		{'I', "min_bytes", strconv.Itoa(minBytes)}, {'I', "max_bytes", strconv.Itoa(maxBytes)}, {'B', "confirm", confirmFlag},
		{'S', "expires_at", expires.Format(time.RFC3339)},
	}, time.Until(expires)+responseWaitExtra)
	if err != nil {
		return nil, "", err
	}
	fail := func() ([]byte, string, error) {
		wipe(r.Value)
		return nil, "", errors.New(CodeProtocol)
	}
	got := map[string]string{}
	for _, f := range r.Fields {
		want, known := entryReplyKeys[f.Key]
		if _, dup := got[f.Key]; !known || want != f.Type || dup {
			return fail()
		}
		got[f.Key] = f.Value
	}
	_, valueField := got["value"]
	if got["v"] != XPCVersion || got["nonce"] != nonce || valueField != r.HasValue || time.Now().After(expires.Add(responseWaitExtra)) {
		return fail()
	}
	if cd, ok := got["service_cdhash"]; ok && cd != a.Provider.pinned() {
		return fail()
	}
	switch got["outcome"] {
	case "entered":
		if !r.HasValue || len(r.Value) < minBytes || len(r.Value) > maxBytes || ctx.Err() != nil {
			return fail()
		}
		return r.Value, "entered", nil
	case "declined", "cancelled", "expired", "busy", "unavailable":
		if r.HasValue {
			return fail()
		}
		return nil, got["outcome"], nil
	default:
		return fail()
	}
}

func (p *XPCProvider) pinned() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cdhash
}
