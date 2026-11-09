// Package ownerinput is the EnvBank (broker) side of the owner-input
// provider protocol (docs/owner-input-protocol.md): the broker dials a
// desktop-host provider, verifies the peer's dynamic code signature (pinned
// Team ID and identifier, hardened runtime) before sending anything, pairs
// once per broker session by having the owner confirm a 6-digit code shown in
// the provider's own window, and pins that exact build (cdhash) for the rest
// of the session. Values arrive only in an `entered` response on the same
// verified connection and are zeroed by the caller after use.
package ownerinput

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Version is the protocol version.
const Version = "envbank.owner-input/v1"

// Fixed codes; nothing peer- or value-derived is ever echoed.
const (
	CodeUnavailable    = "OWNER_INPUT_UNAVAILABLE"
	CodePeerUnverified = "OWNER_INPUT_PEER_UNVERIFIED"
	CodeNotPaired      = "OWNER_INPUT_NOT_PAIRED"
	CodeProtocol       = "OWNER_INPUT_PROTOCOL_ERROR"
)

// Purposes.
const (
	PurposeNewVault   = "new_vault_passphrase"
	PurposeRecovery   = "recovery_passphrase"
	PurposeUnlock     = "unlock_passphrase"
	PurposeSecretVal  = "secret_value"
	maxFrame          = 16 << 10
	maxValue          = 4096
	requestTTL        = 110 * time.Second
	responseWaitExtra = 10 * time.Second
)

// Identity is the verified signing identity of the provider process.
type Identity struct {
	TeamID          string
	Identifier      string
	CDHash          string
	HardenedRuntime bool
}

// DefaultSocketPath is the provider socket from the spec.
func DefaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "EnvBank", "owner-input", "provider.sock")
}

// Provider is a paired desktop-host provider for one broker session.
type Provider struct {
	Socket     string
	TeamID     string
	Identifier string

	mu     sync.Mutex
	paired *Identity
	busy   bool
}

// verifyPeer is the real signature check; tests in this package replace it.
var verifyPeer = peerIdentity

var teamRe = regexp.MustCompile(`^[A-Z0-9]{10}$`)
var identRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{2,200}$`)

// Requirement is the code requirement every provider connection must satisfy.
func (p *Provider) Requirement() (string, error) {
	if !teamRe.MatchString(p.TeamID) || !identRe.MatchString(p.Identifier) {
		return "", errors.New("owner-input: pinned team id and identifier are required")
	}
	// Developer ID only: Apple Development certificates also satisfy
	// `anchor apple generic`, and can be minted for debuggable builds.
	return fmt.Sprintf(`anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "%s" and identifier "%s"`, p.TeamID, p.Identifier), nil
}

// dial connects and verifies the peer before anything is sent. When paired,
// the peer must be the exact paired build.
func (p *Provider) dial(ctx context.Context) (*net.UnixConn, Identity, error) {
	req, err := p.Requirement()
	if err != nil {
		return nil, Identity{}, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", p.Socket)
	if err != nil {
		return nil, Identity{}, errors.New(CodeUnavailable)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, Identity{}, errors.New(CodeUnavailable)
	}
	id, err := verifyPeer(uc, req)
	if err != nil || id.TeamID != p.TeamID || id.Identifier != p.Identifier {
		uc.Close()
		return nil, Identity{}, errors.New(CodePeerUnverified)
	}
	p.mu.Lock()
	paired := p.paired
	p.mu.Unlock()
	if paired != nil && paired.CDHash != id.CDHash {
		uc.Close()
		return nil, Identity{}, errors.New(CodePeerUnverified)
	}
	return uc, id, nil
}

type response struct {
	V        string          `json:"v"`
	Nonce    string          `json:"nonce"`
	Outcome  string          `json:"outcome"`
	Value    string          `json:"value,omitempty"`
	Provider json.RawMessage `json:"provider,omitempty"`
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RequestCode is what the provider window shows for a nonce (XXXX-XXXX).
func RequestCode(nonce string) string {
	if len(nonce) < 8 {
		return ""
	}
	return fmt.Sprintf("%s-%s", upper(nonce[:4]), upper(nonce[4:8]))
}

func upper(s string) string { return string(bytes.ToUpper([]byte(s))) }

func (p *Provider) exchange(ctx context.Context, frame map[string]any, nonce string, expires time.Time) (response, Identity, error) {
	conn, id, err := p.dial(ctx)
	if err != nil {
		return response{}, Identity{}, err
	}
	defer conn.Close()
	raw, err := json.Marshal(frame)
	if err != nil || len(raw)+1 > maxFrame {
		return response{}, Identity{}, errors.New(CodeProtocol)
	}
	_ = conn.SetDeadline(expires.Add(responseWaitExtra))
	go func() { <-ctx.Done(); conn.Close() }()
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return response{}, Identity{}, errors.New(CodeUnavailable)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxFrame+1), 4096).ReadBytes('\n')
	defer wipe(line)
	if err != nil || len(line) > maxFrame {
		return response{}, Identity{}, errors.New(CodeProtocol)
	}
	var r response
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || r.V != Version || r.Nonce != nonce || time.Now().After(expires.Add(responseWaitExtra)) {
		return response{}, Identity{}, errors.New(CodeProtocol)
	}
	return r, id, nil
}

// Pair sends a pairing code; confirm is asked (in the broker terminal) whether
// the provider window shows the same code for this identity. On yes, this exact
// build (cdhash) is pinned for the session.
func (p *Provider) Pair(ctx context.Context, confirm func(id Identity, code string) bool) error {
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
	r, id, err := p.exchange(ctx, map[string]any{"v": Version, "nonce": nonce, "pairing_code": code, "expires_at": expires.Format(time.RFC3339)}, nonce, expires)
	if err != nil {
		return err
	}
	if r.Outcome != "displayed" || r.Value != "" {
		return errors.New(CodeNotPaired)
	}
	if !confirm(id, code) {
		return errors.New(CodeNotPaired)
	}
	p.mu.Lock()
	p.paired = &id
	p.mu.Unlock()
	return nil
}

// Paired reports the pinned identity, if any.
func (p *Provider) Paired() (Identity, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.paired == nil {
		return Identity{}, false
	}
	return *p.paired, true
}

// Entry asks the owner (in the provider window) for a value. outcome is one of
// entered/declined/cancelled/expired/busy; value is non-nil only on entered and
// must be wiped by the caller. onCode is called with the request code so the
// broker terminal can show it next to the provider window's code.
func (p *Provider) Entry(ctx context.Context, purpose, title, detail, subject string, minBytes, maxBytes int, confirm bool, onCode func(string)) ([]byte, string, error) {
	if _, ok := p.Paired(); !ok {
		return nil, "", errors.New(CodeNotPaired)
	}
	if minBytes < 1 || maxBytes > maxValue || minBytes > maxBytes {
		return nil, "", errors.New(CodeProtocol)
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().Add(requestTTL).UTC()
	if onCode != nil {
		onCode(RequestCode(nonce))
	}
	frame := map[string]any{"v": Version, "nonce": nonce, "purpose": purpose, "title": clipRunes(title, 80), "detail": clipRunes(detail, 300),
		"subject": clipRunes(subject, 128), "min_bytes": minBytes, "max_bytes": maxBytes, "confirm": confirm, "expires_at": expires.Format(time.RFC3339)}
	r, _, err := p.exchange(ctx, frame, nonce, expires)
	if err != nil {
		return nil, "", err
	}
	switch r.Outcome {
	case "entered":
		v, err := base64.StdEncoding.DecodeString(r.Value)
		if err != nil || len(v) < minBytes || len(v) > maxBytes {
			wipe(v)
			return nil, "", errors.New(CodeProtocol)
		}
		return v, "entered", nil
	case "declined", "cancelled", "expired", "busy":
		if r.Value != "" {
			return nil, "", errors.New(CodeProtocol)
		}
		return nil, r.Outcome, nil
	default:
		return nil, "", errors.New(CodeProtocol)
	}
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	out := make([]rune, 0, len(r))
	for _, c := range r {
		if len(out) >= n {
			break
		}
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0xfeff {
			c = ' ' // the provider refuses control/bidi characters; never send them
		}
		out = append(out, c)
	}
	return string(out)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
