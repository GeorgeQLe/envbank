package ownerinput

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sync"
	"time"
)

// XPCVersion is the XPC transport version (docs/owner-input-xpc.md).
const XPCVersion = "envbank.owner-input-xpc/v1"

// Default service names and identifiers.
const (
	BrokerServiceName = "dev.georgele.chromux.owner-input"
	ServiceIdentifier = "dev.georgele.chromux.owner-input"
)

type xpcMessage struct {
	strings map[string]string
	ints    map[string]int64
	bools   map[string]bool
}

type xpcReply struct {
	Version       string
	Nonce         string
	Outcome       string
	ServiceCDHash string
	Value         []byte
	HasValue      bool
	UnknownKeys   bool
}

// xpcSend is the transport; tests replace it.
var xpcSend = xpcRequest

var cdhashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// XPCProvider talks to the Chromux owner-input service over XPC. macOS checks
// the service's code signature on every message (Developer ID, pinned team and
// identifier, not debuggable); after pairing, the exact service build is added
// to the requirement as a cdhash.
type XPCProvider struct {
	Service    string
	TeamID     string
	Identifier string

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

func (p *XPCProvider) exchange(ctx context.Context, msg xpcMessage, nonce string, expires time.Time) (xpcReply, error) {
	if ctx.Err() != nil {
		return xpcReply{}, ctx.Err()
	}
	req, err := p.Requirement()
	if err != nil {
		return xpcReply{}, err
	}
	timeout := time.Until(expires) + responseWaitExtra
	r, err := xpcSend(p.Service, req, msg, timeout)
	if err != nil {
		return xpcReply{}, err
	}
	if r.Version != XPCVersion || r.Nonce != nonce || r.UnknownKeys {
		wipe(r.Value)
		return xpcReply{}, errors.New(CodeProtocol)
	}
	return r, nil
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
	fields, err := conn.Request([]xpcField{{'S', "v", XPCVersion}, {'S', "kind", "pairing"}, {'S', "nonce", nonce},
		{'S', "pairing_code", code}, {'S', "expires_at", expires.Format(time.RFC3339)}}, time.Until(expires)+responseWaitExtra)
	if err != nil {
		return err
	}
	got := map[string]string{}
	for _, f := range fields {
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

// Entry implements the same contract as Provider.Entry over XPC.
func (p *XPCProvider) Entry(ctx context.Context, purpose, title, detail, subject string, minBytes, maxBytes int, confirm bool, onCode func(string)) ([]byte, string, error) {
	p.mu.Lock()
	paired := p.cdhash != ""
	p.mu.Unlock()
	if !paired {
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
	msg := xpcMessage{
		strings: map[string]string{"v": XPCVersion, "kind": "entry", "nonce": nonce, "purpose": purpose, "title": clipRunes(title, 80),
			"detail": clipRunes(detail, 300), "subject": clipRunes(subject, 128), "expires_at": expires.Format(time.RFC3339)},
		ints:  map[string]int64{"min_bytes": int64(minBytes), "max_bytes": int64(maxBytes)},
		bools: map[string]bool{"confirm": confirm},
	}
	r, err := p.exchange(ctx, msg, nonce, expires)
	if err != nil {
		return nil, "", err
	}
	switch r.Outcome {
	case "entered":
		if !r.HasValue || len(r.Value) < minBytes || len(r.Value) > maxBytes {
			wipe(r.Value)
			return nil, "", errors.New(CodeProtocol)
		}
		return r.Value, "entered", nil
	case "declined", "cancelled", "expired", "busy", "unavailable":
		if r.HasValue {
			wipe(r.Value)
			return nil, "", errors.New(CodeProtocol)
		}
		return nil, r.Outcome, nil
	default:
		wipe(r.Value)
		return nil, "", errors.New(CodeProtocol)
	}
}
