// Package authz is the broker's policy for authorized agents
// (docs/authorized-agents.md, envbank.authorized-agents/v1).
//
// Only agent sessions launched by the desktop host, identified by the
// session tuple the host attaches (session_id, workspace, agent_kind), can
// use EnvBank, and only within grants the owner made with Touch ID. Grants
// live in broker memory, last at most 12 hours and end when the broker locks.
// Every request is checked against grants BEFORE anything is shown to the
// owner: an ungranted request is refused with NOT_AUTHORIZED and never
// prompts. Revocation only reduces access and needs no Touch ID.
package authz

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
)

// Version is the authorized-agents protocol version.
const Version = "envbank.authorized-agents/v1"

// Grant scopes.
const (
	ScopeNames   = "names"
	ScopeRun     = "run"
	ScopeRequest = "request"
	ScopeSetup   = "setup"
	ScopeRelay   = "relay"
)

// Agent operations beyond the agent broker's own.
const (
	OpGrantRequest = "grant_request"
	OpGrantStatus  = "grant_status"
	OpGrantRevoke  = "grant_revoke"
	OpRelayRequest = "relay_request"
)

// Limits.
const (
	MaxDuration         = 12 * time.Hour
	MinDuration         = time.Minute
	MaxGrantsPerSession = 16
	MaxGrants           = 256
)

var (
	sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	workspaceRe = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{1,128}$`)
	agentKindRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
)

// Session is the identity the desktop host attaches to an agent's request.
// The host, not the agent, sets it (it owns the session it launched).
type Session struct {
	ID        string `json:"session_id"`
	Workspace string `json:"workspace"`
	AgentKind string `json:"agent_kind"`
	Label     string `json:"label"`
}

// ErrInvalidSession is returned for a malformed session tuple.
var ErrInvalidSession = errors.New("invalid session")

// Validate checks every field strictly: session_id is an unguessable token
// (22 to 128 URL-safe characters, at least 128 bits), workspace and
// agent_kind are identifiers, and label is plain text of at most 80
// characters with no control or bidi characters.
func (s Session) Validate() error {
	if !sessionIDRe.MatchString(s.ID) || !workspaceRe.MatchString(s.Workspace) || !agentKindRe.MatchString(s.AgentKind) || !validLabel(s.Label) {
		return ErrInvalidSession
	}
	return nil
}

func validLabel(l string) bool {
	if !utf8.ValidString(l) || utf8.RuneCountInString(l) > 80 || strings.TrimSpace(l) == "" {
		return false
	}
	for _, r := range l {
		if r != ' ' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) || !unicode.IsPrint(r)) {
			return false
		}
	}
	return true
}

type tuple struct{ id, workspace, kind string }

func (s Session) key() tuple { return tuple{s.ID, s.Workspace, s.AgentKind} }

// Who describes the session for owner prompts (bounded, cleaned).
func (s Session) Who() string {
	return fmt.Sprintf("agent session %s (%s, workspace %s)", approval.Quote(s.Label, 80), approval.Clean(s.AgentKind, 32), approval.Clean(s.Workspace, 64))
}

// Grant is one owner-approved grant.
type Grant struct {
	id        string
	session   tuple
	Secrets   []string
	Scope     string
	GrantedAt time.Time
	ExpiresAt time.Time
	revoked   bool
}

// Info is the value-free description returned to the session.
func (g Grant) Info() agentbroker.GrantInfo {
	return agentbroker.GrantInfo{Secrets: append([]string{}, g.Secrets...), Scope: g.Scope,
		GrantedAt: g.GrantedAt.UTC().Format(time.RFC3339), ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339)}
}

// Store holds grants in memory only.
type Store struct {
	mu     sync.Mutex
	now    func() time.Time
	grants map[string]*Grant
	closed bool
	// ended is called (outside the lock) with grants that expired, were
	// revoked or were dropped on close, so "always" approvals end with them.
	ended func(id string)
}

// NewStore returns an empty store. now may be nil (time.Now).
func NewStore(now func() time.Time, ended func(id string)) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, grants: map[string]*Grant{}, ended: ended}
}

func (st *Store) notify(ids []string) {
	if st.ended == nil {
		return
	}
	for _, id := range ids {
		st.ended(id)
	}
}

// pruneLocked removes expired grants and returns their ids.
func (st *Store) pruneLocked() []string {
	var gone []string
	now := st.now()
	for id, g := range st.grants {
		if g.revoked || !now.Before(g.ExpiresAt) {
			delete(st.grants, id)
			gone = append(gone, id)
		}
	}
	return gone
}

// ErrFull is returned when a session or the broker holds too many grants.
var ErrFull = errors.New("too many grants")

// errClosed is returned after Close.
var errClosed = errors.New("store closed")

// Add records a grant. It is called only after the owner's Touch ID.
func (st *Store) Add(s Session, scope string, secrets []string, d time.Duration) (Grant, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Grant{}, err
	}
	st.mu.Lock()
	gone := st.pruneLocked()
	defer func() { st.notify(gone) }()
	defer st.mu.Unlock()
	if st.closed {
		return Grant{}, errClosed
	}
	n := 0
	for _, g := range st.grants {
		if g.session == s.key() {
			n++
		}
	}
	if n >= MaxGrantsPerSession || len(st.grants) >= MaxGrants {
		return Grant{}, ErrFull
	}
	now := st.now()
	g := &Grant{id: hex.EncodeToString(raw[:]), session: s.key(), Secrets: append([]string(nil), secrets...), Scope: scope, GrantedAt: now, ExpiresAt: now.Add(d)}
	st.grants[g.id] = g
	return *g, nil
}

// Count reports how many grants s already holds (for checks before a prompt).
func (st *Store) Count(s Session) (session, total int) {
	st.mu.Lock()
	gone := st.pruneLocked()
	for _, g := range st.grants {
		if g.session == s.key() {
			session++
		}
	}
	total = len(st.grants)
	st.mu.Unlock()
	st.notify(gone)
	return session, total
}

// Active returns s's unexpired grants, oldest first.
func (st *Store) Active(s Session) []Grant {
	st.mu.Lock()
	gone := st.pruneLocked()
	var out []Grant
	for _, g := range st.grants {
		if g.session == s.key() {
			out = append(out, *g)
		}
	}
	st.mu.Unlock()
	st.notify(gone)
	sort.Slice(out, func(i, j int) bool {
		if out[i].GrantedAt.Equal(out[j].GrantedAt) {
			return out[i].id < out[j].id
		}
		return out[i].GrantedAt.Before(out[j].GrantedAt)
	})
	return out
}

// Covering returns an active grant of s with scope that names every secret
// (for setup and relay, any active grant of that scope). When several cover
// the request, the one that lasts longest is used.
func (st *Store) Covering(s Session, scope string, secrets []string) (Grant, bool) {
	var best Grant
	found := false
	for _, g := range st.Active(s) {
		if g.Scope != scope || !covers(g.Secrets, secrets, scope) {
			continue
		}
		if !found || g.ExpiresAt.After(best.ExpiresAt) {
			best, found = g, true
		}
	}
	return best, found
}

func covers(granted, wanted []string, scope string) bool {
	if scope == ScopeSetup || scope == ScopeRelay {
		return len(wanted) == 0
	}
	if len(wanted) == 0 {
		return false
	}
	set := make(map[string]bool, len(granted))
	for _, n := range granted {
		set[n] = true
	}
	for _, n := range wanted {
		if !set[n] {
			return false
		}
	}
	return true
}

// Valid reports whether grant id is still active for s.
func (st *Store) Valid(id string, s Session) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	g, ok := st.grants[id]
	return ok && !st.closed && !g.revoked && g.session == s.key() && st.now().Before(g.ExpiresAt)
}

// Revoke ends every grant of s and returns how many ended.
func (st *Store) Revoke(s Session) int {
	st.mu.Lock()
	var gone []string
	for id, g := range st.grants {
		if g.session == s.key() {
			g.revoked = true
			delete(st.grants, id)
			gone = append(gone, id)
		}
	}
	n := len(gone)
	gone = append(gone, st.pruneLocked()...)
	st.mu.Unlock()
	st.notify(gone)
	return n
}

// Close ends every grant (the broker locked).
func (st *Store) Close() {
	st.mu.Lock()
	st.closed = true
	var gone []string
	for id, g := range st.grants {
		g.revoked = true
		gone = append(gone, id)
	}
	st.grants = map[string]*Grant{}
	st.mu.Unlock()
	st.notify(gone)
}
