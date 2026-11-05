package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
)

// Request is an agent request from a host session: the agent broker's fields
// plus the grant fields.
type Request struct {
	V              int             `json:"v"`
	Op             string          `json:"op"`
	Name           string          `json:"name,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	Secrets        []string        `json:"secrets,omitempty"`
	Argv           []string        `json:"argv,omitempty"`
	Dir            string          `json:"dir,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	Always         bool            `json:"always,omitempty"`
	Setup          json.RawMessage `json:"setup,omitempty"`
	Scope          string          `json:"scope,omitempty"`
	DurationS      int             `json:"duration_s,omitempty"`
}

func (r Request) broker() agentbroker.Request {
	return agentbroker.Request{V: r.V, Op: r.Op, Name: r.Name, Reason: r.Reason, Secrets: r.Secrets, Argv: r.Argv, Dir: r.Dir, TimeoutSeconds: r.TimeoutSeconds, Always: r.Always, Setup: r.Setup}
}

// ParseRequest decodes one request strictly: a single JSON object of at most
// agentbroker.Limits.RequestBytes with no unknown fields. The host sends no
// `v`; when present it must be 1.
func ParseRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) == 0 || len(raw) > agentbroker.Limits.RequestBytes || !utf8.Valid(raw) {
		return r, errors.New(agentbroker.CodeInvalidRequest)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) || (r.V != 0 && r.V != agentbroker.ProtocolVersion) || r.Op == "" {
		return Request{}, errors.New(agentbroker.CodeInvalidRequest)
	}
	r.V = agentbroker.ProtocolVersion
	return r, nil
}

// Display shows grant requests in the broker terminal for reference. It
// approves nothing.
type Display interface {
	ShowPlan(title string, lines []string)
	Notify(line string)
}

// Gate applies the policy, then hands authorized requests to the broker with
// the session's identity.
type Gate struct {
	Broker  *agentbroker.Broker
	Grants  *Store
	Display Display

	mu     sync.Mutex
	now    func() time.Time
	denied map[tuple]time.Time // last declined grant request per session

	// Global grant-prompt limits (never reset by sessions coming and going).
	promptOpen   bool      // a grant prompt is queued or showing
	lastPrompt   time.Time // when the last grant prompt was started
	denials      int       // consecutive declined grant prompts, any session
	backoffUntil time.Time // no grant prompt before this
}

// Grant-prompt limits against prompt fatigue. Requests inside any of them are
// BROKER_BUSY without a prompt.
const (
	// DeniedCooldown is how long a session must wait after the owner declined
	// (or could not approve) one of its grant requests. It is also the first
	// step of the global backoff.
	DeniedCooldown = 30 * time.Second
	// GrantPromptSpacing is the least time between two grant prompts from
	// any sessions; at most one grant prompt is open at a time.
	GrantPromptSpacing = 10 * time.Second
	// MaxDenialBackoff caps the global backoff, which doubles with every
	// consecutive declined grant prompt (30 s, 1 min, 2 min, …) from any
	// session and resets only when the owner approves one.
	MaxDenialBackoff = 15 * time.Minute
	// maxCooldowns bounds the per-session cooldown map; when full, expired
	// entries go first, then the oldest one. It is never cleared wholesale.
	maxCooldowns = 1024
)

// NewGate wires a gate whose grants, when they end, end their "always"
// approvals and kill their running commands.
func NewGate(b *agentbroker.Broker, d Display, now func() time.Time) *Gate {
	if now == nil {
		now = time.Now
	}
	return &Gate{Broker: b, Grants: NewStore(now, func(id string) { b.EndScope(scopeOf(id)) }), Display: d, now: now, denied: map[tuple]time.Time{}}
}

func scopeOf(grantID string) string { return "grant:" + grantID }

// reservePrompt admits one grant prompt if no other is open, the spacing
// since the last one has passed, the global backoff is over and this session
// is not cooling down.
func (g *Gate) reservePrompt(s Session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if t, ok := g.denied[s.key()]; ok && now.Sub(t) < DeniedCooldown {
		return false
	}
	if g.promptOpen || now.Before(g.backoffUntil) || (!g.lastPrompt.IsZero() && now.Sub(g.lastPrompt) < GrantPromptSpacing) {
		return false
	}
	g.promptOpen, g.lastPrompt = true, now
	return true
}

// releasePrompt ends the open grant prompt. A decline extends the global
// backoff and the session's cooldown; an approval resets the backoff.
func (g *Gate) releasePrompt(s Session, asked, approved bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.promptOpen = false
	if !asked {
		return
	}
	now := g.now()
	if approved {
		g.denials, g.backoffUntil = 0, time.Time{}
		return
	}
	g.denials++
	backoff := MaxDenialBackoff
	if g.denials <= 16 {
		backoff = min(MaxDenialBackoff, DeniedCooldown<<(g.denials-1))
	}
	g.backoffUntil = now.Add(backoff)
	g.recordDenialLocked(s, now)
}

func (g *Gate) recordDenialLocked(s Session, now time.Time) {
	if _, ok := g.denied[s.key()]; !ok && len(g.denied) >= maxCooldowns {
		var oldest tuple
		var oldestAt time.Time
		for k, t := range g.denied {
			if now.Sub(t) >= DeniedCooldown {
				delete(g.denied, k)
				continue
			}
			if oldestAt.IsZero() || t.Before(oldestAt) {
				oldest, oldestAt = k, t
			}
		}
		if len(g.denied) >= maxCooldowns {
			delete(g.denied, oldest)
		}
	}
	g.denied[s.key()] = now
}

// Close ends every grant (the broker is locking).
func (g *Gate) Close() { g.Grants.Close() }

func refuse(code string) agentbroker.Response {
	return agentbroker.Response{V: agentbroker.ProtocolVersion, Code: code}
}

// HandleAgent implements the owner-input agent channel's handler: it returns
// the value-free response as JSON.
func (g *Gate) HandleAgent(ctx context.Context, s Session, raw []byte) []byte {
	resp := g.Handle(ctx, s, raw)
	resp.V = agentbroker.ProtocolVersion
	out, err := json.Marshal(resp)
	if err != nil {
		out, _ = json.Marshal(refuse(agentbroker.CodeInvalidRequest))
	}
	return out
}

// Handle checks raw against s's grants and, only if a grant covers it, runs
// it. The owner is never prompted for an ungranted request.
func (g *Gate) Handle(ctx context.Context, s Session, raw []byte) agentbroker.Response {
	if s.Validate() != nil {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	req, err := ParseRequest(raw)
	if err != nil {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	switch req.Op {
	case OpGrantRequest:
		return g.grantRequest(ctx, s, req)
	case OpGrantStatus:
		if !onlyOp(req) {
			return refuse(agentbroker.CodeInvalidRequest)
		}
		return g.status(s, agentbroker.StateListed)
	case OpGrantRevoke:
		// Revoking only reduces access: no Touch ID.
		if !onlyOp(req) {
			return refuse(agentbroker.CodeInvalidRequest)
		}
		if n := g.Grants.Revoke(s); n > 0 {
			g.Display.Notify(fmt.Sprintf("revoked %d grant(s) of %s", n, s.Who()))
		}
		return agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true, State: agentbroker.StateRevoked}
	case agentbroker.OpNames:
		return g.names(ctx, s, req)
	case agentbroker.OpRun:
		return g.forward(ctx, s, req, ScopeRun, req.Secrets)
	case agentbroker.OpRequest:
		if req.Name == "" {
			return refuse(agentbroker.CodeNotAuthorized)
		}
		return g.forward(ctx, s, req, ScopeRequest, []string{req.Name})
	case agentbroker.OpSetup:
		return g.forward(ctx, s, req, ScopeSetup, nil)
	case OpRelayRequest:
		if _, ok := g.Grants.Covering(s, ScopeRelay, nil); !ok {
			return refuse(agentbroker.CodeNotAuthorized)
		}
		return refuse(agentbroker.CodeNotSupported) // the relay is not built on this branch
	default:
		return refuse(agentbroker.CodeNotAuthorized)
	}
}

func onlyOp(r Request) bool {
	return r.Name == "" && r.Reason == "" && len(r.Secrets) == 0 && len(r.Argv) == 0 && r.Dir == "" && r.TimeoutSeconds == 0 && !r.Always && len(r.Setup) == 0 && r.Scope == "" && r.DurationS == 0
}

func (g *Gate) caller(s Session, gr Grant) agentbroker.Caller {
	id, expires := gr.id, gr.ExpiresAt
	return agentbroker.Caller{Who: s.Ident(), Label: s.DisplayLabel(), Scope: scopeOf(id),
		Valid:    func() bool { return g.Grants.Valid(id, s) },
		TimeLeft: func() time.Duration { return expires.Sub(g.now()) }}
}

func (g *Gate) forward(ctx context.Context, s Session, req Request, scope string, secrets []string) agentbroker.Response {
	if req.Scope != "" || req.DurationS != 0 {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	gr, ok := g.Grants.Covering(s, scope, secrets)
	if !ok {
		return refuse(agentbroker.CodeNotAuthorized)
	}
	return g.Broker.HandleFor(ctx, g.caller(s, gr), req.broker())
}

// names lists only secrets this session holds a grant for (any secret scope).
func (g *Gate) names(ctx context.Context, s Session, req Request) agentbroker.Response {
	if req.Scope != "" || req.DurationS != 0 {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	allowed := map[string]bool{}
	var holder Grant
	found := false
	for _, gr := range g.Grants.Active(s) {
		if gr.Scope == ScopeNames || gr.Scope == ScopeRun || gr.Scope == ScopeRequest {
			for _, n := range gr.Secrets {
				allowed[n] = true
			}
			holder, found = gr, true
		}
	}
	if !found {
		return refuse(agentbroker.CodeNotAuthorized)
	}
	resp := g.Broker.HandleFor(ctx, g.caller(s, holder), req.broker())
	if !resp.OK {
		return resp
	}
	filtered := []string{}
	for _, n := range resp.Names {
		if allowed[n] {
			filtered = append(filtered, n)
		}
	}
	resp.Names = filtered
	return resp
}

func (g *Gate) status(s Session, state string) agentbroker.Response {
	resp := agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true, State: state, Grants: []agentbroker.GrantInfo{}}
	for _, gr := range g.Grants.Active(s) {
		resp.Grants = append(resp.Grants, gr.Info())
	}
	return resp
}

// grantRequest validates the request fully, then asks the owner with Touch
// ID; a grant exists only if that succeeds.
func (g *Gate) grantRequest(ctx context.Context, s Session, req Request) agentbroker.Response {
	if req.Name != "" || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || req.Always || len(req.Setup) != 0 ||
		len(req.Reason) > agentbroker.Limits.ReasonBytes {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	d := time.Duration(req.DurationS) * time.Second
	if req.DurationS <= 0 || d < MinDuration || d > MaxDuration {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	var secrets []string
	switch req.Scope {
	case ScopeNames, ScopeRun, ScopeRequest:
		if len(req.Secrets) == 0 || len(req.Secrets) > agentbroker.Limits.Secrets {
			return refuse(agentbroker.CodeInvalidRequest)
		}
		seen := map[string]bool{}
		for _, n := range req.Secrets {
			if !agentbroker.ValidName(n) || seen[n] {
				return refuse(agentbroker.CodeInvalidRequest)
			}
			seen[n] = true
			secrets = append(secrets, n)
		}
		sort.Strings(secrets)
	case ScopeSetup, ScopeRelay:
		if len(req.Secrets) != 0 {
			return refuse(agentbroker.CodeInvalidRequest)
		}
	default:
		return refuse(agentbroker.CodeInvalidRequest)
	}
	if _, ok := grantReason(s, req.Scope, secrets, d, g.now().Add(d)); !ok {
		return refuse(agentbroker.CodeInvalidRequest) // cannot be shown in full in the Touch ID prompt
	}
	if n, total := g.Grants.Count(s); n >= MaxGrantsPerSession || total >= MaxGrants || !g.reservePrompt(s) {
		return refuse(agentbroker.CodeBusy)
	}
	asked, approved := false, false
	defer func() { g.releasePrompt(s, asked, approved) }()
	resp := g.Broker.WithOwnerPrompt(ctx, func() agentbroker.Response {
		// The expiry shown is computed when the prompt is shown.
		reason, ok := grantReason(s, req.Scope, secrets, d, g.now().Add(d))
		if !ok {
			return refuse(agentbroker.CodeInvalidRequest)
		}
		lines := []string{
			"from: " + s.Ident(),
			"session label (set by the agent's host session): " + s.DisplayLabel(),
			"scope: " + req.Scope + " (" + scopeText(req.Scope) + ")",
			"duration: " + humanDuration(d) + " (ends earlier if the broker locks or you revoke it in the host)",
		}
		if len(secrets) > 0 {
			lines = append(lines, "secrets: "+strings.Join(secrets, ", "))
		}
		if req.Reason != "" {
			lines = append(lines, "agent's reason: "+agentbroker.Sanitize(req.Reason, agentbroker.Limits.ReasonBytes))
		}
		g.Display.ShowPlan("EnvBank grant request", lines)
		asked = true
		r := g.Broker.Approve(ctx, reason)
		if !r.OK {
			return r
		}
		approved = true
		gr, err := g.Grants.Add(s, req.Scope, secrets, d)
		if err != nil {
			return refuse(agentbroker.CodeBusy)
		}
		g.Display.Notify("granted " + req.Scope + " to " + s.Ident() + " until " + gr.ExpiresAt.Format("15:04"))
		return agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true}
	})
	if !resp.OK {
		return resp
	}
	return g.status(s, agentbroker.StateGranted)
}

func scopeText(scope string) string {
	switch scope {
	case ScopeNames:
		return "see that these secret names exist"
	case ScopeRun:
		return "ask to run commands with these secrets; each run still needs Touch ID"
	case ScopeRequest:
		return "ask you to store values under these names; you type each value"
	case ScopeSetup:
		return "propose an EnvBank device setup; the plan still needs Touch ID"
	case ScopeRelay:
		return "request cross-device secret relays"
	}
	return scope
}

// grantReason is the Touch ID text. The authoritative terms come first, in
// full: the action and scope, the secrets, the duration and expiry, then the
// agent kind, session fingerprint and workspace. The agent-influenced label
// comes last, without quote characters, and is the only part ever clipped.
// It reports false if the authoritative part does not fit.
func grantReason(s Session, scope string, secrets []string, d time.Duration, expires time.Time) (string, bool) {
	var what string
	switch scope {
	case ScopeSetup:
		what = "permission to propose an EnvBank device setup"
	case ScopeRelay:
		what = "permission to request secret relays"
	default:
		what = scope + " access to " + strings.Join(secrets, ", ")
	}
	auth := fmt.Sprintf("grant %s for %s (until %s) to %s", what, humanDuration(d), expires.Format("15:04"), s.Ident())
	return approval.WithLabel(auth, s.DisplayLabel())
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h, m := int(d/time.Hour), int((d%time.Hour)/time.Minute)
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%d h %d min", h, m)
	case h > 0:
		return fmt.Sprintf("%d h", h)
	default:
		return fmt.Sprintf("%d min", m)
	}
}
