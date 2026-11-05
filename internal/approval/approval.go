// Package approval is the owner's biometric approval for EnvBank agent
// grants and approvals (docs/authorized-agents.md).
//
// Every decision that used to be a typed "y" in the broker terminal (grants,
// run approvals, ingest replacement, setup plans, pairing) goes through an
// Approver. The production Approver is LocalAuthentication (Touch ID): an
// agent with computer use can click and type, but cannot produce the owner's
// fingerprint. Tests inject fakes; there is no production switch that turns
// biometrics off.
package approval

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Outcome of one approval.
type Outcome int

const (
	// Denied covers a cancel, a failed match, a timeout or a cancelled request.
	Denied Outcome = iota
	// Approved means the owner authenticated for exactly this reason.
	Approved
	// Unavailable means no biometry is enrolled or usable: every approval is
	// refused (APPROVAL_UNAVAILABLE); there is no silent fallback.
	Unavailable
)

func (o Outcome) String() string {
	switch o {
	case Approved:
		return "approved"
	case Unavailable:
		return "unavailable"
	default:
		return "denied"
	}
}

// Approver asks the owner to approve one action.
type Approver interface {
	// Available reports whether approvals can be made at all (no prompt).
	Available() bool
	// Approve shows reason and blocks until the owner answers, ctx ends or
	// the approver's own timeout passes. reason must come from Reason.
	Approve(ctx context.Context, reason string) Outcome
}

// MaxReasonBytes bounds a reason string. Callers that cannot describe an
// action within it say where the full details are (the broker terminal).
const MaxReasonBytes = 600

// DefaultTimeout is how long an approval waits for the owner. A request's
// own deadline shortens it (agent requests are answered within 140 s).
const DefaultTimeout = 2 * time.Minute

// MinPromptTime: with less time left than this, no prompt is shown.
const MinPromptTime = 10 * time.Second

// Clean renders untrusted text as one plain line of at most maxRunes runes:
// control, format (including bidi overrides) and other non-printing runes
// become '?', whitespace runs collapse to one space, and clipping is marked
// with an ellipsis.
func Clean(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	pendingSpace := false
	emit := func(r rune) bool {
		if n >= maxRunes {
			b.WriteRune('…')
			return false
		}
		b.WriteRune(r)
		n++
		return true
	}
	for _, r := range s {
		if unicode.IsSpace(r) {
			pendingSpace = n > 0
			continue
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
			r = '?'
		}
		if pendingSpace {
			pendingSpace = false
			if !emit(' ') {
				return b.String()
			}
		}
		if !emit(r) {
			return b.String()
		}
	}
	return b.String()
}

// Reason formats a reason from a verb phrase and pre-cleaned parts and
// bounds the result to MaxReasonBytes (on a rune boundary, with an ellipsis).
// macOS shows it as "<app> is trying to <reason>".
func Reason(format string, args ...any) string {
	s := Clean(fmt.Sprintf(format, args...), MaxReasonBytes)
	if len(s) <= MaxReasonBytes {
		return s
	}
	cut := MaxReasonBytes - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Quote cleans and quotes a short untrusted field for a reason string.
func Quote(s string, maxRunes int) string { return "“" + Clean(s, maxRunes) + "”" }
