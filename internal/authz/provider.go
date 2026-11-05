package authz

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
)

// ownerKey is the session tuple as the provider journal's owner key.
func ownerKey(s Session) string {
	return s.ID + "\x00" + s.Workspace + "\x00" + s.AgentKind
}

// providerAction checks the session's provider grant first (NOT_AUTHORIZED,
// never a prompt), then validates and plans the action, then asks the owner
// with Touch ID showing the exact plan. There is no "always": every call is
// its own approval. Only an approved action starts.
func (g *Gate) providerAction(ctx context.Context, s Session, req Request) agentbroker.Response {
	if req.Name != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || req.Always ||
		len(req.Setup) != 0 || req.Scope != "" || req.DurationS != 0 || len(req.Actions) != 0 || req.OperationID != "" ||
		len(req.Reason) > agentbroker.Limits.ReasonBytes || req.Action == "" || len(req.Params) == 0 {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	gr, ok := g.Grants.CoveringAction(s, req.Action)
	if !ok {
		return refuse(agentbroker.CodeNotAuthorized)
	}
	if !g.Provider.Available() {
		return refuse(provideraction.CodeUnavailable)
	}
	prep, code, detail := g.Provider.PrepareDetail(ctx, req.Action, req.Params)
	if code != "" {
		resp := refuse(code)
		if detail != nil {
			// Value-free IDs for cleanup (STRIPE_ORPHAN_ENDPOINT).
			if raw, err := json.Marshal(detail); err == nil && string(raw) != "{}" {
				resp.Result = raw
			}
		}
		return resp
	}
	defer prep.Release()
	reason, code := providerReason(s, prep.Summary())
	if code != "" {
		return refuse(code) // the plan cannot be shown in full: never prompt clipped
	}
	caller := g.caller(s, gr)
	var opID string
	resp := g.Broker.WithOwnerPrompt(ctx, func() agentbroker.Response {
		if !caller.Valid() {
			return refuse(agentbroker.CodeNotAuthorized)
		}
		lines := []string{
			"from: " + s.Ident(),
			"session label (set by the agent's host session): " + s.DisplayLabel(),
			"action: " + prep.Action(),
			"plan: " + prep.Summary(),
		}
		if req.Reason != "" {
			lines = append(lines, "agent's reason: "+agentbroker.Sanitize(req.Reason, agentbroker.Limits.ReasonBytes))
		}
		g.Display.ShowPlan("EnvBank provider action", lines)
		if r := g.Broker.Approve(ctx, reason); !r.OK {
			return r
		}
		if !caller.Valid() {
			return refuse(agentbroker.CodeNotAuthorized)
		}
		id, code := g.Provider.Start(prep, ownerKey(s), caller.Scope, caller.Valid)
		if code != "" {
			return refuse(code)
		}
		opID = id
		g.Display.Notify("started provider action " + prep.Action() + " for " + s.Ident())
		return agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true}
	})
	if !resp.OK {
		return resp
	}
	return agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true, OperationID: opID, Action: prep.Action(), State: provideraction.StateStarted}
}

// providerReason is the Touch ID text: the plan in full, then the session
// (authoritative), then the label last, ASCII-only inside fixed delimiters
// so it cannot read as plan text. The plan is never clipped: one that does
// not fit with room for a minimal label is refused (PLAN_TOO_LONG). The
// label gets the rest of the budget and is clipped to it, so the agent's
// label can never make an approval fail.
func providerReason(s Session, summary string) (string, string) {
	authoritative := "perform a provider action: " + summary + ", for " + s.Ident()
	if approval.Clean(authoritative, len(authoritative)) != authoritative {
		return "", agentbroker.CodeInvalidRequest
	}
	if len(authoritative) > MaxProviderPlanBytes {
		return "", provideraction.CodePlanTooLong
	}
	reason := authoritative
	if label := asciiLabel(s.Label, approval.MaxReasonBytes-len(authoritative)-len(labelOpen)-len(labelClose)); label != "" {
		reason += labelOpen + label + labelClose
	}
	if len(reason) > approval.MaxReasonBytes {
		return "", provideraction.CodePlanTooLong // unreachable: the label is clipped to fit
	}
	return reason, ""
}

const (
	labelOpen  = `; [agent label: "`
	labelClose = `"]`
	// maxLabelRunes bounds the label shown in a provider approval.
	maxLabelRunes = 80
	// minLabelRunes is the label room every plan leaves: at least this
	// much of the label, then "...", is always shown.
	minLabelRunes = 8
	// MaxProviderPlanBytes bounds "perform a provider action: <plan>, for
	// <session>": the prompt limit less the label's minimum room.
	MaxProviderPlanBytes = approval.MaxReasonBytes - len(labelOpen) - len(labelClose) - minLabelRunes - len("...")
)

// asciiLabel renders the agent-influenced label for a provider approval in
// at most room bytes (never less than minLabelRunes plus "..."): cleaned to
// one line without quote-like characters (approval.Plain), then every rune
// that is not printable ASCII, and the delimiters '"', '[' and ']', become
// '?'. A label longer than maxLabelRunes or than room is clipped with
// "..." (ASCII): the label is never authoritative.
func asciiLabel(label string, room int) string {
	limit := maxLabelRunes
	if room-len("...") < limit {
		limit = room - len("...")
	}
	if limit < minLabelRunes {
		limit = minLabelRunes
	}
	clean := approval.Plain(label, 1<<10)
	var b strings.Builder
	n := 0
	for _, r := range clean {
		if n == limit {
			b.WriteString("...")
			break
		}
		switch {
		case r < 0x20 || r > 0x7e || r == '"' || r == '[' || r == ']' || r == '\\':
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// providerStatus answers only the session that started the operation. An
// unknown operation and another session's look the same.
func (g *Gate) providerStatus(s Session, req Request) agentbroker.Response {
	if req.Name != "" || req.Reason != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || req.Always ||
		len(req.Setup) != 0 || req.Scope != "" || req.DurationS != 0 || len(req.Actions) != 0 || req.Action != "" || len(req.Params) != 0 ||
		!provideraction.ValidOperationID(req.OperationID) {
		return refuse(agentbroker.CodeInvalidRequest)
	}
	if g.Provider == nil {
		return refuse(provideraction.CodeUnknownOperation)
	}
	st, ok := g.Provider.Status(ownerKey(s), req.OperationID)
	if !ok {
		return refuse(provideraction.CodeUnknownOperation)
	}
	resp := agentbroker.Response{V: agentbroker.ProtocolVersion, OK: true, OperationID: st.OperationID, Action: st.Action, State: st.State,
		Step: st.Step, Code: st.Code, Steps: st.Steps}
	if st.Result != nil {
		raw, err := json.Marshal(st.Result)
		if err == nil && !strings.EqualFold(string(raw), "{}") {
			resp.Result = raw
		}
	}
	return resp
}
