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
	prep, code := g.Provider.Prepare(ctx, req.Action, req.Params)
	if code != "" {
		return refuse(code)
	}
	defer prep.Release()
	reason, fits := providerReason(s, prep.Summary())
	if !fits {
		return refuse(agentbroker.CodeInvalidRequest) // the plan cannot be shown in full: never prompt clipped
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
// (authoritative), then the label last.
func providerReason(s Session, summary string) (string, bool) {
	return approval.WithLabel("perform a provider action: "+summary+", for "+s.Ident(), s.DisplayLabel())
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
