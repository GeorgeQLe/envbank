package agentbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/setup"
)

// MCP tool names. None returns a value; there is no get/set/raw tool.
const (
	ToolNames   = "envbank_secret_names"
	ToolRequest = "envbank_secret_request"
	ToolRun     = "envbank_secret_run"
	// Device setup (names avoid the workflow tool envbank_setup_plan).
	ToolSetupPlan  = "envbank_device_setup_plan"
	ToolSetupApply = "envbank_device_setup_apply"
)

// MCPExtension forwards the agent tools to an owner-run broker over the
// development Unix socket. It holds no vault access itself. It reaches only
// brokers started with --legacy-socket (development only, unqualified):
// authorized agents use the desktop host's tools instead.
type MCPExtension struct {
	Socket string
}

// Tools implements mcpserver.Extension.
func (MCPExtension) Tools() []mcpserver.ToolDefinition {
	str := map[string]any{"type": "string"}
	strs := map[string]any{"type": "array", "items": str}
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	}
	return []mcpserver.ToolDefinition{
		{Name: ToolNames, Description: "List the NAMES of secrets in the owner's EnvBank vault. Never returns values.", Schema: obj(map[string]any{})},
		{Name: ToolRequest, Description: "Ask the owner to store a secret under NAME. The owner types the value into the EnvBank broker terminal; you receive only 'stored' or 'denied', never the value. Explain why in `reason`.",
			Schema: obj(map[string]any{"name": str, "reason": str}, "name", "reason")},
		{Name: ToolRun, Description: "Run a command with the named secrets set as environment variables. The broker (not you) spawns it after the owner approves this exact command with Touch ID (absolute working directory required; no shell -c / inline interpreter code). Set `always` to ask for approval of this exact command until the broker locks (fixed programs only). stdout/stderr come back with secret values redacted. Use this instead of reading secrets.",
			Schema: obj(map[string]any{"secrets": strs, "argv": strs, "dir": str, "always": map[string]any{"type": "boolean"}, "timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": int(Limits.MaxTimeout.Seconds())}}, "secrets", "argv", "dir")},
		{Name: ToolSetupPlan, Description: "Validate a proposed EnvBank device setup (sync mode, vault/backup directories, identity path) against this machine's real volumes. Read-only: changes nothing.", Schema: setupSchema(obj)},
		{Name: ToolSetupApply, Description: "Ask the owner-held broker (setup mode) to apply a device setup. The broker re-plans it, shows it to the owner, and the owner types every passphrase there; you receive only the outcome and completed step ids.", Schema: setupSchema(obj)},
	}
}

// Call implements mcpserver.Extension. Errors are fixed codes only.
func (e MCPExtension) Call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	var req Request
	switch name {
	case ToolNames:
		req.Op = OpNames
		if !emptyObject(raw) {
			return nil, errors.New(CodeInvalidRequest)
		}
	case ToolRequest:
		var args struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		}
		if !strictDecode(raw, &args) {
			return nil, errors.New(CodeInvalidRequest)
		}
		req = Request{Op: OpRequest, Name: args.Name, Reason: args.Reason}
	case ToolRun:
		var args struct {
			Secrets        []string `json:"secrets"`
			Argv           []string `json:"argv"`
			Dir            string   `json:"dir"`
			TimeoutSeconds int      `json:"timeout_seconds"`
			Always         bool     `json:"always"`
		}
		if !strictDecode(raw, &args) {
			return nil, errors.New(CodeInvalidRequest)
		}
		req = Request{Op: OpRun, Secrets: args.Secrets, Argv: args.Argv, Dir: args.Dir, TimeoutSeconds: args.TimeoutSeconds, Always: args.Always}
	case ToolSetupPlan, ToolSetupApply:
		var args setup.Request
		if !strictDecode(raw, &args) {
			return nil, errors.New(CodeInvalidRequest)
		}
		plan, err := setup.PlanFor(args, setup.SystemInspector{})
		if err != nil {
			var r setup.Refusal
			if errors.As(err, &r) {
				return map[string]any{"ok": false, "refusal": r.Reason}, nil
			}
			return nil, errors.New(CodeInvalidRequest)
		}
		if name == ToolSetupPlan {
			return plan, nil
		}
		req = Request{Op: OpSetup, Setup: raw}
	default:
		return nil, errors.New("unknown tool")
	}
	resp, err := Call(ctx, e.Socket, req)
	if err != nil {
		return nil, errors.New(CodeBrokerDown + ": no development-socket broker (the owner must start `envbank agent-broker --legacy-socket`; authorized agents use the desktop host's EnvBank tools)")
	}
	return resp, nil
}

func setupSchema(obj func(map[string]any, ...string) map[string]any) map[string]any {
	str := map[string]any{"type": "string"}
	return obj(map[string]any{
		"sync":       map[string]any{"type": "string", "enum": []string{setup.SyncLocalServer, setup.SyncHosted, setup.SyncLocalOnly}},
		"server_url": str, "listen": str, "cloudflare_access": map[string]any{"type": "boolean"}, "vault_name": str, "device_name": str, "config_path": str, "vault_dir": str, "backup_dir": str,
	}, "sync", "vault_name", "device_name", "config_path", "backup_dir")
}

func strictDecode(raw json.RawMessage, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return false
	}
	return errors.Is(dec.Decode(&struct{}{}), io.EOF)
}

func emptyObject(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && len(m) == 0
}
