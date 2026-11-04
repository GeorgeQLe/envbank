package agentbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
)

// MCP tool names. None returns a value; there is no get/set/raw tool.
const (
	ToolNames   = "envbank_secret_names"
	ToolRequest = "envbank_secret_request"
	ToolRun     = "envbank_secret_run"
)

// MCPExtension forwards the agent tools to an owner-run broker. It holds no
// vault access itself: the MCP process can run inside the agent sandbox.
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
		{Name: ToolRun, Description: "Run a command with the named secrets set as environment variables. The broker (not you) spawns it after the owner approves this exact command (absolute working directory required; no shell -c / inline interpreter code). stdout/stderr come back with secret values redacted. Use this instead of reading secrets.",
			Schema: obj(map[string]any{"secrets": strs, "argv": strs, "dir": str, "timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": int(Limits.MaxTimeout.Seconds())}}, "secrets", "argv", "dir")},
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
		}
		if !strictDecode(raw, &args) {
			return nil, errors.New(CodeInvalidRequest)
		}
		req = Request{Op: OpRun, Secrets: args.Secrets, Argv: args.Argv, Dir: args.Dir, TimeoutSeconds: args.TimeoutSeconds}
	default:
		return nil, errors.New("unknown tool")
	}
	resp, err := Call(ctx, e.Socket, req)
	if err != nil {
		return nil, errors.New(CodeBrokerDown + ": start `envbank agent-broker` in your own terminal")
	}
	return resp, nil
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
