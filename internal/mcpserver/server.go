// Package mcpserver exposes only workflow-oriented, secret-free operations.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

var toolNames = []string{"envbank_capabilities", "envbank_setup_plan", "envbank_workflow_start", "envbank_workflow_resume", "envbank_workflow_status", "envbank_rotation_due", "envbank_rotation_run", "envbank_operation_evidence", "envbank_policy_status"}

// ToolDefinition permits an isolated executable to extend the protocol without
// adding test controls to the production binary.
type ToolDefinition struct {
	Name        string
	Description string
	Schema      map[string]any
}

type Extension interface {
	Tools() []ToolDefinition
	Call(context.Context, string, json.RawMessage) (any, error)
}

type Result struct {
	PlanID      string           `json:"plan_id,omitempty"`
	OperationID string           `json:"operation_id,omitempty"`
	Stage       string           `json:"stage,omitempty"`
	Provider    string           `json:"provider,omitempty"`
	ResourceIDs []string         `json:"resource_ids,omitempty"`
	Capability  string           `json:"capability,omitempty"`
	Health      []HealthEvidence `json:"health,omitempty"`
	BlockerCode string           `json:"blocker_code,omitempty"`
}
type HealthEvidence struct {
	CheckID          string `json:"check_id"`
	SuccessfulChecks int    `json:"successful_checks"`
	Healthy          bool   `json:"healthy"`
}
type Request struct {
	VaultID        string `json:"vault_id,omitempty"`
	Bundle         string `json:"bundle,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Environment    string `json:"environment,omitempty"`
	Provider       string `json:"provider,omitempty"`
	PlanID         string `json:"plan_id,omitempty"`
	OperationID    string `json:"operation_id,omitempty"`
	PolicyID       string `json:"policy_id,omitempty"`
}

type Backend interface {
	Call(context.Context, string, Request) (Result, error)
}
type Server struct {
	Backend   Backend
	Extension Extension
}

func Tools() []string { return append([]string(nil), toolNames...) }

func (server Server) Call(ctx context.Context, name string, raw json.RawMessage) (Result, error) {
	if !knownTool(name) {
		return Result{}, errors.New("unknown tool")
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) != 0 {
		if err := decoder.Decode(&request); err != nil {
			return Result{}, errors.New("invalid tool arguments")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Result{}, errors.New("invalid tool arguments")
		}
	}
	if name == "envbank_capabilities" {
		return Result{Capability: "stripe:webhook-signing-secret=automatic,clerk:application-key=interactive,vercel:deployment=automatic,railway:deployment=automatic"}, nil
	}
	if server.Backend == nil {
		return Result{BlockerCode: "WORKFLOW_BACKEND_UNAVAILABLE"}, nil
	}
	result, err := server.Backend.Call(ctx, name, request)
	if err != nil {
		return Result{BlockerCode: "WORKFLOW_FAILED"}, nil
	}
	return result, nil
}

func productionTool(name string) ToolDefinition {
	stringField := func() map[string]any { return map[string]any{"type": "string"} }
	fields := map[string]map[string]any{
		"envbank_capabilities":       {},
		"envbank_setup_plan":         {"vault_id": stringField(), "bundle": stringField(), "manifest_digest": stringField(), "environment": stringField()},
		"envbank_workflow_start":     {"vault_id": stringField(), "bundle": stringField(), "manifest_digest": stringField(), "environment": stringField(), "provider": stringField(), "plan_id": stringField(), "policy_id": stringField()},
		"envbank_workflow_resume":    {"operation_id": stringField()},
		"envbank_workflow_status":    {"operation_id": stringField()},
		"envbank_rotation_due":       {"vault_id": stringField(), "bundle": stringField()},
		"envbank_rotation_run":       {"operation_id": stringField(), "provider": stringField()},
		"envbank_operation_evidence": {"operation_id": stringField()},
		"envbank_policy_status":      {"policy_id": stringField()},
	}
	properties := map[string]any{}
	for key, schema := range fields[name] {
		properties[key] = schema
	}
	return ToolDefinition{Name: name, Description: "EnvBank secret-free workflow operation", Schema: map[string]any{"type": "object", "properties": properties, "additionalProperties": false}}
}

func knownTool(name string) bool {
	for _, candidate := range toolNames {
		if candidate == name {
			return true
		}
	}
	return false
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve handles newline-delimited JSON-RPC over local stdio. It never logs a
// frame, and malformed arguments are replaced with bounded fixed errors.
func (server Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		var request rpcRequest
		if json.Unmarshal(scanner.Bytes(), &request) != nil {
			if err := encoder.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}); err != nil {
				return err
			}
			continue
		}
		response := rpcResponse{JSONRPC: "2.0", ID: request.ID}
		if len(request.ID) == 0 && request.Method == "notifications/initialized" {
			continue
		}
		switch request.Method {
		case "initialize":
			response.Result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "envbank", "version": "1"}}
		case "tools/list":
			tools := make([]map[string]any, 0, len(toolNames)+5)
			for _, name := range toolNames {
				definition := productionTool(name)
				tools = append(tools, map[string]any{"name": definition.Name, "description": definition.Description, "inputSchema": definition.Schema})
			}
			if server.Extension != nil {
				for _, definition := range server.Extension.Tools() {
					tools = append(tools, map[string]any{"name": definition.Name, "description": definition.Description, "inputSchema": definition.Schema})
				}
			}
			response.Result = map[string]any{"tools": tools}
		case "tools/call":
			var call struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if json.Unmarshal(request.Params, &call) != nil {
				response.Error = &rpcError{Code: -32602, Message: "invalid params"}
				break
			}
			var result any
			var err error
			if knownTool(call.Name) {
				result, err = server.Call(ctx, call.Name, call.Arguments)
			} else if server.Extension != nil {
				result, err = server.Extension.Call(ctx, call.Name, call.Arguments)
			} else {
				err = errors.New("unknown tool")
			}
			if err != nil {
				response.Error = &rpcError{Code: -32602, Message: err.Error()}
			} else {
				response.Result = map[string]any{"content": []map[string]string{{"type": "text", "text": mustJSON(result)}}}
			}
		default:
			response.Error = &rpcError{Code: -32601, Message: "method not found"}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func mustJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }
