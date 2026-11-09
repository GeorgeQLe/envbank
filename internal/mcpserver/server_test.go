package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type capabilityBackend struct{ fail bool }

func (backend capabilityBackend) Call(_ context.Context, name string, _ Request) (Result, error) {
	if backend.fail {
		return Result{}, errors.New("untrusted-provider-response")
	}
	if name != "envbank_capabilities" {
		return Result{}, errors.New("unexpected operation")
	}
	return Result{Capability: "vercel:deployment=unavailable"}, nil
}

func TestCapabilitiesComeFromConfiguredBackend(t *testing.T) {
	result, err := (Server{Backend: capabilityBackend{}}).Call(context.Background(), "envbank_capabilities", json.RawMessage(`{}`))
	if err != nil || result.Capability != "vercel:deployment=unavailable" {
		t.Fatalf("capability result: %+v, %v", result, err)
	}
	result, err = (Server{Backend: capabilityBackend{fail: true}}).Call(context.Background(), "envbank_capabilities", json.RawMessage(`{}`))
	if err != nil || result.BlockerCode != "WORKFLOW_FAILED" || result.Capability != "" {
		t.Fatal("backend failure did not return a bounded blocker")
	}
}

func TestToolSurfaceIsWorkflowOnly(t *testing.T) {
	tools := strings.Join(Tools(), ",")
	for _, name := range []string{"envbank_capabilities", "envbank_workflow_start", "envbank_rotation_run", "envbank_policy_status"} {
		if !strings.Contains(tools, name) {
			t.Fatalf("missing %s", name)
		}
	}
	for _, prohibited := range []string{"get_secret", "set_secret", "raw"} {
		if strings.Contains(tools, prohibited) {
			t.Fatalf("prohibited tool %s", prohibited)
		}
	}
}

func TestCallRejectsSecretShapedArgumentsWithoutEcho(t *testing.T) {
	const sentinel = "unique-secret-sentinel"
	_, err := (Server{}).Call(context.Background(), "envbank_workflow_start", json.RawMessage(`{"bundle":"x","secret":"`+sentinel+`"}`))
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error=%v", err)
	}
}

func TestServeListsToolsAndReturnsNoSecrets(t *testing.T) {
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"envbank_capabilities\",\"arguments\":{}}}\n")
	var output strings.Builder
	if err := (Server{}).Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "workflow=unavailable") || !strings.Contains(output.String(), "WORKFLOW_BACKEND_UNAVAILABLE") || strings.Contains(output.String(), "=automatic") || strings.Contains(output.String(), "whsec_") {
		t.Fatalf("output=%s", output.String())
	}
}
