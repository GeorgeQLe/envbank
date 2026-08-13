package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

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
	if !strings.Contains(output.String(), "stripe:webhook-signing-secret=automatic") || strings.Contains(output.String(), "whsec_") {
		t.Fatalf("output=%s", output.String())
	}
}
