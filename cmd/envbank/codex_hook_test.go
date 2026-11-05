package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/pkg/codexhook"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

func TestCodexHookEntrypointFailsClosedAndInstallsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gate")
	pre := []byte(`{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"synthetic"}}`)

	// Uninitialized / missing / malformed arguments: refusal, not a CLI error.
	for _, args := range [][]string{
		{"pre-tool-use", "--gate-dir", dir},
		{"pre-tool-use"},
		{"pre-tool-use", "--gate-dir"},
		{"pre-tool-use", "--gate-dir", dir, "extra"},
		{"pre-tool-use", "--unknown-flag"},
	} {
		var out bytes.Buffer
		if err := runCodexHook(args, bytes.NewReader(pre), &out); err != nil {
			t.Fatalf("%v returned a CLI error instead of a refusal", args)
		}
		if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
			t.Fatalf("%v did not refuse", args)
		}
	}

	var initOut bytes.Buffer
	if err := runCodexHook([]string{"init-gate", "--gate-dir", dir}, nil, &initOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(initOut.String(), "READY") || !strings.Contains(initOut.String(), "No Codex hook was installed") {
		t.Fatal("init-gate did not report its bounded effect")
	}
	var out bytes.Buffer
	if err := runCodexHook([]string{"pre-tool-use", "--gate-dir", dir}, bytes.NewReader(pre), &out); err != nil || out.Len() != 0 {
		t.Fatal("initialized ready gate did not express no opinion")
	}

	// A running authority with an active phase is observed through the same latch.
	g, err := protectedfill.OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := runCodexHook([]string{"init-gate", "--gate-dir", dir}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("second authority accepted")
	}

	var caps bytes.Buffer
	if err := runCodexHook([]string{"capabilities"}, nil, &caps); err != nil {
		t.Fatal(err)
	}
	var c codexhook.Capabilities
	dec := json.NewDecoder(&caps)
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || c.CredentialRelease != "refused" || c.GlobalCaptureBarrier || c.InstalledRuntimeQualified {
		t.Fatal("capabilities overstate coverage")
	}
	if runCodexHook([]string{"capabilities", "--qualified"}, nil, &bytes.Buffer{}) == nil || runCodexHook([]string{"enable"}, nil, &bytes.Buffer{}) == nil || runCodexHook(nil, nil, &bytes.Buffer{}) == nil {
		t.Fatal("unsupported subcommand accepted")
	}
}
