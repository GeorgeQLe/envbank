package codexhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/nativehost"
	"github.com/GeorgeQLe/envbank/pkg/computeruse"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

// All values are synthetic random; failures never print them.
func sentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("random source unavailable")
	}
	return "SYNTHETIC_" + hex.EncodeToString(b)
}

func openGate(t *testing.T) (*protectedfill.Gate, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gate")
	g, err := protectedfill.OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, dir
}

func payload(event Event, tool string, extra map[string]any) []byte {
	m := map[string]any{"session_id": "s", "hook_event_name": string(event), "tool_name": tool, "cwd": "/tmp"}
	for k, v := range extra {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return raw
}

func run(t *testing.T, event Event, dir string, input []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Evaluate(event, dir, bytes.NewReader(input), &out); err != nil {
		t.Fatal("decision write failed")
	}
	return out.Bytes()
}

// Strict: exactly the supported fields and values, one JSON document.
func assertDenied(t *testing.T, out []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var v preToolUseOutput
	if err := dec.Decode(&v); err != nil || dec.More() {
		t.Fatal("PreToolUse refusal is not a single strict JSON decision")
	}
	if v.HookSpecificOutput != (preToolUseDecision{HookEventName: "PreToolUse", PermissionDecision: "deny", PermissionDecisionReason: DenyReason}) {
		t.Fatal("PreToolUse refusal has unexpected content")
	}
}

func assertWithheld(t *testing.T, out []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var v postToolUseOutput
	if err := dec.Decode(&v); err != nil || dec.More() || v != (postToolUseOutput{Decision: "block", Reason: WithheldReason}) {
		t.Fatal("PostToolUse refusal is not the fixed strict decision")
	}
}

func assertNoLeak(t *testing.T, out []byte, secret string) {
	t.Helper()
	if bytes.Contains(out, []byte(secret)) || bytes.Contains(out, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) || bytes.Contains(out, []byte(hex.EncodeToString([]byte(secret)))) {
		t.Fatal("hook output echoed tool input or response material")
	}
}

// Not a tool-name list: arbitrary, unknown, MCP, shell, write_stdin-like and computer-use names behave identically.
var toolNames = []string{"shell", "exec_command", "write_stdin", "apply_patch", "computer_use", "mcp__envbank__status", "browser.screenshot", "unlisted_future_tool"}

func TestReadyGateExpressesNoOpinionForAnyTool(t *testing.T) {
	_, dir := openGate(t)
	for _, tool := range toolNames {
		if out := run(t, PreToolUse, dir, payload(PreToolUse, tool, map[string]any{"tool_input": map[string]any{"x": 1}})); len(out) != 0 {
			t.Fatalf("ready gate produced a PreToolUse decision for %q", tool)
		}
		if out := run(t, PostToolUse, dir, payload(PostToolUse, tool, map[string]any{"tool_response": "ok"})); len(out) != 0 {
			t.Fatalf("ready gate produced a PostToolUse decision for %q", tool)
		}
	}
}

type blockingDriver struct {
	entered, release chan struct{}
	destroyErr       error
	orphanErr        error
}

func (d *blockingDriver) Validate(context.Context, protectedfill.Target) error { return nil }
func (d *blockingDriver) FillAndSubmit(ctx context.Context, _ protectedfill.Target, _ []byte) (bool, error) {
	if d.entered != nil {
		close(d.entered)
		<-d.release
	}
	return true, nil
}
func (d *blockingDriver) Destroy(context.Context, protectedfill.Target) error { return d.destroyErr }
func (d *blockingDriver) DestroyOrphans(context.Context) error                { return d.orphanErr }

func target() protectedfill.Target {
	return protectedfill.Target{Record: "TOKEN", Context: "owned_ctx", Document: "doc_1", Field: "field_1", Submit: "submit_1", Origin: "https://example.com"}
}

// The hook reads the SAME latch the in-process authority writes before value
// retrieval; it never holds or creates separate state.
func TestInFlightProtectedOperationDeniesAllToolsAcrossParallelSessions(t *testing.T) {
	g, dir := openGate(t)
	secret := sentinel(t)
	d := &blockingDriver{entered: make(chan struct{}), release: make(chan struct{})}
	c := &protectedfill.Coordinator{Gate: g, Driver: d}
	done := make(chan protectedfill.Receipt, 1)
	go func() {
		done <- c.Run(context.Background(), target(), func() ([]byte, error) { return []byte(secret), nil })
	}()
	<-d.entered
	if protectedfill.ProbeGate(dir) != protectedfill.GateBlocked {
		t.Fatal("probe did not observe the active protected phase")
	}
	var wg sync.WaitGroup
	errs := make(chan string, 3*len(toolNames)*4)
	for session := 0; session < 4; session++ {
		for _, tool := range toolNames {
			wg.Add(1)
			go func(tool string) {
				defer wg.Done()
				var pre, post bytes.Buffer
				_ = Evaluate(PreToolUse, dir, bytes.NewReader(payload(PreToolUse, tool, map[string]any{"tool_input": secret})), &pre)
				_ = Evaluate(PostToolUse, dir, bytes.NewReader(payload(PostToolUse, tool, map[string]any{"tool_response": secret})), &post)
				if !strings.Contains(pre.String(), `"permissionDecision":"deny"`) {
					errs <- "pre"
				}
				if !strings.Contains(post.String(), `"decision":"block"`) {
					errs <- "post"
				}
				if strings.Contains(pre.String()+post.String(), secret) {
					errs <- "leak"
				}
			}(tool)
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("parallel session was not refused (%s)", e)
	}
	assertDenied(t, run(t, PreToolUse, dir, payload(PreToolUse, "shell", nil)))
	assertWithheld(t, run(t, PostToolUse, dir, payload(PostToolUse, "shell", nil)))
	close(d.release)
	if r := <-done; r.Status != "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED" {
		t.Fatal("synthetic protected operation did not complete")
	}
	if out := run(t, PreToolUse, dir, payload(PreToolUse, "shell", nil)); len(out) != 0 {
		t.Fatal("verified context destruction did not resume")
	}
}

func TestFailedCleanupLatchSurvivesAuthorityExitUntilTrustedRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gate")
	g, err := protectedfill.OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := &blockingDriver{destroyErr: errors.New("synthetic cleanup failure")}
	if r := (&protectedfill.Coordinator{Gate: g, Driver: d}).Run(context.Background(), target(), func() ([]byte, error) { return []byte("synthetic"), nil }); r.Status != "RECOVERY_REQUIRED" {
		t.Fatal("failed cleanup did not latch")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	// No authority running: the durable latch alone still refuses.
	assertDenied(t, run(t, PreToolUse, dir, payload(PreToolUse, "computer_use", nil)))
	assertWithheld(t, run(t, PostToolUse, dir, payload(PostToolUse, "computer_use", nil)))
	next, err := protectedfill.OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	d.orphanErr = errors.New("unproven destruction")
	c := &protectedfill.Coordinator{Gate: next, Driver: d}
	if c.Recover(context.Background()) == nil {
		t.Fatal("unproven destruction recovered")
	}
	assertDenied(t, run(t, PreToolUse, dir, payload(PreToolUse, "shell", nil)))
	d.orphanErr = nil
	if c.Recover(context.Background()) != nil {
		t.Fatal("trusted recovery failed")
	}
	if out := run(t, PreToolUse, dir, payload(PreToolUse, "shell", nil)); len(out) != 0 {
		t.Fatal("recovered gate still refused")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

func TestMalformedInputAndUnavailableAuthorityRefuse(t *testing.T) {
	_, dir := openGate(t)
	oversize := append(payload(PreToolUse, "shell", nil)[:1], bytes.Repeat([]byte(" "), MaxInputBytes)...)
	oversize = append(oversize, payload(PreToolUse, "shell", nil)[1:]...)
	for name, input := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte(`[{"hook_event_name":"PreToolUse","tool_name":"shell"}]`), "truncated": []byte(`{"hook_event_name":"PreToolUse"`),
		"wrong-event": payload(PostToolUse, "shell", nil), "missing-tool": []byte(`{"hook_event_name":"PreToolUse"}`), "empty-tool": payload(PreToolUse, "", nil),
		"non-string-tool": []byte(`{"hook_event_name":"PreToolUse","tool_name":7}`), "trailing": append(payload(PreToolUse, "shell", nil), []byte(` {}`)...),
		"oversize": oversize, "long-tool": payload(PreToolUse, strings.Repeat("x", 257), nil),
	} {
		t.Run(name, func(t *testing.T) { assertDenied(t, run(t, PreToolUse, dir, input)) })
	}
	var out bytes.Buffer
	if Evaluate(PreToolUse, dir, failingReader{}, &out) != nil {
		t.Fatal("write failed")
	}
	assertDenied(t, out.Bytes())
	out.Reset()
	if Evaluate(Event("SessionStart"), dir, bytes.NewReader(payload(PreToolUse, "shell", nil)), &out) != nil {
		t.Fatal("write failed")
	}
	assertDenied(t, out.Bytes())
	assertWithheld(t, run(t, PostToolUse, dir, []byte("{")))

	base := t.TempDir()
	open := filepath.Join(base, "open")
	uninitialized := filepath.Join(base, "uninitialized")
	link := filepath.Join(base, "link")
	if os.Mkdir(open, 0755) != nil || os.Mkdir(uninitialized, 0700) != nil || os.Symlink(dir, link) != nil {
		t.Fatal("fixture setup failed")
	}
	for name, gate := range map[string]string{
		"none": "", "relative": "gate", "unclean": dir + "/../gate", "missing": filepath.Join(base, "missing"), "world-readable": open,
		"uninitialized": uninitialized, "symlink": link,
	} {
		if protectedfill.ProbeGate(gate) != protectedfill.GateUnknown {
			t.Fatalf("probe accepted %s gate", name)
		}
		assertDenied(t, run(t, PreToolUse, gate, payload(PreToolUse, "shell", nil)))
		assertWithheld(t, run(t, PostToolUse, gate, payload(PostToolUse, "shell", nil)))
	}
}

func TestSlowInputRefusesBeforeRuntimeTimeout(t *testing.T) {
	_, dir := openGate(t)
	reader, writer := io.Pipe()
	defer writer.Close()
	start := time.Now()
	var out bytes.Buffer
	if Evaluate(PreToolUse, dir, reader, &out) != nil {
		t.Fatal("write failed")
	}
	if elapsed := time.Since(start); elapsed > ReadTimeout+time.Second {
		t.Fatal("slow input was not bounded")
	}
	assertDenied(t, out.Bytes())
}

func TestToolPayloadsAndQualificationClaimsCannotChangeDecisionOrLeak(t *testing.T) {
	g, dir := openGate(t)
	secret := sentinel(t)
	claims := map[string]any{
		"tool_input":                 map[string]any{"command": secret, "ack": "PROTECTION_PAUSED", "envbank_qualified": true},
		"tool_response":              secret,
		"envbank_host_qualified":     true,
		"plugin_trusted":             true,
		"extension_ack":              "observation_barrier_installed",
		"permission_mode":            "bypassPermissions",
		"dangerously_bypass_hooks":   true,
		"installed_runtime_verified": true,
	}
	before := Describe()
	// Ready: claims are ignored (no opinion), and nothing is echoed.
	assertNoLeak(t, run(t, PreToolUse, dir, payload(PreToolUse, "shell", claims)), secret)
	// Latched: claims cannot downgrade the refusal.
	d := &blockingDriver{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		(&protectedfill.Coordinator{Gate: g, Driver: d}).Run(context.Background(), target(), func() ([]byte, error) { return []byte("synthetic"), nil })
		close(done)
	}()
	<-d.entered
	pre := run(t, PreToolUse, dir, payload(PreToolUse, "shell", claims))
	post := run(t, PostToolUse, dir, payload(PostToolUse, "shell", claims))
	assertDenied(t, pre)
	assertWithheld(t, post)
	assertNoLeak(t, pre, secret)
	assertNoLeak(t, post, secret)
	close(d.release)
	<-done
	after := Describe()
	raw1, _ := json.Marshal(before)
	raw2, _ := json.Marshal(after)
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("capabilities changed at runtime")
	}
	if after.CredentialRelease != "refused" || after.GlobalCaptureBarrier || after.InstalledRuntimeQualified || after.InFlightWorkDrain ||
		after.WriteStdinPreToolUseCovered || after.HostedToolsCovered || after.PostToolUseUndoesSideEffects || after.MissingOrUntrustedHookRuns ||
		!after.RuntimeMayFailOpenOnHookError || !after.SpecializedPathsMayOptOut {
		t.Fatal("capabilities overstate coverage")
	}
	// The documented PostToolUse decision:block (not continue:false) rejects a
	// code-mode nested promise; the capability must match the output emitted.
	if !after.PostToolUseBlockRejectsNestedPromise || !bytes.Contains(post, []byte(`"decision":"block"`)) || bytes.Contains(post, []byte(`"continue"`)) {
		t.Fatal("nested-promise capability does not match the emitted PostToolUse decision")
	}
}

type countingKeychain struct{ reads int }

func (k *countingKeychain) Get(string, string, string) ([]byte, error) {
	k.reads++
	return nil, errors.New("unavailable")
}

// A Codex-observed host shares the Gate but has no qualified Driver: the
// native-host embedding refuses release before touching config or Keychain.
func TestCodexObservedHostCannotReleaseCredentials(t *testing.T) {
	g, dir := openGate(t)
	store := &countingKeychain{}
	host := computeruse.NewNativeHost(filepath.Join(t.TempDir(), "must-not-read.json"), store, &protectedfill.Coordinator{Gate: g})
	status, _ := host.Handle(nativehost.Request{Version: 1, ID: "status", Action: "protected_status"})
	if m, ok := status.Result.(map[string]any); !ok || m["available"] != false {
		t.Fatal("hook-observed host reported protection available")
	}
	tg := target()
	r, _ := host.Handle(nativehost.Request{Version: 1, ID: "execute", Action: "protected_execute", Name: tg.Record, Origin: tg.Origin, Target: &tg})
	if receipt, ok := r.Result.(protectedfill.Receipt); !ok || receipt.Status != "HOST_PROTECTION_UNAVAILABLE" || store.reads != 0 {
		t.Fatal("credential release was not refused before Keychain access")
	}
	for _, action := range []string{"get_for_fill", "generate_password", "allow_origin", "deny_origin"} {
		if resp, _ := host.Handle(nativehost.Request{Version: 1, ID: "a", Action: action, Name: "TOKEN", Origin: "https://example.com"}); resp.OK {
			t.Fatalf("%s accepted", action)
		}
	}
	if store.reads != 0 || protectedfill.ProbeGate(dir) != protectedfill.GateReady {
		t.Fatal("refusal touched Keychain or changed gate state")
	}
}
