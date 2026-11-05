package agentbroker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// randomValue is a process-local sentinel; it must never appear in any response.
func randomValue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sk_test_" + base64.RawURLEncoding.EncodeToString(b)
}

type fakeVault struct {
	mu     sync.Mutex
	values map[string]string
	stored int
	fail   bool
}

func (v *fakeVault) Names(context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail {
		return nil, errors.New("vault down " + "with a detail that must not leak")
	}
	var names []string
	for n := range v.values {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
func (v *fakeVault) Values(_ context.Context, names []string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	for _, n := range names {
		val, ok := v.values[n]
		if !ok {
			return nil, ErrMissing
		}
		out[n] = val
	}
	return out, nil
}
func (v *fakeVault) Exists(_ context.Context, name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.values[name]
	return ok, nil
}
func (v *fakeVault) Store(_ context.Context, name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[name] = value
	v.stored++
	return nil
}

// fakePrompter is the terminal display and, for tests, the Touch ID approver.
type fakePrompter struct {
	mu          sync.Mutex
	decision    approval.Outcome
	unavailable bool
	reasons     []string
	secret      []byte
	ok          bool
	runs        []Command
	ingests     []Ingest
	block       chan struct{}
	notes       []string
}

func (p *fakePrompter) ShowRun(cmd Command, _ string, _ bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.runs = append(p.runs, cmd)
}
func (p *fakePrompter) Available() bool { return !p.unavailable }
func (p *fakePrompter) Approve(ctx context.Context, reason string) approval.Outcome {
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return approval.Denied
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reasons = append(p.reasons, reason)
	return p.decision
}
func (p *fakePrompter) ReadSecret(_ context.Context, req Ingest) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ingests = append(p.ingests, req)
	return append([]byte(nil), p.secret...), p.ok, nil
}
func (p *fakePrompter) Notify(line string) {
	p.mu.Lock()
	p.notes = append(p.notes, line)
	p.mu.Unlock()
}
func (p *fakePrompter) prompts() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.runs) }

// script writes an executable test script into a fresh directory.
func script(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	path = filepath.Join(dir, "tool.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func newBroker(t *testing.T, vault Vault, p Prompter) *Broker {
	t.Helper()
	b, err := New(Options{Vault: vault, Prompter: p, Approver: p.(approval.Approver), Runner: ExecRunner{}, Path: "/usr/bin:/bin", BaseEnv: []string{"PATH=/usr/bin:/bin", "TERM=dumb"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noValue(t *testing.T, value string, v any) {
	t.Helper()
	raw, _ := json.Marshal(v)
	for _, enc := range []string{value, base64.StdEncoding.EncodeToString([]byte(value)), hex.EncodeToString([]byte(value))} {
		if strings.Contains(string(raw), enc) {
			t.Fatalf("secret value (or encoding) escaped in %s", raw)
		}
	}
}

func TestRedactorCoversEncodingsAndCutPrefixes(t *testing.T) {
	v := randomValue(t) + "/+=&?"
	r := NewRedactor(map[string]string{"TOKEN": v})
	quoted, _ := json.Marshal(v)
	for _, enc := range []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
		hex.EncodeToString([]byte(v)), strings.ToUpper(hex.EncodeToString([]byte(v))), url.QueryEscape(v), url.PathEscape(v), strings.Trim(string(quoted), `"`)} {
		out, n := r.Redact([]byte("before "+enc+" after"), false)
		if n == 0 || strings.Contains(string(out), enc) || !strings.Contains(string(out), "[REDACTED:TOKEN]") {
			t.Fatalf("encoding not redacted: %q", out)
		}
	}
	// Capture limit split the value: its prefix must not survive.
	out, n := r.Redact([]byte("log line "+v[:12]), true)
	if n == 0 || strings.Contains(string(out), v[:12]) {
		t.Fatalf("cut prefix leaked: %q", out)
	}
	if out, n := r.Redact([]byte("ordinary output"), false); n != 0 || string(out) != "ordinary output" {
		t.Fatal("ordinary output changed")
	}
}

func TestResolveCommandRefusesArbitraryCodeAndEnvDumpers(t *testing.T) {
	dir, tool := script(t, "exit 0\n")
	path := "/usr/bin:/bin"
	refusedCases := [][]string{
		{"env"}, {"/usr/bin/env", "node", "x.js"}, {"printenv"}, {"sudo", tool}, {"sh", "-c", "echo $X"}, {"/bin/bash", "-lc", "echo"},
		{"zsh", "--command", "x"}, {"python3", "-c", "print(1)"}, {"node", "-e", "1"}, {"node", "--eval=1"}, {"perl", "-E", "say 1"},
		{"ruby", "-e", "1"}, {"osascript", "-e", "x"}, {"awk", "BEGIN{}"}, {"xargs", "echo"},
	}
	checked := 0
	for _, argv := range refusedCases {
		_, err := ResolveCommand(argv, dir, []string{"TOKEN"}, path)
		if err == nil {
			t.Fatalf("approved %v", argv)
		}
		reason, _ := RefusalReason(err)
		if strings.Contains(reason, "not found") {
			continue // interpreter not installed here; the rule itself is checked where it exists
		}
		checked++
		if !strings.Contains(reason, "cannot be approved") {
			t.Fatalf("%v refused for the wrong reason: %q", argv, reason)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d refusal rules exercised", checked)
	}
	for _, bad := range []struct {
		argv    []string
		dir     string
		secrets []string
	}{
		{[]string{tool}, "relative", []string{"TOKEN"}},
		{[]string{tool}, "/nonexistent-dir-xyz", []string{"TOKEN"}},
		{[]string{tool}, dir, nil},
		{[]string{tool}, dir, []string{"bad-name"}},
		{[]string{tool}, dir, []string{"A", "A"}},
		{[]string{"tool.sh"}, dir, []string{"TOKEN"}}, // bare name: PATH only, never "."
		{[]string{"x\x00y"}, dir, []string{"TOKEN"}},
	} {
		if _, err := ResolveCommand(bad.argv, bad.dir, bad.secrets, ".:"+dir+"/.."); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	cmd, err := ResolveCommand([]string{"./tool.sh", "deploy"}, dir, []string{"B", "A"}, path)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Executable != tool || strings.Join(cmd.Secrets, ",") != "A,B" || len(cmd.Warnings) == 0 {
		t.Fatalf("resolved %+v", cmd)
	}
	key := cmd.ApprovalKey()
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	changed, err := ResolveCommand([]string{"./tool.sh", "deploy"}, dir, []string{"A", "B"}, path)
	if err != nil || changed.ApprovalKey() == key {
		t.Fatal("editing the executable must invalidate an always-approval")
	}
	other, _ := ResolveCommand([]string{"./tool.sh", "other"}, dir, []string{"A", "B"}, path)
	if other.ApprovalKey() == changed.ApprovalKey() {
		t.Fatal("different arguments share an approval")
	}
}

func TestRunInjectsOnlyNamedSecretsAndRedactsOutput(t *testing.T) {
	value := randomValue(t)
	other := randomValue(t)
	t.Setenv("AGENT_ONLY", "agent-environment-must-not-pass")
	t.Setenv("ENVBANK_PASSPHRASE", "passphrase-must-not-pass")
	dir, tool := script(t, `echo "raw:$TOKEN"
printf %s "$TOKEN" | base64
printf %s "$TOKEN" | od -An -tx1 | tr -d ' \n'; echo
echo "other:$OTHER agent:$AGENT_ONLY pass:$ENVBANK_PASSPHRASE" >&2
exit 7
`)
	vault := &fakeVault{values: map[string]string{"TOKEN": value, "OTHER": other}}
	p := &fakePrompter{decision: approval.Approved}
	b := newBroker(t, vault, p)
	resp := b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir})
	if !resp.OK || resp.ExitCode == nil || *resp.ExitCode != 7 || p.prompts() != 1 {
		t.Fatalf("resp %+v prompts %d", resp, p.prompts())
	}
	noValue(t, value, resp)
	noValue(t, other, resp)
	if !strings.Contains(resp.Stdout, "raw:[REDACTED:TOKEN]") || resp.Redactions < 3 {
		t.Fatalf("stdout %q redactions %d", resp.Stdout, resp.Redactions)
	}
	if !strings.Contains(resp.Stderr, "other: agent: pass:") {
		t.Fatalf("environment leaked into child: %q", resp.Stderr)
	}
}

func TestApprovalOnceAlwaysDenyAndNoPromptForUnusableRequests(t *testing.T) {
	value := randomValue(t)
	dir, tool := script(t, "echo ok\n")
	vault := &fakeVault{values: map[string]string{"TOKEN": value, "SHORT": "abc"}}
	p := &fakePrompter{decision: approval.Denied}
	b := newBroker(t, vault, p)
	// A fixed system binary outside the working directory may be approved "always".
	run := func(args ...string) Response {
		return b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: append([]string{"/bin/echo"}, args...), Dir: dir, Always: true})
	}
	if r := run(); r.OK || r.Code != CodeDenied {
		t.Fatalf("deny: %+v", r)
	}
	p.decision = approval.Approved
	if r := run(); !r.OK {
		t.Fatalf("always: %+v", r)
	}
	if r := run(); !r.OK || p.prompts() != 2 {
		t.Fatalf("always-approved command prompted again: %d", p.prompts())
	}
	if r := run("different"); !r.OK || p.prompts() != 3 {
		t.Fatal("a different exact command must be approved separately")
	}
	before := p.prompts()
	for _, req := range []Request{
		{V: 1, Op: OpRun, Secrets: []string{"MISSING"}, Argv: []string{tool}, Dir: dir},
		{V: 1, Op: OpRun, Secrets: []string{"SHORT"}, Argv: []string{tool}, Dir: dir},
		{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"sh", "-c", "echo $TOKEN"}, Dir: dir},
		{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir, Name: "x"},
		{V: 2, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir},
		{V: 1, Op: "get", Name: "TOKEN"},
	} {
		if r := b.Handle(context.Background(), req); r.OK {
			t.Fatalf("accepted %+v", req)
		}
	}
	if p.prompts() != before {
		t.Fatal("an unusable request reached the owner")
	}
	b.Close()
	if r := run(); r.OK || r.Code != CodeBrokerClosed {
		t.Fatal("closed broker still runs (or kept always-approvals)")
	}
}

func TestIngestStoresOnlyWhatTheOwnerTypes(t *testing.T) {
	vault := &fakeVault{values: map[string]string{"EXISTING": randomValue(t)}}
	value := randomValue(t)
	p := &fakePrompter{secret: []byte(value), ok: true, decision: approval.Approved}
	b := newBroker(t, vault, p)
	resp := b.Handle(context.Background(), Request{V: 1, Op: OpRequest, Name: "NEW_KEY", Reason: "deploy preview \x1b[2J"})
	if !resp.OK || resp.State != StateStored || vault.values["NEW_KEY"] != value {
		t.Fatalf("resp %+v", resp)
	}
	noValue(t, value, resp)
	if r := b.Handle(context.Background(), Request{V: 1, Op: OpRequest, Name: "EXISTING", Reason: "rotate"}); r.State != StateStored || !p.ingests[1].Replaces {
		t.Fatal("replacement must be flagged to the owner")
	}
	p.ok = false
	if r := b.Handle(context.Background(), Request{V: 1, Op: OpRequest, Name: "DECLINED", Reason: "x"}); r.State != StateDenied {
		t.Fatal("declined ingest stored")
	}
	p.ok, p.secret = true, []byte("short")
	if r := b.Handle(context.Background(), Request{V: 1, Op: OpRequest, Name: "TOO_SHORT", Reason: "x"}); r.State != StateDenied {
		t.Fatal("unredactably short value stored")
	}
	for _, bad := range []Request{
		{V: 1, Op: OpRequest, Name: "bad-name", Reason: "x"},
		{V: 1, Op: OpRequest, Name: "OK", Reason: strings.Repeat("x", Limits.ReasonBytes+1)},
		{V: 1, Op: OpRequest, Name: "OK", Reason: "x", Argv: []string{"/bin/echo"}},
	} {
		if r := b.Handle(context.Background(), bad); r.OK {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if vault.stored != 2 {
		t.Fatalf("stored %d", vault.stored)
	}
	vault.fail = true
	if r := b.Handle(context.Background(), Request{V: 1, Op: OpNames}); r.OK || r.Code != CodeVaultFailed || strings.Contains(r.Code, "detail") {
		t.Fatal("vault failure must be a fixed code")
	}
}

func TestTimeoutKillsTheWholeProcessGroup(t *testing.T) {
	dir, tool := script(t, "sleep 30 &\nsleep 30\n")
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, &fakePrompter{decision: approval.Approved})
	start := time.Now()
	resp := b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir, TimeoutSeconds: 1})
	if !resp.OK || !resp.TimedOut || time.Since(start) > 10*time.Second {
		t.Fatalf("resp %+v after %v", resp, time.Since(start))
	}
}

func TestPromptQueueIsBoundedAndCancelledRequestsNeverPrompt(t *testing.T) {
	dir, tool := script(t, "echo ok\n")
	p := &fakePrompter{decision: approval.Approved, block: make(chan struct{})}
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, p)
	var wg sync.WaitGroup
	results := make(chan Response, 16)
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < Limits.QueuedPrompts+3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- b.Handle(ctx, Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool, string(rune('a' + i))}, Dir: dir})
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	cancel() // every agent hangs up while the owner has not answered
	close(p.block)
	wg.Wait()
	close(results)
	busy := 0
	for r := range results {
		if r.OK {
			t.Fatal("a cancelled request ran")
		}
		if r.Code == CodeBusy {
			busy++
		}
	}
	if busy < 3 || p.prompts() > 1 {
		t.Fatalf("busy %d prompts %d", busy, p.prompts())
	}
}

func TestReviewBypassesAreRefused(t *testing.T) {
	dir, tool := script(t, "exit 0\n")
	path := "/usr/bin:/bin"
	for _, argv := range [][]string{
		{"python3", "-Ic", "x"}, {"python3", "-uc", "x"}, {"perl", "-we", "1"}, {"perl", "-lE", "1"}, {"perl", "-MFoo"}, {"ruby", "-we", "1"},
		{"php", "-nr", "1"}, {"node", "--require=./x.js", "app.js"}, {"node", "--import", "x"},
		{"timeout", "5", "printenv"}, {"nice", "printenv"}, {"time", "printenv"}, {"caffeinate", "-i", "printenv"}, {"busybox", "sh", "-c", "x"},
		{"git", "-c", "alias.x=!printenv", "x"}, {"git", "--config-env=core.pager=X", "log"}, {"vim", "-c", ":!printenv"}, {"jq", "-n", "env.TOKEN"},
		{"find", ".", "-exec", "printenv", ";"}, {"sed", "e"}, {"ssh", "localhost"}, {"open", "-a", "Terminal"},
	} {
		_, err := ResolveCommand(argv, dir, []string{"TOKEN"}, path)
		if err == nil {
			t.Fatalf("approved %v", argv)
		}
	}
	// A shebang interpreter is held to the same rules.
	for _, line := range []string{"#!/usr/bin/env -S bash -c 'printenv'", "#!/bin/sh -c printenv", "#!/usr/bin/env printenv"} {
		bad := filepath.Join(dir, "bad.sh")
		if err := os.WriteFile(bad, []byte(line+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveCommand([]string{bad}, dir, []string{"TOKEN"}, path); err == nil {
			t.Fatalf("approved shebang %q", line)
		}
	}
	// Too long to show the owner in full ⇒ refused, never truncated.
	long := strings.Repeat("a", Limits.ArgBytes)
	if _, err := ResolveCommand([]string{tool, long, long, long}, dir, []string{"TOKEN"}, path); err == nil {
		t.Fatal("over-long command accepted")
	}
}

func TestScriptArgumentsAndInterpretersAreBoundToTheApproval(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	deploy := filepath.Join(dir, "deploy.sh")
	if err := os.WriteFile(deploy, []byte("echo v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, err := ResolveCommand([]string{"/bin/sh", "deploy.sh"}, dir, []string{"TOKEN"}, "/usr/bin:/bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Files) != 1 || cmd.Files[0].Path != deploy || cmd.AlwaysAllowed {
		t.Fatalf("file argument not bound or always offered: %+v", cmd)
	}
	if err := os.WriteFile(deploy, []byte("echo v2 && printenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Verify(cmd, []string{"/bin/sh", "deploy.sh"}, dir, []string{"TOKEN"}, "/usr/bin:/bin") == nil {
		t.Fatal("edited script still matched the approval")
	}
	_, tool := script(t, "echo hi\n")
	sh, err := ResolveCommand([]string{tool}, filepath.Dir(tool), []string{"TOKEN"}, "/usr/bin:/bin")
	if err != nil || sh.Interpreter == "" || sh.InterpreterSHA256 == "" || sh.AlwaysAllowed {
		t.Fatalf("shebang interpreter not bound: %+v %v", sh, err)
	}
}

// swapVault returns a different value on its second fetch (a rotation or edit
// between approval and execution).
type swapVault struct {
	fakeVault
	calls int
	later map[string]string
}

func (v *swapVault) Values(ctx context.Context, names []string) (map[string]string, error) {
	v.calls++
	if v.calls > 1 {
		v.fakeVault.values = v.later
	}
	return v.fakeVault.Values(ctx, names)
}

func TestValuesShortenedOrScriptsEditedAfterApprovalAreRefused(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	v := &swapVault{fakeVault: fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, later: map[string]string{"TOKEN": "abc"}}
	b := newBroker(t, v, &fakePrompter{decision: approval.Approved})
	if r := b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"/bin/echo", "x"}, Dir: dir}); r.OK || r.Code != CodeValueTooShort {
		t.Fatalf("shortened value at execution: %+v", r)
	}
	// Edit the script while the owner is looking at the prompt.
	deploy := filepath.Join(dir, "deploy.sh")
	_ = os.WriteFile(deploy, []byte("echo v1\n"), 0o600)
	edit := &editingPrompter{fakePrompter: fakePrompter{decision: approval.Approved}, edit: func() { _ = os.WriteFile(deploy, []byte("printenv\n"), 0o600) }}
	b2 := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, edit)
	if r := b2.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"/bin/sh", "deploy.sh"}, Dir: dir}); r.OK || r.Code != CodeCommandRefused {
		t.Fatalf("script edited after approval still ran: %+v", r)
	}
}

type editingPrompter struct {
	fakePrompter
	edit func()
}

func (p *editingPrompter) Approve(ctx context.Context, reason string) approval.Outcome {
	p.edit()
	return p.fakePrompter.Approve(ctx, reason)
}

func TestRedactionHandlesMultilineOverlapAndAnyCutFragment(t *testing.T) {
	pem := "-----BEGIN KEY-----\nAAAAsecretLINEoneZZZZ\nBBBBsecretLINEtwoYYYY\n-----END KEY-----\n"
	r := NewRedactor(map[string]string{"PEM": pem})
	for _, out := range []string{strings.ReplaceAll(pem, "\n", "\r\n"), "line: AAAAsecretLINEoneZZZZ\n", base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(pem)))} {
		got, _ := r.Redact([]byte(out), false)
		if strings.Contains(string(got), "secretLINE") || strings.Contains(string(got), base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(pem)))[:20]) {
			t.Fatalf("multi-line form leaked: %q", got)
		}
	}
	a, b := "OVERLAPaaaaaaaaSHARED", "SHAREDbbbbbbbbbbOVERLAP"
	got, _ := NewRedactor(map[string]string{"A": a, "B": b}).Redact([]byte("x"+a[:len(a)-6]+"SHAREDbbbbbbbbbbOVERLAPy"), false)
	if strings.Contains(string(got), "aaaaaaaa") || strings.Contains(string(got), "bbbbbbbb") {
		t.Fatalf("overlapping secrets left fragments: %q", got)
	}
	v := randomValue(t)
	for k := 1; k < 8; k++ {
		got, _ := NewRedactor(map[string]string{"T": v}).Redact([]byte("end:"+v[:k]), true)
		if strings.HasSuffix(string(got), v[:k]) {
			t.Fatalf("%d-byte cut fragment leaked: %q", k, got)
		}
	}
}

func TestCancelledIngestIsNeverStored(t *testing.T) {
	vault := &fakeVault{values: map[string]string{}}
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancellingPrompter{cancel: cancel, value: []byte(randomValue(t))}
	b := newBroker(t, vault, p)
	if r := b.Handle(ctx, Request{V: 1, Op: OpRequest, Name: "LATE", Reason: "x"}); r.State == StateStored || vault.stored != 0 {
		t.Fatalf("cancelled ingest stored: %+v", r)
	}
}

type cancellingPrompter struct {
	fakePrompter
	cancel func()
	value  []byte
}

func (p *cancellingPrompter) ReadSecret(context.Context, Ingest) ([]byte, bool, error) {
	p.cancel() // the agent hangs up while the owner is typing
	return append([]byte(nil), p.value...), true, nil
}

// A command whose full text does not fit the Touch ID prompt is refused with
// a fixed code and the owner is never prompted.
func TestRunTooLongToApproveIsRefusedWithoutPrompting(t *testing.T) {
	dir := t.TempDir()
	p := &fakePrompter{decision: approval.Approved}
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, p)
	resp := b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"/bin/echo", strings.Repeat("pad", 200), "--then-something-else"}, Dir: dir})
	if resp.OK || resp.Code != CodeCommandTooLong {
		t.Fatalf("resp %+v", resp)
	}
	if p.prompts() != 0 || len(p.reasons) != 0 {
		t.Fatal("owner prompted for a command that cannot be shown in full")
	}
	resp = b.Handle(context.Background(), Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{"/bin/echo", "short", "--tail"}, Dir: dir})
	if !resp.OK || len(p.reasons) != 1 || !strings.Contains(p.reasons[0], "/bin/echo with 2 argument(s): short --tail") {
		t.Fatalf("resp %+v reasons %q", resp, p.reasons)
	}
}

// Ending a grant's scope kills its running command's whole process group at
// once, and the run returns no output.
func TestEndScopeKillsRunningCommands(t *testing.T) {
	dir, tool := script(t, "sleep 60 &\necho $! > \"$0.child\"\necho $$ > \"$0.pid\"\necho started\nwait\n")
	b := newBroker(t, &fakeVault{values: map[string]string{"TOKEN": randomValue(t)}}, &fakePrompter{decision: approval.Approved})
	caller := Caller{Who: "test", Scope: "grant:abc"}
	done := make(chan Response, 1)
	start := time.Now()
	go func() {
		done <- b.HandleFor(context.Background(), caller, Request{V: 1, Op: OpRun, Secrets: []string{"TOKEN"}, Argv: []string{tool}, Dir: dir, TimeoutSeconds: 60})
	}()
	pids := waitPids(t, tool+".pid", tool+".child")
	b.EndScope("grant:other") // another grant's end leaves it running
	time.Sleep(100 * time.Millisecond)
	if !alive(pids[0]) {
		t.Fatal("run killed by another scope")
	}
	b.EndScope("grant:abc")
	var resp Response
	select {
	case resp = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run survived the end of its grant")
	}
	if resp.OK || resp.Code != CodeNotAuthorized || resp.Stdout != "" || time.Since(start) > 10*time.Second {
		t.Fatalf("resp %+v", resp)
	}
	assertDead(t, pids...)
}

func waitPids(t *testing.T, files ...string) []int {
	t.Helper()
	var pids []int
	deadline := time.Now().Add(10 * time.Second)
	for _, f := range files {
		for {
			raw, err := os.ReadFile(f)
			if n, perr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && perr == nil && n > 0 {
				pids = append(pids, n)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no pid in %s", f)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return pids
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func assertDead(t *testing.T, pids ...int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for _, pid := range pids {
		for alive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("process %d outlived its grant", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
