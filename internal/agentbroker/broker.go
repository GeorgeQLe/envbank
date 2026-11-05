package agentbroker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// Vault is the owner-unlocked store. Implementations never log values.
type Vault interface {
	Names(ctx context.Context) ([]string, error)
	// Values returns exactly the named values, or an error if any is missing.
	Values(ctx context.Context, names []string) (map[string]string, error)
	Exists(ctx context.Context, name string) (bool, error)
	Store(ctx context.Context, name, value string) error
}

// ErrMissing is returned by Vault.Values when a named secret does not exist.
var ErrMissing = errors.New("secret not found")

// Ingest describes a value the agent asked the owner to enter.
type Ingest struct {
	Name     string
	Reason   string // agent-supplied; the prompter must sanitize before display
	Replaces bool
}

// Prompter is the owner's display and secret-entry channel (the broker
// terminal, with secret entry optionally routed to a verified desktop host).
// It approves nothing: every approval goes to the Approver. Calls are
// serialized by the broker; implementations need not be concurrency-safe.
type Prompter interface {
	// ShowRun displays a run request in full for reference while the owner
	// decides with Touch ID. It reads no input.
	ShowRun(cmd Command, who string, always bool)
	// ReadSecret returns the entered value, or ok=false when the owner declined.
	ReadSecret(ctx context.Context, req Ingest) (value []byte, ok bool, err error)
	// Notify shows a one-line status (no values) in the owner terminal.
	Notify(line string)
}

// Caller identifies who a request is for. The authorization layer builds it
// from a verified host session and an active grant; the development socket
// uses LegacyCaller.
type Caller struct {
	// Who is an owner-visible, already-bounded description for prompts.
	Who string
	// Scope namespaces "always" approvals (a grant id): they end with it.
	Scope string
	// Valid, when set, is re-checked after every approval and before acting,
	// so a revoked or expired grant stops a request in flight.
	Valid func() bool
}

// LegacyCaller is the unauthenticated development socket's caller.
var LegacyCaller = Caller{Who: "an unauthenticated local client (development socket)", Scope: "legacy-socket"}

func (c Caller) valid() bool { return c.Valid == nil || c.Valid() }

type callerKey struct{}

// CallerFrom returns the caller a request is being handled for (for owner
// prompts in the setup applier).
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// Runner executes an approved command with exactly the given environment.
type Runner interface {
	Run(ctx context.Context, cmd Command, env []string) RunResult
}

// RunResult is raw (unredacted) output; the broker redacts before returning it.
type RunResult struct {
	ExitCode  int
	TimedOut  bool
	Started   bool
	Stdout    []byte
	Stderr    []byte
	StdoutCut bool
	StderrCut bool
}

// Broker serves agent requests. Zero values are not usable; use New.
type Broker struct {
	vault    Vault // nil in setup mode (no vault on this device yet)
	setup    Setup
	prompter Prompter
	approver approval.Approver
	runner   Runner
	path     string   // broker's own PATH for resolution
	baseEnv  []string // minimal non-secret environment for children

	prompt chan struct{} // the owner channel: one holder at a time
	queued chan struct{}
	runs   chan struct{}

	mu     sync.Mutex
	always map[string]bool
	closed bool
}

// Setup applies an agent-proposed setup request with the owner (setup mode).
// It re-plans from the request itself, confirms with the owner, collects
// owner secrets on the owner surface, and returns the new, unlocked vault.
type Setup interface {
	Apply(ctx context.Context, req json.RawMessage) (Vault, []string, error)
}

// Options configure a broker.
type Options struct {
	// Vault is nil to start in setup mode (then Setup is required).
	Vault    Vault
	Setup    Setup
	Prompter Prompter
	// Approver decides every approval (Touch ID in production).
	Approver approval.Approver
	Runner   Runner
	Path     string
	BaseEnv  []string
}

// New returns a broker. Every dependency is required.
func New(o Options) (*Broker, error) {
	if (o.Vault == nil && o.Setup == nil) || o.Prompter == nil || o.Runner == nil || o.Approver == nil {
		return nil, errors.New("agentbroker: a vault (or setup), prompter, approver and runner are required")
	}
	return &Broker{
		vault: o.Vault, setup: o.Setup, prompter: o.Prompter, approver: o.Approver, runner: o.Runner, path: o.Path, baseEnv: append([]string(nil), o.BaseEnv...),
		prompt: make(chan struct{}, 1), queued: make(chan struct{}, Limits.QueuedPrompts), runs: make(chan struct{}, Limits.ConcurrentRuns), always: map[string]bool{},
	}, nil
}

// Close refuses all later requests and forgets "always" approvals.
func (b *Broker) Close() {
	b.mu.Lock()
	b.closed = true
	b.always = map[string]bool{}
	b.mu.Unlock()
}

func refuse(code string) Response { return Response{V: ProtocolVersion, Code: code} }

// ForgetAlways drops every "always" approval made under scope (a grant that
// was revoked or expired).
func (b *Broker) ForgetAlways(scope string) {
	prefix := scope + "\x00"
	b.mu.Lock()
	for k := range b.always {
		if strings.HasPrefix(k, prefix) {
			delete(b.always, k)
		}
	}
	b.mu.Unlock()
}

// Approve asks the owner (through the Approver) and maps the outcome to a
// response: ok, DENIED_BY_OWNER or APPROVAL_UNAVAILABLE. Callers hold the
// owner channel (WithOwnerPrompt).
func (b *Broker) Approve(ctx context.Context, reason string) Response {
	if !b.approver.Available() {
		b.prompter.Notify("Touch ID is unavailable on this Mac: approval refused (nothing typed here can approve)")
		return refuse(CodeApprovalUnavailable)
	}
	b.prompter.Notify("waiting for Touch ID (typing in this terminal approves nothing)")
	switch b.approver.Approve(ctx, reason) {
	case approval.Approved:
		if ctx.Err() != nil {
			return refuse(CodeDenied)
		}
		return Response{V: ProtocolVersion, OK: true}
	case approval.Unavailable:
		b.prompter.Notify("Touch ID is unavailable: approval refused")
		return refuse(CodeApprovalUnavailable)
	default:
		b.prompter.Notify("not approved")
		return refuse(CodeDenied)
	}
}

// Handle processes one request for the development socket. It never returns
// a secret value.
func (b *Broker) Handle(ctx context.Context, req Request) Response {
	return b.HandleFor(ctx, LegacyCaller, req)
}

// HandleFor processes one request for caller, which the authorization layer
// has already checked against an active grant. It never returns a value.
func (b *Broker) HandleFor(ctx context.Context, caller Caller, req Request) Response {
	ctx = context.WithValue(ctx, callerKey{}, caller)
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return refuse(CodeBrokerClosed)
	}
	if req.V != ProtocolVersion {
		return refuse(CodeInvalidRequest)
	}
	if req.Op == OpSetup {
		return b.applySetup(ctx, req)
	}
	if b.currentVault() == nil {
		return refuse(CodeNotSetUp)
	}
	switch req.Op {
	case OpNames:
		if req.Name != "" || req.Reason != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 {
			return refuse(CodeInvalidRequest)
		}
		names, err := b.currentVault().Names(ctx)
		if err != nil {
			return refuse(CodeVaultFailed)
		}
		return Response{V: ProtocolVersion, OK: true, Names: names}
	case OpRequest:
		return b.ingest(ctx, caller, req)
	case OpRun:
		return b.run(ctx, caller, req)
	default:
		return refuse(CodeInvalidRequest)
	}
}

// WithOwnerPrompt serializes the owner channel (prompts, Touch ID and secret
// entry); a bounded queue waits, the rest are busy.
func (b *Broker) WithOwnerPrompt(ctx context.Context, fn func() Response) Response {
	return b.withPrompt(ctx, fn)
}

func (b *Broker) withPrompt(ctx context.Context, fn func() Response) Response {
	select {
	case b.queued <- struct{}{}:
	default:
		return refuse(CodeBusy)
	}
	defer func() { <-b.queued }()
	// Waiting is bounded by the request's own context (the host gives up on
	// an agent request after 150 s), so a queued request never hangs.
	select {
	case b.prompt <- struct{}{}:
	case <-ctx.Done():
		return refuse(CodeDenied)
	}
	defer func() { <-b.prompt }()
	if ctx.Err() != nil {
		return refuse(CodeDenied) // the agent went away while queued: never prompt for it
	}
	return fn()
}

func (b *Broker) ingest(ctx context.Context, caller Caller, req Request) Response {
	if !ValidName(req.Name) || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || req.Always ||
		len(req.Reason) > Limits.ReasonBytes || !utf8.ValidString(req.Reason) {
		return refuse(CodeInvalidRequest)
	}
	exists, err := b.currentVault().Exists(ctx, req.Name)
	if err != nil {
		return refuse(CodeVaultFailed)
	}
	return b.withPrompt(ctx, func() Response {
		if !caller.valid() {
			return refuse(CodeNotAuthorized)
		}
		if exists {
			// Replacing a value is an approval: Touch ID with the exact action.
			b.prompter.Notify(req.Name + " already exists; " + caller.Who + " asked to replace it (reason: " + Sanitize(req.Reason, Limits.ReasonBytes) + ")")
			reason := approval.Reason("replace the existing EnvBank secret %s for %s", req.Name, caller.Who)
			if r := b.Approve(ctx, reason); !r.OK {
				if r.Code == CodeApprovalUnavailable {
					return r
				}
				return Response{V: ProtocolVersion, OK: true, State: StateDenied}
			}
			if !caller.valid() {
				return refuse(CodeNotAuthorized)
			}
		}
		value, ok, err := b.prompter.ReadSecret(ctx, Ingest{Name: req.Name, Reason: req.Reason, Replaces: exists})
		defer wipe(value)
		if err != nil || !ok || ctx.Err() != nil { // never act on a request the agent cancelled
			return Response{V: ProtocolVersion, OK: true, State: StateDenied}
		}
		if !caller.valid() {
			return refuse(CodeNotAuthorized)
		}
		if len(value) < Limits.MinValueBytes || len(value) > Limits.MaxValueBytes {
			b.prompter.Notify("value rejected: length must be 8 bytes to 64 KiB; nothing stored")
			return Response{V: ProtocolVersion, OK: true, State: StateDenied}
		}
		if err := b.currentVault().Store(context.WithoutCancel(ctx), req.Name, string(value)); err != nil {
			b.prompter.Notify("store failed; nothing was returned to the agent")
			return refuse(CodeVaultFailed)
		}
		b.prompter.Notify("stored " + req.Name)
		return Response{V: ProtocolVersion, OK: true, State: StateStored}
	})
}

func (b *Broker) run(ctx context.Context, caller Caller, req Request) Response {
	if req.Name != "" || req.Reason != "" || req.TimeoutSeconds < 0 {
		return refuse(CodeInvalidRequest)
	}
	cmd, err := ResolveCommand(req.Argv, req.Dir, req.Secrets, b.path)
	if err != nil {
		return refuse(CodeCommandRefused)
	}
	timeout := Limits.DefaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = min(Limits.MaxTimeout, secondsDuration(req.TimeoutSeconds))
	}
	// Existence and redactability are checked before bothering the owner.
	values, err := b.currentVault().Values(ctx, cmd.Secrets)
	if errors.Is(err, ErrMissing) {
		return refuse(CodeUnknownSecret)
	}
	if err != nil {
		return refuse(CodeVaultFailed)
	}
	for _, v := range values {
		if len(v) < Limits.MinValueBytes {
			return refuse(CodeValueTooShort)
		}
	}
	key := caller.Scope + "\x00" + cmd.ApprovalKey()
	b.mu.Lock()
	approved := b.always[key]
	b.mu.Unlock()
	if !approved {
		always := req.Always && cmd.AlwaysAllowed
		resp := b.withPrompt(ctx, func() Response {
			if !caller.valid() {
				return refuse(CodeNotAuthorized)
			}
			if req.Always && !cmd.AlwaysAllowed {
				b.prompter.Notify("always is not available for commands that run project code; asking for this run only")
			}
			b.prompter.ShowRun(cmd, caller.Who, always)
			r := b.Approve(ctx, runReason(cmd, caller.Who, always))
			if !r.OK {
				return r
			}
			if always {
				b.mu.Lock()
				if !b.closed && caller.valid() {
					b.always[key] = true
				}
				b.mu.Unlock()
			}
			return r
		})
		if !resp.OK {
			return resp
		}
	}
	if !caller.valid() {
		return refuse(CodeNotAuthorized)
	}
	select {
	case b.runs <- struct{}{}:
	default:
		return refuse(CodeBusy)
	}
	defer func() { <-b.runs }()
	// The command and every bound file must still match what was approved.
	if err := Verify(cmd, req.Argv, req.Dir, req.Secrets, b.path); err != nil {
		b.prompter.Notify("refused: command or a file it uses changed after approval")
		return refuse(CodeCommandRefused)
	}
	// Fresh values at execution time, in case of a rotation since approval.
	values, err = b.currentVault().Values(ctx, cmd.Secrets)
	if err != nil {
		return refuse(CodeVaultFailed)
	}
	for _, v := range values {
		if len(v) < Limits.MinValueBytes {
			return refuse(CodeValueTooShort)
		}
	}
	env := append([]string(nil), b.baseEnv...)
	for _, name := range cmd.Secrets {
		env = append(env, name+"="+values[name])
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := b.runner.Run(runCtx, cmd, env)
	if !result.Started {
		return refuse(CodeStartFailed)
	}
	redactor := NewRedactor(values)
	stdout, n1 := redactor.Redact(result.Stdout, result.StdoutCut)
	stderr, n2 := redactor.Redact(result.Stderr, result.StderrCut)
	truncated := result.StdoutCut || result.StderrCut
	stdout, t1 := clip(stdout)
	stderr, t2 := clip(stderr)
	exit := result.ExitCode
	b.prompter.Notify("ran " + cmd.Executable + " (" + itoa(len(cmd.Secrets)) + " secret(s), exit " + itoa(exit) + ")")
	return Response{
		V: ProtocolVersion, OK: true, ExitCode: &exit, TimedOut: result.TimedOut,
		Stdout: string(stdout), Stderr: string(stderr), Truncated: truncated || t1 || t2, Redactions: n1 + n2,
	}
}

func (b *Broker) currentVault() Vault {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.vault
}

// applySetup runs only in setup mode, one at a time, through the owner channel.
func (b *Broker) applySetup(ctx context.Context, req Request) Response {
	if req.Name != "" || req.Reason != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || req.Always || len(req.Setup) == 0 {
		return refuse(CodeInvalidRequest)
	}
	if b.currentVault() != nil || b.setup == nil {
		return refuse(CodeAlreadySetUp)
	}
	return b.withPrompt(ctx, func() Response {
		if b.currentVault() != nil {
			return refuse(CodeAlreadySetUp)
		}
		vault, done, err := b.setup.Apply(ctx, req.Setup)
		if vault != nil {
			b.mu.Lock()
			if !b.closed {
				b.vault = vault
			}
			b.mu.Unlock()
		}
		if err != nil {
			var r interface{ SetupRefusal() string }
			code := CodeSetupFailed
			if errors.As(err, &r) {
				code = r.SetupRefusal()
			}
			return Response{V: ProtocolVersion, Code: code, Steps: done}
		}
		b.prompter.Notify("setup complete; vault unlocked for agent use")
		return Response{V: ProtocolVersion, OK: true, State: StateApplied, Steps: done}
	})
}

// runReason is the Touch ID text for a run: the exact action, bounded. The
// broker terminal shows every argument and hash in full.
func runReason(cmd Command, who string, always bool) string {
	mode := "once"
	if always {
		mode = "always (this exact command, until the grant ends)"
	}
	args := make([]string, 0, len(cmd.Args))
	for _, a := range cmd.Args {
		args = append(args, quoteArg(a))
	}
	line := strings.TrimSpace(quoteArg(cmd.Executable) + " " + strings.Join(args, " "))
	const room = 260
	if len(line) > room {
		cut := room
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		line = line[:cut] + "… (full command in the broker terminal)"
	}
	return approval.Reason("run %s with %s in %s for %s, %s (exe sha256 %.12s)",
		line, strings.Join(cmd.Secrets, ", "), quoteArg(cmd.Dir), who, mode, cmd.ExecutableSHA256)
}

func clip(b []byte) ([]byte, bool) {
	if len(b) <= Limits.ReturnBytes {
		return b, false
	}
	return b[:Limits.ReturnBytes], true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
