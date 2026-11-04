package agentbroker

import (
	"context"
	"errors"
	"sync"
	"unicode/utf8"
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

// Decision is the owner's answer to a run request.
type Decision int

const (
	Deny Decision = iota
	AllowOnce
	AllowAlways
)

// Ingest describes a value the agent asked the owner to enter.
type Ingest struct {
	Name     string
	Reason   string // agent-supplied; the prompter must sanitize before display
	Replaces bool
}

// Prompter is the owner channel (the broker terminal). Calls are serialized by
// the broker; implementations need not be concurrency-safe.
type Prompter interface {
	ApproveRun(ctx context.Context, cmd Command) (Decision, error)
	// ReadSecret returns the entered value, or ok=false when the owner declined.
	ReadSecret(ctx context.Context, req Ingest) (value []byte, ok bool, err error)
	// Notify shows a one-line status (no values) in the owner terminal.
	Notify(line string)
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
	vault    Vault
	prompter Prompter
	runner   Runner
	path     string   // broker's own PATH for resolution
	baseEnv  []string // minimal non-secret environment for children

	promptMu sync.Mutex
	queued   chan struct{}
	runs     chan struct{}

	mu     sync.Mutex
	always map[string]bool
	closed bool
}

// Options configure a broker.
type Options struct {
	Vault    Vault
	Prompter Prompter
	Runner   Runner
	Path     string
	BaseEnv  []string
}

// New returns a broker. Every dependency is required.
func New(o Options) (*Broker, error) {
	if o.Vault == nil || o.Prompter == nil || o.Runner == nil {
		return nil, errors.New("agentbroker: vault, prompter and runner are required")
	}
	return &Broker{
		vault: o.Vault, prompter: o.Prompter, runner: o.Runner, path: o.Path, baseEnv: append([]string(nil), o.BaseEnv...),
		queued: make(chan struct{}, Limits.QueuedPrompts), runs: make(chan struct{}, Limits.ConcurrentRuns), always: map[string]bool{},
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

// Handle processes one request. It never returns a secret value.
func (b *Broker) Handle(ctx context.Context, req Request) Response {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return refuse(CodeBrokerClosed)
	}
	if req.V != ProtocolVersion {
		return refuse(CodeInvalidRequest)
	}
	switch req.Op {
	case OpNames:
		if req.Name != "" || req.Reason != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 {
			return refuse(CodeInvalidRequest)
		}
		names, err := b.vault.Names(ctx)
		if err != nil {
			return refuse(CodeVaultFailed)
		}
		return Response{V: ProtocolVersion, OK: true, Names: names}
	case OpRequest:
		return b.ingest(ctx, req)
	case OpRun:
		return b.run(ctx, req)
	default:
		return refuse(CodeInvalidRequest)
	}
}

// withPrompt serializes the owner channel; a bounded queue waits, the rest are busy.
func (b *Broker) withPrompt(ctx context.Context, fn func() Response) Response {
	select {
	case b.queued <- struct{}{}:
	default:
		return refuse(CodeBusy)
	}
	defer func() { <-b.queued }()
	b.promptMu.Lock()
	defer b.promptMu.Unlock()
	if ctx.Err() != nil {
		return refuse(CodeDenied) // the agent went away while queued: never prompt for it
	}
	return fn()
}

func (b *Broker) ingest(ctx context.Context, req Request) Response {
	if !ValidName(req.Name) || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 ||
		len(req.Reason) > Limits.ReasonBytes || !utf8.ValidString(req.Reason) {
		return refuse(CodeInvalidRequest)
	}
	exists, err := b.vault.Exists(ctx, req.Name)
	if err != nil {
		return refuse(CodeVaultFailed)
	}
	return b.withPrompt(ctx, func() Response {
		value, ok, err := b.prompter.ReadSecret(ctx, Ingest{Name: req.Name, Reason: req.Reason, Replaces: exists})
		defer wipe(value)
		if err != nil || !ok || ctx.Err() != nil { // never act on a request the agent cancelled
			return Response{V: ProtocolVersion, OK: true, State: StateDenied}
		}
		if len(value) < Limits.MinValueBytes || len(value) > Limits.MaxValueBytes {
			b.prompter.Notify("value rejected: length must be 8 bytes to 64 KiB; nothing stored")
			return Response{V: ProtocolVersion, OK: true, State: StateDenied}
		}
		if err := b.vault.Store(context.WithoutCancel(ctx), req.Name, string(value)); err != nil {
			b.prompter.Notify("store failed; nothing was returned to the agent")
			return refuse(CodeVaultFailed)
		}
		b.prompter.Notify("stored " + req.Name)
		return Response{V: ProtocolVersion, OK: true, State: StateStored}
	})
}

func (b *Broker) run(ctx context.Context, req Request) Response {
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
	values, err := b.vault.Values(ctx, cmd.Secrets)
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
	key := cmd.ApprovalKey()
	b.mu.Lock()
	approved := b.always[key]
	b.mu.Unlock()
	if !approved {
		resp := b.withPrompt(ctx, func() Response {
			decision, err := b.prompter.ApproveRun(ctx, cmd)
			if err != nil || decision == Deny || ctx.Err() != nil {
				return refuse(CodeDenied)
			}
			if decision == AllowAlways && !cmd.AlwaysAllowed {
				b.prompter.Notify("approved once (always is not available for commands that run project code)")
				decision = AllowOnce
			}
			if decision == AllowAlways {
				b.mu.Lock()
				if !b.closed {
					b.always[key] = true
				}
				b.mu.Unlock()
			}
			return Response{OK: true}
		})
		if !resp.OK {
			return resp
		}
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
	values, err = b.vault.Values(ctx, cmd.Secrets)
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
