package agentbroker

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
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
	vault    Vault // nil in setup mode (no vault on this device yet)
	setup    Setup
	relay    Relay // nil when cross-device relay is unavailable
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

// Setup applies an agent-proposed setup request with the owner (setup mode).
// It re-plans from the request itself, confirms with the owner, collects
// owner secrets on the owner surface, and returns the new, unlocked vault.
type Setup interface {
	Apply(ctx context.Context, req json.RawMessage) (Vault, []string, error)
}

// Options configure a broker.
type Options struct {
	// Vault is nil to start in setup mode (then Setup is required).
	Vault Vault
	Setup Setup
	// Relay enables OpRelayRequest; the Prompter must implement RelayPrompter.
	Relay    Relay
	Prompter Prompter
	Runner   Runner
	Path     string
	BaseEnv  []string
}

// New returns a broker. Every dependency is required.
func New(o Options) (*Broker, error) {
	if (o.Vault == nil && o.Setup == nil) || o.Prompter == nil || o.Runner == nil {
		return nil, errors.New("agentbroker: a vault (or setup), prompter and runner are required")
	}
	return &Broker{
		vault: o.Vault, setup: o.Setup, relay: o.Relay, prompter: o.Prompter, runner: o.Runner, path: o.Path, baseEnv: append([]string(nil), o.BaseEnv...),
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
		return b.ingest(ctx, req)
	case OpRun:
		return b.run(ctx, req)
	case OpRelayRequest:
		return b.relayRequest(ctx, req)
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
	exists, err := b.currentVault().Exists(ctx, req.Name)
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
		if err := b.currentVault().Store(context.WithoutCancel(ctx), req.Name, string(value)); err != nil {
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
	if req.Name != "" || req.Reason != "" || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 || len(req.Setup) == 0 {
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

// RelayPeer is another enrolled, active device of the vault.
type RelayPeer struct {
	ID          string
	Name        string // server-supplied; prompters must sanitize
	Fingerprint string
}

// RelayPrompt is what the owner sees about a relay request. No values.
type RelayPrompt struct {
	Name     string
	Reason   string // agent-supplied; sanitize before display
	Replaces bool
	Sender   RelayPeer
	SAS      string
	Expires  time.Time
}

// ErrRelayExpired is returned by RelaySession.Wait when the request expired.
var ErrRelayExpired = errors.New("relay request expired")

// Relay creates cross-device relay requests for this broker's device.
type Relay interface {
	Peers(ctx context.Context) ([]RelayPeer, error)
	Begin(ctx context.Context, sender RelayPeer, name, reason string) (RelaySession, error)
}

// RelaySession is one outstanding request. Wait returns the verified,
// decrypted value (the caller wipes it), ErrRelayExpired, or another error.
type RelaySession interface {
	SAS() string
	Expires() time.Time
	Wait(ctx context.Context) ([]byte, error)
	Cancel()
}

// RelayPrompter is the owner-channel part of the relay flow.
type RelayPrompter interface {
	// ChooseRelaySender lets the owner approve the request by picking the
	// sending device (index into peers), or decline (ok=false).
	ChooseRelaySender(ctx context.Context, p RelayPrompt, peers []RelayPeer) (index int, ok bool, err error)
	// ShowRelayCode shows the SAS the sending device must display.
	ShowRelayCode(p RelayPrompt)
	// ConfirmRelay asks the owner to store the received value.
	ConfirmRelay(ctx context.Context, p RelayPrompt) (bool, error)
}

func (b *Broker) relayRequest(ctx context.Context, req Request) Response {
	if !ValidName(req.Name) || len(req.Secrets) != 0 || len(req.Argv) != 0 || req.Dir != "" || req.TimeoutSeconds != 0 ||
		len(req.Reason) > Limits.ReasonBytes || !utf8.ValidString(req.Reason) || len(req.Setup) != 0 {
		return refuse(CodeInvalidRequest)
	}
	owner, ok := b.prompter.(RelayPrompter)
	if b.relay == nil || !ok {
		return refuse(CodeRelayDisabled)
	}
	exists, err := b.currentVault().Exists(ctx, req.Name)
	if err != nil {
		return refuse(CodeVaultFailed)
	}
	denied := Response{V: ProtocolVersion, OK: true, State: StateDenied}
	return b.withPrompt(ctx, func() Response {
		peers, err := b.relay.Peers(ctx)
		if err != nil {
			return refuse(CodeVaultFailed)
		}
		prompt := RelayPrompt{Name: req.Name, Reason: req.Reason, Replaces: exists}
		if len(peers) == 0 {
			b.prompter.Notify("relay request for " + req.Name + " refused: no other enrolled device in this vault")
			return denied
		}
		index, ok, err := owner.ChooseRelaySender(ctx, prompt, peers)
		if err != nil || !ok || index < 0 || index >= len(peers) || ctx.Err() != nil {
			return denied
		}
		prompt.Sender = peers[index]
		session, err := b.relay.Begin(ctx, prompt.Sender, req.Name, req.Reason)
		if err != nil {
			b.prompter.Notify("relay request could not be created; nothing was sent")
			return refuse(CodeRelayFailed)
		}
		prompt.SAS, prompt.Expires = session.SAS(), session.Expires()
		owner.ShowRelayCode(prompt)
		value, err := session.Wait(ctx)
		defer wipe(value)
		switch {
		case ctx.Err() != nil:
			session.Cancel()
			return denied
		case errors.Is(err, ErrRelayExpired):
			b.prompter.Notify("relay request for " + req.Name + " expired; nothing stored")
			return Response{V: ProtocolVersion, OK: true, State: StateExpired}
		case err != nil:
			session.Cancel()
			b.prompter.Notify("relay envelope rejected (verification failed); nothing stored")
			return denied
		}
		if len(value) < Limits.MinValueBytes || len(value) > Limits.MaxValueBytes {
			b.prompter.Notify("value rejected: length must be 8 bytes to 64 KiB; nothing stored")
			return denied
		}
		confirmed, err := owner.ConfirmRelay(ctx, prompt)
		if err != nil || !confirmed || ctx.Err() != nil {
			return denied
		}
		if err := b.currentVault().Store(context.WithoutCancel(ctx), req.Name, string(value)); err != nil {
			b.prompter.Notify("store failed; nothing was returned to the agent")
			return refuse(CodeVaultFailed)
		}
		b.prompter.Notify("stored " + req.Name + " (relayed from " + prompt.Sender.Name + ")")
		return Response{V: ProtocolVersion, OK: true, State: StateStored}
	})
}
