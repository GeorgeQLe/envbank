// Package agentbroker lets coding agents ingest and use EnvBank secrets without
// ever receiving a secret value.
//
// Custody is split: the OWNER starts `envbank agent-broker` in their own
// terminal and unlocks the vault there. Agents only reach the broker over a
// private Unix socket (directly or through `envbank mcp serve`). The broker:
//
//   - lists secret NAMES only;
//   - ingests a value only when the owner types it into the broker terminal
//     (no echo); the agent learns the name and "stored" or "denied";
//   - runs an owner-approved exact command with only the named secrets in its
//     environment, spawned by the broker (not the agent), and returns its
//     output with every injected value and its common encodings redacted.
//
// There is deliberately no operation that returns a value. Residual risk: an
// approved command that executes agent-editable code (npm scripts, repository
// scripts) can still exfiltrate the values it receives; the approval prompt
// says so. A placeholder egress proxy is the planned stronger mode for HTTP
// API keys.
package agentbroker

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the socket protocol version (one JSON request line, one
// JSON response line, per connection).
const ProtocolVersion = 1

// Limits bound every request so a misbehaving agent cannot exhaust the broker
// or flood the owner's terminal.
var Limits = struct {
	RequestBytes   int
	Argv           int
	ArgBytes       int
	Secrets        int
	ReasonBytes    int
	CaptureBytes   int
	ReturnBytes    int
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MinValueBytes  int
	MaxValueBytes  int
	ConcurrentRuns int
	QueuedPrompts  int
}{
	RequestBytes:   64 << 10,
	Argv:           64,
	ArgBytes:       4096,
	Secrets:        16,
	ReasonBytes:    300,
	CaptureBytes:   4 << 20,
	ReturnBytes:    256 << 10,
	DefaultTimeout: 2 * time.Minute,
	MaxTimeout:     30 * time.Minute,
	MinValueBytes:  8,
	MaxValueBytes:  64 << 10,
	ConcurrentRuns: 4,
	QueuedPrompts:  4,
}

// Operations.
const (
	OpNames   = "names"
	OpRequest = "request"
	OpRun     = "run"
	OpSetup   = "setup"
)

// Request is the only message an agent can send.
type Request struct {
	V              int      `json:"v"`
	Op             string   `json:"op"`
	Name           string   `json:"name,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Secrets        []string `json:"secrets,omitempty"`
	Argv           []string `json:"argv,omitempty"`
	Dir            string   `json:"dir,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	// Always asks the owner to approve this exact command for the rest of the
	// grant (offered only for fixed programs). The Touch ID reason says so.
	Always bool `json:"always,omitempty"`
	// Setup is a setup.Request (setup mode only). Re-planned by the broker.
	Setup json.RawMessage `json:"setup,omitempty"`
}

// Response never carries a secret value. Code is a fixed string on refusal.
type Response struct {
	V          int      `json:"v"`
	OK         bool     `json:"ok"`
	Code       string   `json:"code,omitempty"`
	Names      []string `json:"names,omitempty"`
	State      string   `json:"state,omitempty"`
	ExitCode   *int     `json:"exit_code,omitempty"`
	TimedOut   bool     `json:"timed_out,omitempty"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Redactions int      `json:"redactions,omitempty"`
	Steps      []string `json:"steps,omitempty"`
	// Grants lists the calling session's active grants (grant ops only).
	Grants []GrantInfo `json:"grants,omitempty"`
}

// GrantInfo describes one active grant to the session that holds it. It
// carries names, never values.
type GrantInfo struct {
	Secrets   []string `json:"secrets"` // empty for setup and relay grants
	Scope     string   `json:"scope"`
	GrantedAt string   `json:"granted_at"`
	ExpiresAt string   `json:"expires_at"`
}

// Fixed refusal codes. Nothing caller-supplied or value-derived is ever echoed.
const (
	CodeInvalidRequest = "INVALID_REQUEST"
	CodeUnknownSecret  = "UNKNOWN_SECRET"
	CodeValueTooShort  = "SECRET_TOO_SHORT_TO_REDACT"
	CodeCommandRefused = "COMMAND_REFUSED"
	CodeDenied         = "DENIED_BY_OWNER"
	CodeBusy           = "BROKER_BUSY"
	CodeVaultFailed    = "VAULT_FAILED"
	CodeStartFailed    = "COMMAND_START_FAILED"
	CodeBrokerClosed   = "BROKER_CLOSED"
	CodeBrokerDown     = "BROKER_UNAVAILABLE"
	CodeNotSetUp       = "VAULT_NOT_SET_UP"
	CodeAlreadySetUp   = "ALREADY_SET_UP"
	CodeSetupFailed    = "SETUP_FAILED"
	// CodeNotAuthorized: no active grant of this session covers the request.
	// The owner was not prompted.
	CodeNotAuthorized = "NOT_AUTHORIZED"
	// CodeApprovalUnavailable: biometric approval is not possible here.
	CodeApprovalUnavailable = "APPROVAL_UNAVAILABLE"
	// CodeNotSupported: a granted operation this broker build does not offer.
	CodeNotSupported = "NOT_SUPPORTED"
	// CodeEnrollmentChanged: the enrolled biometrics changed since the broker
	// started; every approval is refused until it is restarted.
	CodeEnrollmentChanged = "APPROVAL_ENROLLMENT_CHANGED"
	// CodeCommandTooLong: the full command (executable, interpreter, every
	// argument, directory, secrets) does not fit in the Touch ID prompt, so it
	// cannot be approved. The owner was not prompted.
	CodeCommandTooLong = "COMMAND_TOO_LONG_TO_APPROVE"
	// CodeTimeBudget: the request's end-to-end time budget (110 s on the
	// agent channel) does not leave enough time to prompt the owner or run
	// the command. The owner was not prompted (or the wait ended unanswered
	// before a prompt), and nothing ran.
	CodeTimeBudget = "TIME_BUDGET_EXHAUSTED"
)

// States for an ingest request.
const (
	StateStored  = "stored"
	StateDenied  = "denied"
	StateApplied = "applied"
	StateGranted = "granted"
	StateRevoked = "revoked"
	StateListed  = "listed"
)
