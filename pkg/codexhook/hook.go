// Package codexhook connects EnvBank's shared protected-operation state
// (pkg/protectedfill Gate latch) to the documented Codex lifecycle hooks
// PreToolUse and PostToolUse as ADDITIONAL, owner-installed enforcement.
//
// What it does: while the gate is latched (a protected phase is active, or a
// crashed phase awaits trusted recovery) or its state is unknown, PreToolUse
// denies EVERY tool call it is invoked for (no tool-name allow/deny list), and
// PostToolUse returns decision "block", which the Codex hooks documentation
// says replaces the model-visible tool result with the fixed reason and, for a
// code-mode nested call, rejects the tool promise with that reason (unlike
// continue:false, which does not reject it). Neither undoes side effects of a
// tool that already ran. Malformed, oversized, slow or mismatched hook input
// is treated the same way.
//
// What it cannot do, and therefore never claims: lifecycle hooks are not a
// global capture barrier. The runtime may fail OPEN when a hook command errors,
// times out or prints malformed output; a missing or untrusted hook does not
// run at all; continued write_stdin input has no new PreToolUse; hosted tools
// are not dispatched through local hooks; and specialized tool paths can opt
// out of the hook path. A hook process also
// cannot drain or invalidate work that started before a protected phase. So
// nothing in this package — no tool argument, extension ACK, plugin trust
// flag, hook payload field or configuration — can qualify a host for value
// release. There is no Driver here: credential release through a Codex-hosted
// observer stays refused (HOST_PROTECTION_UNAVAILABLE).
//
// Tool inputs and responses are never logged, persisted, echoed or parsed
// beyond the envelope fields below; the input buffer is wiped after parsing,
// including when a slow writer finishes after the read bound has expired.
package codexhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

type Event string

const (
	PreToolUse  Event = "PreToolUse"
	PostToolUse Event = "PostToolUse"
)

const (
	// MaxInputBytes bounds the hook payload read from stdin. Larger ⇒ refused.
	MaxInputBytes = 1 << 20
	// ReadTimeout refuses before a slow writer can push the hook into the
	// runtime's own timeout (which may fail open).
	ReadTimeout = 2 * time.Second

	DenyReason     = "EnvBank protected operation is active or protection state is unknown; tool call refused."
	WithheldReason = "EnvBank protected operation is active or protection state is unknown; this tool result was withheld."
)

// Capabilities is a fixed statement of this integration's coverage. No input
// can change it.
type Capabilities struct {
	Version                       string   `json:"version"`
	Integration                   string   `json:"integration"`
	Events                        []string `json:"events"`
	Role                          string   `json:"role"`
	ToolCoverage                  string   `json:"tool_coverage"`
	GlobalCaptureBarrier          bool     `json:"global_capture_barrier"`
	RuntimeMayFailOpenOnHookError bool     `json:"runtime_may_fail_open_on_hook_error"`
	MissingOrUntrustedHookRuns    bool     `json:"missing_or_untrusted_hook_runs"`
	SpecializedPathsMayOptOut     bool     `json:"specialized_tool_paths_may_opt_out"`
	WriteStdinPreToolUseCovered   bool     `json:"write_stdin_pre_tool_use_covered"`
	HostedToolsCovered            bool     `json:"hosted_tools_covered"`
	// Documented for decision "block" (not continue:false): the model-visible
	// result is replaced and a code-mode nested tool promise rejects with the
	// reason. The tool has already run; its side effects are not undone.
	PostToolUseBlockRejectsNestedPromise bool   `json:"post_tool_use_block_rejects_nested_promise"`
	PostToolUseUndoesSideEffects         bool   `json:"post_tool_use_undoes_side_effects"`
	InFlightWorkDrain                    bool   `json:"in_flight_work_drain"`
	StaleResultInvalidation              string `json:"stale_result_invalidation"`
	CapabilitySource                     string `json:"capability_source"`
	CredentialRelease                    string `json:"credential_release"`
	InstalledRuntimeQualified            bool   `json:"installed_runtime_qualified"`
	InstallationState                    string `json:"installation_state"`
}

// Describe returns the fixed capability statement.
func Describe() Capabilities {
	return Capabilities{
		Version:                              "envbank-codex-hook/v2",
		Integration:                          "codex-lifecycle-hooks",
		Events:                               []string{string(PreToolUse), string(PostToolUse)},
		Role:                                 "additional_admission_enforcement",
		ToolCoverage:                         "every_local_tool_call_the_runtime_dispatches_to_this_hook",
		GlobalCaptureBarrier:                 false,
		RuntimeMayFailOpenOnHookError:        true,
		MissingOrUntrustedHookRuns:           false,
		SpecializedPathsMayOptOut:            true,
		WriteStdinPreToolUseCovered:          false,
		HostedToolsCovered:                   false,
		PostToolUseBlockRejectsNestedPromise: true,
		PostToolUseUndoesSideEffects:         false,
		InFlightWorkDrain:                    false,
		StaleResultInvalidation:              "post_time_latch_check_only",
		CapabilitySource:                     "official_codex_hooks_documentation_not_installed_runtime",
		CredentialRelease:                    "refused",
		InstalledRuntimeQualified:            false,
		InstallationState:                    "owner_review_required_not_installed_by_envbank",
	}
}

type preToolUseOutput struct {
	HookSpecificOutput preToolUseDecision `json:"hookSpecificOutput"`
}

type preToolUseDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type postToolUseOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// envelope holds only the fields used for validation. tool_input and
// tool_response are deliberately absent so they are never decoded or retained.
type envelope struct {
	HookEventName *string `json:"hook_event_name"`
	ToolName      *string `json:"tool_name"`
}

// Evaluate reads one hook payload and writes at most one decision. With a
// READY gate and a well-formed payload it writes nothing (no opinion; the
// runtime's normal permission flow applies). Everything else refuses. The
// returned error reports only a failed write of the decision itself.
func Evaluate(event Event, gateDirectory string, input io.Reader, output io.Writer) error {
	known := event == PreToolUse || event == PostToolUse
	if !known {
		event = PreToolUse // an unknown event is answered with a refusal, never allowed
	}
	wellFormed := known && readEnvelope(event, input)
	if wellFormed && protectedfill.ProbeGate(gateDirectory) == protectedfill.GateReady {
		return nil
	}
	if event == PostToolUse {
		return json.NewEncoder(output).Encode(postToolUseOutput{Decision: "block", Reason: WithheldReason})
	}
	return json.NewEncoder(output).Encode(preToolUseOutput{HookSpecificOutput: preToolUseDecision{
		HookEventName: string(PreToolUse), PermissionDecision: "deny", PermissionDecisionReason: DenyReason,
	}})
}

func readEnvelope(event Event, input io.Reader) bool {
	if input == nil {
		return false
	}
	type result struct {
		raw []byte
		err error
	}
	// Unbuffered: a reader that finishes after the bound has expired cannot
	// hand its buffer over, so it wipes the buffer itself and ends.
	done := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		// One fixed buffer, so no partially filled growth copies are left
		// behind unwiped. One extra byte detects oversize input.
		buf := make([]byte, MaxInputBytes+1)
		n, err := io.ReadFull(input, buf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = nil
		}
		select {
		case done <- result{buf[:n], err}:
		case <-abandoned:
			wipe(buf)
		}
	}()
	timer := time.NewTimer(ReadTimeout)
	defer timer.Stop()
	var r result
	select {
	case r = <-done:
	case <-timer.C:
		// The reader may stay blocked until the runtime closes stdin (the
		// hook process exits first); its buffer is never parsed or returned.
		close(abandoned)
		return false
	}
	defer wipe(r.raw)
	if r.err != nil || len(r.raw) == 0 || len(r.raw) > MaxInputBytes {
		return false
	}
	trimmed := bytes.TrimSpace(r.raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return false
	}
	var e envelope
	if json.Unmarshal(trimmed, &e) != nil || e.HookEventName == nil || *e.HookEventName != string(event) || e.ToolName == nil || *e.ToolName == "" || len(*e.ToolName) > 256 {
		return false
	}
	return true
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
