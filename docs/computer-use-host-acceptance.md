# External computer-use host: integration and acceptance checklist

Status (November 4, 2026): **release fail-closed; lifecycle-hook admission
implemented but not installed or qualified.**

Correction of earlier wording: Codex **does** document `PreToolUse` and
`PostToolUse` lifecycle hooks, and `PreToolUse` can deny a tool call. They are
not a global observation barrier or a Driver registration hook: a hook command
error, timeout or malformed output can fail open at the runtime, missing or
untrusted hooks do not run, continued `write_stdin` input has no new
`PreToolUse`, hosted tools are not covered and specialized tool paths can opt
out, `PostToolUse` runs after the tool (its `decision: "block"` replaces the
result and rejects a code-mode nested promise, but cannot undo side effects),
and a hook process cannot drain or invalidate work begun before a protected
phase. No browser extension
can hide native screenshots, accessibility trees or OS capture.

Three separate states, kept distinct:

| Layer | State |
| --- | --- |
| (a) Code implemented | `pkg/codexhook` + `envbank codex-hook pre-tool-use/post-tool-use` deny/withhold every hooked tool while the shared `Gate` latch is set or unknown ([integration notes](../integrations/codex/README.md)); `protectedfill.ProbeGate` reads that one latch. |
| (b) Registered in a controlled host | **Not done.** EnvBank installs, enables and trusts nothing; `integrations/codex/hooks.example.json` is an owner-review artifact; its shape, matcher, timeout and outputs were source-checked against the official Codex hooks documentation (November 4, 2026), not against an installed runtime. |
| (c) Installed vendor/runtime qualification | **Not done, not claimed.** The closed-source Codex/CUA service was not patched or qualified. |

Credential release stays refused for any hook-observed host: there is no
Driver in the hook integration, and `pkg/computeruse.NewNativeHost` with only a
shared `Gate` still returns `HOST_PROTECTION_UNAVAILABLE` before the config or
Keychain is opened (`pkg/codexhook/hook_test.go`). Without a host-supplied `Gate`
**and** qualified `Driver`, every value-releasing or credential-mutating action
is refused (`pkg/computeruse/host_test.go`, `internal/nativehost/protected_test.go`,
`pkg/protectedfill/operation_test.go`). Those are isolated tests, not external
acceptance.

Safe to merge with runtime activation disabled: the hook package, CLI
entrypoint, probe and example artifacts (no install path, no Driver, no new
release route). Not safe to claim: any route coverage of the installed runtime,
or any credential transfer through it.

## Ownership the host must prove

The host vendor (not EnvBank, not the agent) must own and document each route,
and route it through ONE shared `Gate.Observe` for all sessions:

| Route | Owner must provide | Evidence required |
| --- | --- | --- |
| Screenshots (explicit and automatic, thumbnails, previews) | Capture call site wrapped by `Gate.Observe`; no pre-barrier cache | Sentinel never appears in any image/OCR during or after the protected phase |
| Screen recording / video / streaming | Paused and segment discarded across the barrier | Recorded artifacts free of sentinel |
| Accessibility tree / AX queries | AX reads wrapped; no AX snapshot cache | AX dumps free of sentinel; field value never exposed |
| DOM / CDP / page scripts | Controller-owned isolated browser context; no DOM read/eval during protected phase; DevTools closed | DOM, console and network logs free of sentinel |
| Clipboard / pasteboard | Never used for value transfer; clipboard reads wrapped | Pasteboard history unchanged |
| Logs, traces, crash reports, telemetry | Value-bearing buffers excluded; tool results not logged outside the wrapper | Log/trace grep free of sentinel |
| Delayed callbacks / late results | Captures started before the barrier are cancelled and discarded (`epoch`) | Late-result test against the real capture pipeline |
| Parallel agents / sessions / sub-agents | Single process-wide authority (`OpenGate` lock) shared by every session | Concurrent session cannot observe during protected phase |
| Input tools (click/type/keys) | Wrapped by the same Gate; blocked during the protected phase | No agent input reaches the isolated context mid-fill |
| Shell / file / process inspection | Contained or disabled during the phase | Documented sandbox boundary |
| Driver (`Validate`, `FillAndSubmit`, `Destroy`, `DestroyOrphans`) | Single-use human authorization bound to record/origin/context/document/field/submit; proof all pages/popups/artifacts destroyed | Crash/kill tests leave the durable latch blocked until trusted recovery |

## Acceptance procedure (owner + host vendor)

1. Obtain written host API documentation for the barrier and Driver hook. If
   it does not exist, stop: the blocker remains.
2. Wire `protectedfill.OpenGate` (private absolute directory) and a reviewed
   `Driver` in the host's own bootstrap, then `computeruse.NewNativeHost`.
3. Use a disposable fake site and a random disposable sentinel record (never a
   real credential). Exercise every route above during and after a protected
   fill, including forced late captures, parallel sessions, driver crash and
   SIGKILL of the host.
4. Scan every artifact (images via OCR, AX dumps, DOM/HAR, clipboard history,
   logs, traces, crash reports) for the sentinel. Any hit fails acceptance.
5. Independent source/security review of the host integration and Driver.
6. Only then may show-once provider key capture be designed as a separate,
   separately approved flow.

Until all steps pass, protected filling and browser capture of provider keys
stay unavailable, and the Vercel REST path remains the only supported route.
