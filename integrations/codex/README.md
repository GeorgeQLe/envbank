# Codex lifecycle hooks: owner-reviewed EnvBank integration

Status (November 4, 2026): **code implemented; not installed; not qualified.**
EnvBank does not install, enable or trust these hooks, does not edit any Codex
configuration, and never uses `--dangerously-bypass-hook-trust`. The owner
reviews and installs them manually, if at all.

## What this is

Codex documents `PreToolUse` and `PostToolUse` lifecycle hooks that run an
owner-configured command with a JSON payload on stdin. `envbank codex-hook`
connects them to the **same** durable protected-operation latch that
`pkg/protectedfill.Gate` writes before any value is retrieved. It keeps no
state of its own.

| Gate state | `pre-tool-use` | `post-tool-use` |
| --- | --- | --- |
| READY (initialized, no latch) | prints nothing (no opinion) | prints nothing |
| BLOCKED (active phase or crash latch) | `permissionDecision: "deny"` | `decision: "block"` (result replaced; code-mode nested promise rejects) |
| UNKNOWN (missing, non-private, foreign-owned, uninitialized, unreadable) | deny | withheld |
| Malformed/oversized (>1 MiB)/slow (>2 s)/mismatched payload, bad flags | deny | withheld |

Every tool call the runtime dispatches to the hook is treated the same; there
is no tool-name allow/deny list. Tool inputs and responses are never logged,
persisted, echoed or decoded (only `hook_event_name` and `tool_name` are
checked). Refusals are fixed strings. `envbank codex-hook capabilities` prints
the fixed coverage statement.

## Why this does not qualify a host for credential release

Lifecycle hooks are additional enforcement, not a global capture barrier:

- the runtime may **fail open** if the hook command errors, times out or prints
  malformed output (the hook refuses on its own 2 s input bound to reduce this,
  but cannot remove it);
- a **missing or untrusted hook does not run**: non-managed hooks (user,
  project, plugin) are skipped until reviewed and trusted, and hooks can be
  turned off with `[features].hooks = false`;
- continued `write_stdin` input to a running process has **no new PreToolUse**
  (a later poll may deliver the original command's PostToolUse);
- **hosted tools** (for example `WebSearch`) do not use the local hook path, and
  specialized tool paths can opt out of it;
- `PostToolUse` runs **after** the tool. `decision: "block"` replaces the
  model-visible result and, for a code-mode nested call, rejects the tool
  promise with the hook reason (unlike `continue: false`), but it **cannot undo
  side effects** of the tool that already ran;
- a hook process cannot **drain or invalidate** work that started before a
  protected phase, and same-user processes can tamper with local state.

Therefore there is no Driver here and no input (tool argument, extension ACK,
plugin trust flag, payload field, flag) can mark the host qualified. A
Codex-observed host embedding `pkg/computeruse.NewNativeHost` with only the
shared Gate still returns `HOST_PROTECTION_UNAVAILABLE` before any Keychain or
config access. The installed closed-source Codex/CUA service has not been
patched, inspected or qualified.

## Owner installation (manual, optional)

1. Choose a private absolute gate directory on owner-controlled storage that
   the protected-operation authority will also use.
2. `envbank codex-hook init-gate --gate-dir DIR` (creates the 0700 directory and
   authority lock file through `protectedfill.OpenGate`; installs nothing).
3. `hooks.example.json` was checked against the official Codex hooks
   documentation downloaded on November 4, 2026 (not against an installed
   runtime): `hooks.json` shape (event → matcher group → `command` handler),
   `matcher: "*"` matches every occurrence of `PreToolUse`/`PostToolUse`,
   `timeout` is in seconds (default 600; 5 here exceeds the 2 s input bound),
   PreToolUse `hookSpecificOutput.permissionDecision: "deny"` and PostToolUse
   `decision: "block"` with `reason` are documented outputs, and exit 0 with no
   output means "continue". Locations include `~/.codex/hooks.json` and
   `<repo>/.codex/hooks.json` (project hooks load only when that layer is
   trusted). Do not set `async`: background hooks cannot block. Recheck against
   the documentation current at installation time.
4. Install through Codex's own documented `/hooks` review and trust flow. Do
   not use `--dangerously-bypass-hook-trust`.

## Tests

`go test ./pkg/codexhook ./pkg/protectedfill` and
`go test ./cmd/envbank -run TestCodexHook` cover ready/no-opinion, in-flight and crash latches across parallel callers,
malformed/oversized/slow input, unavailable/forged gate directories,
qualification-claim payloads, output redaction with random sentinels, and
refusal of release by the native-host embedding. These are isolated tests; they
do not exercise an installed Codex runtime.
