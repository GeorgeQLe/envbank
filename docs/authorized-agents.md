# Authorized agents (`envbank.authorized-agents/v1`)

Status (November 4, 2026): **broker side implemented and unit-tested; host
side (the desktop host's forwarding, tool surface and settings) not built
yet; not run end to end; not qualified.** See
[Broker implementation](#broker-implementation).

Owner decisions:

- **Who is authorized.** Only agent sessions launched by the desktop host
  (Chromux) that the owner has explicitly granted. Agents outside the host
  (plain terminals, other apps) cannot use EnvBank at all.
- **How the owner confirms.** Every grant and every approval needs the
  owner's **Touch ID**. A computer-use agent can click and type, but cannot
  produce a fingerprint.

## Threat model

The adversary is any agent or process running as the owner. It may have a
shell and computer use: it can drive the host UI and the broker terminal and
run any binary, including signed EnvBank and Chromux. It must not be able to:

1. use a secret without a grant that covers it;
2. obtain or widen a grant without the owner's fingerprint;
3. approve a run, ingest, setup or pairing on the owner's behalf;
4. pass itself off as a different, granted session.

The host is trusted to attribute requests to the session it launched (it owns
that session's process tree, pty or VM) and is authenticated by code signature
over XPC. EnvBank does **not** trust the host's word that the owner approved
anything: the broker runs the biometric check itself.

## Channel

```text
 agent session ──host MCP tool──▶ Chromux main ──XPC (.ui)──▶ owner-input service ◀──XPC── envbank agent-broker
   (launched by Chromux)           (attaches session id)       (routes agent_request)       (policy + Touch ID)
```

- **Broker registration.** At startup the broker connects to
  `dev.georgele.chromux.owner-input` (the peer requirement from
  owner-input-xpc.md, cdhash-pinned after pairing), pairs **on that
  connection** (the service replies `confirmed` only after the owner's
  Touch ID in Chromux; then the owner's Touch ID in the broker terminal), and
  only then sends `{v, kind:"broker_hello"}` on it. Only the broker
  connection that completed a host-confirmed pairing may register; the
  service keeps it as the agent-request target and warns the owner in
  Chromux whenever the registered broker connection changes.
- **Forwarding.** Chromux sends `{v, kind:"agent_request", session, request}`
  on its `.ui` connection. The service forwards it, with a `route_id`, to the
  registered broker as a message expecting a reply. The broker's reply goes
  back to Chromux, and Chromux returns it to the session's tool call. With no
  broker registered the reply is `unavailable`.
- **No socket path.** The broker's Unix-socket agent API is **off by default**
  and needs `--legacy-socket` (development only; labelled unqualified).
  `envbank agent …` and `envbank mcp serve` therefore cannot reach a
  default broker.

## Messages

`session` (string fields, all required):

| Field | Meaning |
| --- | --- |
| `session_id` | host-assigned, unguessable (≥128 bits), unique per launched session |
| `workspace` | host workspace id |
| `agent_kind` | e.g. `claude`, `codex` |
| `label` | owner-visible session name, plain text, ≤80 characters |

The broker identifies a session to the owner by its **fingerprint**: the
first 8 lowercase hex characters of SHA-256 of the UTF-8 `session_id`. The
host must show the same fingerprint next to the session (in its session list
and "Granted agents" settings), so the owner can match a Touch ID prompt to
the session that asked.

`request` reuses the agent broker operations (`names`, `request`, `run`,
`setup`, `relay_request`) with the same fields and the same value-free
responses, plus:

- `grant_request {secrets:[NAME…], scope:"names"|"run"|"request", duration_s}`:
  ask the owner to grant this session; duration at most 12 h.
- `grant_status {}`: this session's active grants (names, scopes, expiry).

The reply is the agent broker response (value-free, fixed codes) plus `route_id`.

## Policy (broker)

- **Grants.** A grant is `{session_id, workspace, agent_kind, secrets,
  scope, expires_at, granted_at}`. Grants live in broker memory and end when
  the broker locks. Persistent grants are a later, separate decision.
- **Checks before any owner prompt.** Every agent operation is checked
  against grants first. `names` lists only granted secrets. `run` and
  `request` need a grant covering every named secret with that scope. `setup`
  and `relay_request` need an explicit setup or relay grant. Anything else is
  refused with `NOT_AUTHORIZED`, and the owner is never prompted for an
  ungranted request.
- **Touch ID for every grant.** The broker calls LocalAuthentication
  (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`). Biometrics only: no
  device-passcode fallback unless the owner starts the broker with
  `--allow-password-fallback`. The reason string puts the authoritative
  terms first and in full (action and scope, secrets, duration and expiry
  time, agent kind, session fingerprint, workspace) and the agent-influenced
  label last, after `; session label:`, with quote characters removed and
  control, bidi and zero-width characters replaced. Only the label is ever
  clipped; a request whose authoritative terms do not fit is refused. A
  grant is created only if this succeeds.
- **Grant-prompt limits.** Globally, at most one grant prompt is open at a
  time and grant prompts start at least 10 s apart. Each declined (or
  unapprovable) grant prompt, from any session, doubles a global backoff
  (30 s, 1 min, 2 min, … up to 15 min) that only an approval resets; new or
  churning sessions do not reset it. A declined session also waits 30 s. The
  per-session cooldown table is capped at 1024 entries by dropping expired,
  then oldest, entries; it is never cleared wholesale. Requests inside any
  limit get `BROKER_BUSY` without a prompt.
- **Touch ID for every approval.** Approvals that used to be a typed `y`
  (`run` once or always, ingest replace, setup plan, pairing confirmation) use
  the same Touch ID check, with the exact action in the reason string. The
  terminal shows the same details for reference, but typing there approves
  nothing. "Always" approvals stay scoped to the grant and end with it.
- **Secret entry.** Values are still typed in the host's secure window
  (owner-input), never in the terminal.
- **Biometrics unavailable.** If no biometry is enrolled, or the hardware is
  unavailable, the broker refuses every approval (`APPROVAL_UNAVAILABLE`).
  There is no silent fallback.

## Host (Chromux)

- **Tool surface.** Chromux exposes EnvBank tools to the agent sessions it
  launches, through its existing agent tool route. Each call is tagged with
  the session's identity by Chromux main, never by the agent.
- **Settings.** A "Granted agents" list shows sessions, grants and expiry,
  with a **Revoke** button. Revocation is sent as an agent request with
  `request:{op:"grant_revoke"}`. It needs no Touch ID: revoking only reduces
  access.
- **No silent requests.** The host never creates `grant_request` on its own.
  Only a session's tool call does.

## Broker implementation

What `envbank agent-broker` does today (`internal/authz`,
`internal/approval`, `internal/ownerinput/agent*.go`):

- **Agent channel.** It starts only after pairing with
  `--owner-input chromux --owner-input-unqualified`, so the service build is
  already pinned by cdhash. Without pairing, and without `--legacy-socket`,
  the broker refuses to start. On `dev.georgele.chromux.owner-input` it keeps
  one connection open and sends `{v, kind:"broker_hello"}` with a reply
  expected. The reply must be `{v, kind:"broker_hello", outcome}`; anything
  but `outcome:"registered"` (for example `declined`) closes the connection
  and retries. `broker_hello` is sent only after a `confirmed` pairing on the
  same connection. If the connection is interrupted (the service
  restarted), the broker pairs again on it, then says hello again; if it
  becomes invalid, it reconnects (pairing again) with backoff (1 s up to
  30 s). The
  service makes the newest broker connection the agent-request target. At
  most 8 requests are handled at a time.
- **`agent_request`, as received by the broker.** Every message carries
  `v:"envbank.owner-input-xpc/v1"`. The service sends this one as a message
  expecting a reply, on the broker's existing connection, with exactly these
  keys and no others:

  | Key | XPC type |
  | --- | --- |
  | `v` | string |
  | `kind` | string, `agent_request` |
  | `route_id` | uint64, not 0 |
  | `session` | dictionary of exactly four strings: `session_id`, `workspace`, `agent_kind`, `label` |
  | `request` | dictionary `{op, …op fields}`, with **no** `v`; at most 64 KiB when rendered as JSON |

  Session field formats:
  - `session_id`: 22 to 128 characters of `[A-Za-z0-9_-]`;
  - `workspace`: 1 to 128 characters of `[A-Za-z0-9._:@/-]`;
  - `agent_kind`: `[a-z0-9][a-z0-9._-]{0,31}`;
  - `label`: 1 to 80 characters, with no control, bidi or line-break
    characters.

  `request` values may be strings, integers, bools, arrays and nested
  dictionaries (for `setup`); any other XPC type refuses the request. The
  broker renders the dictionary as JSON and decodes it strictly (unknown
  fields are refused; `v`, if present, must be 1). Fields:
  - broker fields: `op`, `name`, `reason`, `secrets` (array of strings),
    `argv` (array of strings), `dir`, `timeout_seconds`, `always`, `setup`
    (dictionary);
  - grant fields: `scope` and `duration_s` (`grant_request` only).

  Operations:
  - `names`, `run`, `request`, `setup`, `relay_request`;
  - `grant_request {secrets, scope, duration_s[, reason]}`;
  - `grant_status {}` and `grant_revoke {}`. Revoke takes no fields, needs
    no Touch ID, and ends every grant of the calling session. There is no
    `grant_list` op.
- **Reply.** Exactly `{v, route_id, response}`, with no other keys:
  - `route_id` is the request's uint64 (omitted only when the request had
    no valid one);
  - `response` is a dictionary holding the agent broker's value-free
    response.

  Response contents:
  - Always `v` (int64 1) and `ok` (bool). On refusal, also `code` (fixed
    string).
  - Otherwise, whichever of these apply: `names`, `state`, `exit_code`,
    `timed_out`, `stdout`, `stderr`, `truncated`, `redactions`, `steps`,
    `grants`. Numbers are int64 and absent fields are omitted.
  - A malformed message gets `code:"INVALID_REQUEST"`. A request over the
    concurrency bound gets `code:"BROKER_BUSY"`.
  - Grant operations set `state` (`granted`, `listed` or `revoked`).
    `grant_request` and `grant_status` answer `{ok, state, grants:[{secrets,
    scope, granted_at, expires_at}]}`, where `secrets` is always an array
    (empty for `setup` and `relay`) and times are RFC 3339 UTC.
- **Time budget.** The host's service gives up on an agent request after
  150 s, and agent tool calls are capped at 120 s, so the broker answers
  every agent request within 140 s:
  - A request still waiting for the owner channel at the deadline gets
    `DENIED_BY_OWNER`.
  - A Touch ID prompt is limited to the time left; with under 10 s left, it
    is not shown.
  - A run still going at the deadline is killed and reported `timed_out`.
- **Scopes.**
  - `names`, `run` and `request` take 1 to 16 secret names.
  - `setup` and `relay` take none.
  - `names` lists the secrets in any of the session's `names`, `run` or
    `request` grants.
  - `run` needs a single grant that covers every secret named.
  - `relay_request` is checked against a `relay` grant, then answers
    `NOT_SUPPORTED`, because the relay is not built.
  - Durations run from 60 s to 12 h.
  - The tuple is `session_id`, `workspace` and `agent_kind`. `label` is for
    display only.
  - Limits: 16 grants per session and 256 in total.
- **Touch ID.**
  - Every grant and approval goes through `LAContext evaluatePolicy` with
    `LAPolicyDeviceOwnerAuthenticationWithBiometrics`. There is no password
    button, reuse duration is 0, and the timeout is 2 minutes.
  - `canEvaluatePolicy` is checked first; if it fails, the reply is
    `APPROVAL_UNAVAILABLE`.
  - `--allow-password-fallback` switches to
    `LAPolicyDeviceOwnerAuthentication`.
  - Reason strings are cleaned (control and bidi characters become `?`) and
    bounded to 600 bytes; authoritative terms come first, the session label
    last (see Policy).
  - A grant request whose authoritative terms would not fit is refused
    (`INVALID_REQUEST`). A run approval names the resolved executable, its
    script interpreter (shebang), every argument in full (invisible and
    quote-like characters escaped, space runs counted), the directory, the
    secrets, the mode, the executable hash prefix and the session. A run
    whose full text does not fit is refused with
    `COMMAND_TOO_LONG_TO_APPROVE` before any prompt; it is never clipped.
  - The `LAContext` is invalidated (the prompt dismissed) as soon as the
    request's context is cancelled or expires.
  - The biometric enrollment state (`domainState.biometry.stateHash`, or
    `evaluatedPolicyDomainState` before macOS 15) is recorded when the
    broker starts. If it changes (a fingerprint added or removed), every
    later approval is refused with `APPROVAL_ENROLLMENT_CHANGED`, before
    prompting, until the broker is restarted.
- **"Always".** A `run` sets `always: true` to ask for it, and the Touch ID
  text says so. It is offered only for fixed programs. It is stored under the
  grant and ends when that grant expires, is revoked or the broker locks.
  Grants are re-checked after every approval and right before the broker
  acts, so a revocation stops a request that is already in flight.
- **Revocation kills running commands.** When a grant is revoked, expires or
  ends with the broker, any command still running under it is killed (its
  whole process group, with `SIGKILL`) and the run answers `NOT_AUTHORIZED`
  with no output. A run's timeout is also capped at the time left in its
  grant.
- **Test seam.** A binary built with `-tags envbank_testapprover` adds
  `--test-approver-file PATH`, which answers approvals from a file, for
  disposable end-to-end runs only. Such a build refuses
  `--owner-input chromux` (so any XPC agent channel) and any `--config`
  outside a dedicated `TMPDIR` with `TEST_APPROVER_BUILD_REFUSED`. The
  default build has no such flag; a source/build test checks both.

## Not covered

- **Same-user debugging and memory inspection** of the signed processes.
  Hardened runtime without `get-task-allow` reduces this; it does not prevent
  root.
- **What a granted agent does with a granted `run`.** That is the agent
  broker's documented residual risk.
- **Grants persisting across a broker restart.** Not implemented.
