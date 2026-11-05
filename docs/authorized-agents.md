# Authorized agents (`envbank.authorized-agents/v1`)

Status (November 4, 2026): **specification; implementation in progress; not
qualified.**

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
  owner-input-xpc.md, cdhash-pinned after pairing) and sends
  `{v, kind:"broker_hello"}`. The service keeps the newest broker
  connection as the agent-request target.
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
  `--allow-password-fallback`. The reason string names the session label,
  agent kind, workspace, secrets, scope and duration. A grant is created only
  if this succeeds.
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

## Not covered

- **Same-user debugging and memory inspection** of the signed processes.
  Hardened runtime without `get-task-allow` reduces this; it does not prevent
  root.
- **What a granted agent does with a granted `run`.** That is the agent
  broker's documented residual risk.
- **Grants persisting across a broker restart.** Not implemented.
