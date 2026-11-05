# Owner-input XPC transport v1 (`envbank.owner-input-xpc/v1`)

Status (November 4, 2026): **implemented, and end-to-end tested with a
synthetic value; not qualified.**

First signed end-to-end run on macOS 27.2, with a throwaway vault:

- **Builds.** The installed, Developer ID signed Chromux rebuild app had its
  service registered through `SMAppService` and approved by the owner. The
  broker was the signed `envbank` (`com.georgeqle.envbank`).
- **Pairing.** Pairing displayed in Chromux, and the owner confirmed that the
  code matched the terminal. The service build was then pinned by cdhash.
- **Entry.** An agent requested `SYNTH_TEST`. The owner typed a random
  synthetic value in Chromux's secure window. It was stored byte for byte, and
  the agent received only `stored`.
- **No leak observed.** The value appeared in neither the agent output nor the
  broker terminal transcript.

Two defects were found and fixed along the way:

- **Service reply context.** The service dropped the request's reply context,
  which the client saw as "Connection interrupted" (Chromux `dd580e7`).
- **Pairing window.** An open pairing window blocked the next entry, which
  then got `busy`. Being fixed; the run used a manual close.

The broker's pairing window was also extended from 2 to 10 minutes. The
installed-build no-leak harness and an independent review are still
required before `qualified`. This replaces the filesystem-socket transport of
[owner-input-protocol.md](owner-input-protocol.md). That transport is
disabled because a socket's peer token identifies its last owner, which an
impostor can arrange via fd hand-off and exec. Message semantics (purposes,
outcomes, pairing, display rules, no-leak requirements) are unchanged from
that document.

## Topology

```text
 envbank agent-broker ──XPC──▶ owner-input service ◀──XPC── Chromux main process
   (client, signed)          (launchd agent, signed)       (client via N-API module, signed)
```

- **Service.** A small native helper in the Chromux bundle, registered with
  `SMAppService.agent(plistName:)`. The owner approves it once under System
  Settings → General → Login Items & Extensions. The launchd plist ships
  inside the signed bundle (`Contents/Library/LaunchAgents/`), so an agent
  cannot re-point the Mach service without breaking the bundle signature.
  - Label and helper identifier: `dev.georgele.chromux.owner-input`.
  - **Two Mach service names**, because a peer requirement must be set
    before a connection is resumed, so the role can't be learned from a
    first message: `dev.georgele.chromux.owner-input` accepts only brokers,
    and `dev.georgele.chromux.owner-input.ui` accepts only the Chromux UI.
- **UI client.** The Chromux main process connects through an N-API module
  loaded in-process. The XPC connection exists only inside the genuine
  Chromux process. No intermediate bridge process is allowed: a bridge's
  pipes can be handed to an agent the same way a socket can.
- **Broker client.** `envbank agent-broker --owner-input chromux` connects
  through libxpc (cgo).

## Peer requirements (checked by macOS on every message)

Each side calls `xpc_connection_set_peer_code_signing_requirement`. The
service sets it on every incoming connection; each client sets it on its
service connection. All requirements are Developer ID only and refuse
debuggable code:

```text
anchor apple generic
and certificate 1[field.1.2.840.113635.100.6.2.6]
and certificate leaf[field.1.2.840.113635.100.6.1.13]
and certificate leaf[subject.OU] = "NC56VXK48K"
and identifier "<ID>"
and !(entitlement["com.apple.security.get-task-allow"] exists)
```

| Who checks | Peer | `<ID>` |
| --- | --- | --- |
| Service | broker | `com.georgeqle.envbank` |
| Service | UI | `dev.georgele.chromux.v2.rebuild` or `party.gblock.chromux.v2.desktop` (build-time list) |
| Broker | service | `dev.georgele.chromux.owner-input` |
| UI | service | `dev.georgele.chromux.owner-input` |

The Team ID and identifiers are build or flag inputs with these defaults. A
connection whose peer fails the requirement gets `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`,
and no message is processed.

## Service rules

- **Routing.** At most one UI connection may be registered: the most recent
  verified UI client replaces the previous one. Requests are routed only to
  that connection. With no UI client, the service replies `unavailable`.
- **Requests.** One outstanding request at a time; any other gets `busy`.
- **Expiry.** The service enforces `expires_at` of at most 120 s. On expiry it
  replies `expired` to the broker and tells the UI to cancel.
- **What the service never does.** It never logs, persists or inspects
  values: it copies the reply's `value` data to the broker reply once and
  then releases it. It holds no state across restarts.
- **Identity.** It reports its own build cdhash in pairing replies.

## Messages (XPC dictionaries)

The `kind` and fields below come from the broker. The service forwards them
to the UI as the same dictionary, plus a `route_id` (uint64). Every field is
type-checked. Unknown keys mean the message is dropped and the reply is
`declined`.

| Key | Type | Notes |
| --- | --- | --- |
| `v` | string | `envbank.owner-input-xpc/v1` |
| `kind` | string | `pairing` or `entry` (agent-channel kinds are in authorized-agents.md) |
| `nonce` | string | 32 lowercase hex |
| `expires_at` | string | RFC 3339, at most 120 s ahead |
| `pairing_code` | string | pairing only, 6 digits |
| `purpose` | string | entry only: `new_vault_passphrase`, `recovery_passphrase`, `unlock_passphrase` or `secret_value` |
| `title` `detail` `subject` | string | entry only; untrusted; at most 80 / 300 / 128 characters; no control or bidi characters |
| `min_bytes` `max_bytes` | int64 | entry only; `1 ≤ min ≤ max ≤ 4096` |
| `confirm` | bool | entry only |

The reply is a dictionary with `v`, `nonce` (echoed), `outcome` (string) and,
only when the outcome is `entered`, `value` (data). Possible outcomes:

| Kind | Outcomes |
| --- | --- |
| entry | `entered`, `declined`, `cancelled`, `expired`, `busy`, `unavailable` |
| pairing | `confirmed`, `declined`, `cancelled`, `expired`, `busy`, `unavailable` |

Pairing replies also carry `provider` (a dictionary of the UI's
self-report) and `service_cdhash` (string), and nothing else (no `value`).

**Pairing is confirmed on the host (Unreleased; replaces `displayed`).** The
service and UI show the pairing code and reply `confirmed` only after the
owner confirmed that code **in Chromux with Touch ID**. Showing the code is
no longer enough: the broker treats `displayed`, or any other outcome, as not
paired. The broker then asks for the owner's Touch ID in its own terminal as
well; both are required.

**Pairing is per connection.** The broker sends `pairing` on the same
long-lived connection it later registers on with `broker_hello`
(authorized-agents.md), and sends `broker_hello` only after a `confirmed`
pairing on that connection. The service must:

- accept `broker_hello` (and route agent requests) only on a broker
  connection that completed a host-confirmed pairing, and forget that
  pairing when the connection closes or the service restarts (the broker
  then pairs again before saying hello again);
- warn the owner in Chromux whenever the registered broker connection
  changes (a new broker, or the same broker after a reconnect), before
  routing anything to it.

### Service ↔ UI messages (implemented in the provider)

- **Hello.** The UI connects to `…owner-input.ui` and sends `{v, kind:"ui_hello"}`.
  The service replies `{v, kind:"ui_hello", outcome:"registered", service_cdhash}`.
  The newest verified UI wins, and a request in flight on the old UI ends
  `cancelled`.
- **Forwarding.** The service forwards the broker's dictionary plus `route_id`
  (uint64). The UI replies `{v, nonce, route_id, outcome[, value][, provider]}`.
  The service validates this reply, then builds a **fresh** broker reply
  containing only `v`, `nonce`, `outcome`, `value`, `provider` and
  `service_cdhash`; `route_id` never reaches the broker.
- **Cancel.** The service sends `{v, kind:"cancel", route_id}` to the UI, with
  no reply expected.
- **Other details.** `service_cdhash` is present on every pairing reply. A
  request with a malformed nonce gets `declined` with no `nonce`, which the
  broker treats as a protocol error.

## Broker behavior

- **Pairing.** Pair at start, on the agent-channel connection, using the
  6-digit code shown in Chromux. The service replies `confirmed` only after
  the owner's Touch ID in Chromux; the broker then shows the code, the
  service's team, identifier and cdhash in its terminal and asks for Touch ID
  again (the reason names the code). Any other outcome, a wrong nonce, an
  unknown key or a `value` pins nothing and closes the connection. A new
  connection, or a service restart, pairs again (both Touch IDs) before
  `broker_hello`; a re-pairing must report the same pinned build. After 3
  declined pairings in a row the agent channel stops until the broker is
  restarted; transport failures only back off (1 s to 30 s).
- **Pinning.** For the rest of the session the broker pins the service build
  it paired with by appending `and cdhash H"<service cdhash>"` to its peer
  requirement. macOS then enforces the same build on every later message;
  the broker does not trust a self-reported hash alone.
- **Values.** The broker accepts `value` only on `entered`, for the
  outstanding nonce, within bounds, and zeroes it after use.
- **Fallback.** If the service is unavailable or fails the requirement, the
  broker falls back to the terminal and says so. A decline in Chromux is a
  decline, never a silent fallback.
- **Real secrets.** They go through this transport only once the
  installed-build qualification in owner-input-protocol.md has passed.
  Until then the broker labels the session `unqualified` and requires the
  owner's explicit `--owner-input-unqualified` flag.
