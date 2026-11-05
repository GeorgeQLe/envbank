# Cross-device secret relay

Status (November 4, 2026): **implemented for the vault-ingest sink and tested
end to end against a disposable loopback server and throwaway vault. Not yet
independently reviewed, and not yet available on the Cloudflare Worker sync
runtime.**

The relay lets the owner type a secret on one enrolled device (the *sender*,
for example a phone or a second laptop) and have it stored in the vault by
another device's owner-held [agent broker](agent-broker.md) (the *target*).
The value is plaintext only in the sender's `envbank relay send` process and
the target broker process. The sync service carries ciphertext only, and
agents learn only `stored`, `denied` or `expired`.

## Flow

```
 target (B): owner-held broker                 sender (A): owner terminal
 ─────────────────────────────                 ──────────────────────────
 agent: envbank agent relay-request
   --name NAME --reason TEXT
 owner picks the sending device ──┐
 request created, code shown      │ POST /relays (descriptor: opaque)
   "Relay code: 123 456"          │
                                  │            envbank relay send
                                  │ GET /relays  ── verifies request,
                                  │               shows target + code
                                  │            owner: code matches? y
                                  │            owner types value twice (no echo)
                                  │ POST /relays/ID/seal (envelope: opaque)
 broker polls POST /relays/ID/consume (once)
 verifies, decrypts, shows sender + code
 owner: store? y  → vault ingest under NAME
 agent receives: stored
```

1. **Target-initiated.** An agent (`envbank agent relay-request`, or the MCP
   tool `envbank_secret_relay_request`) or the owner asks the broker for a
   value. The broker lists the vault's other active devices and the owner
   approves by choosing the sender. The broker creates a request with a fresh
   random id and 32-byte nonce, an expiry of five minutes, and a sink (ingest
   under `NAME`). It shows the six-digit relay code.
2. **Sender verification.** `envbank relay send` (owner's own terminal on the
   sender) unlocks the device config, fetches pending requests addressed to
   it, and verifies each one (see below). It shows the target device's name,
   ID and enrollment fingerprint, the name, the sanitized reason, the expiry
   and the code. The owner continues only if the target shows the same code.
3. **Entry.** The value is read twice from the terminal with echo turned off
   *before* each prompt (`agentbroker.ReadHidden`). Values must be 8 bytes to
   64 KiB of UTF-8 text. There is no clipboard, file, argument or environment
   input.
4. **Delivery.** The broker polls, takes the envelope once, verifies and
   decrypts it, then shows the sender device and the code again and asks the
   owner to confirm storing (or replacing). It stores through the same vault
   path as `envbank set` and the broker's ingest, and the agent gets
   `stored`.

## Cryptography

No new primitives are introduced. Everything comes from `internal/secure`:

| Part | Construction |
| --- | --- |
| Descriptor confidentiality and authenticity | AES-256-GCM (`secure.Seal`) under `HKDF-SHA-256(vault_key, info = "envbank.relay.descriptor-key.v1\x00" ‖ vault_id)`; AAD = `"envbank.relay.descriptor.v1" ‖ vault_id ‖ request_id ‖ target_id ‖ sender_id ‖ expires_at` (NUL-separated) |
| Descriptor origin | Ed25519 signature by the target over `"envbank.relay.request.v1\n" ‖ descriptor_json` |
| Value envelope | `secure.SealToDevice`: the same ephemeral-X25519 + HKDF-SHA-256 + AES-256-GCM construction as enrollment vault-key envelopes, to the target's wrapping key, with its own context |
| Envelope context (HKDF info and GCM AAD) | `"envbank.relay.seal.v1" ‖ vault_id ‖ request_id ‖ target_id ‖ sender_id ‖ sink_kind ‖ sink_name ‖ expires_at ‖ nonce ‖ base64url(SHA-256(descriptor_json))` |
| Envelope origin | Ed25519 signature by the sender over the envelope message (SHA-256 of the context, ids, ephemeral key, nonce, ciphertext) |
| Same-vault proof | HMAC-SHA-256 of the same message under `HKDF-SHA-256(vault_key, "envbank.relay.mac-key.v1\x00" ‖ vault_id)` |
| Relay code (SAS) | `SHA-256("envbank.relay.sas.v1" ‖ vault_id ‖ request_id ‖ nonce ‖ target signing ‖ target wrapping ‖ sender signing ‖ sender wrapping)`, first 8 bytes big-endian mod 10⁶, shown as `123 456` |

The relay subkeys follow the review's recommendation of domain-separated
subkeys rather than using the vault key directly.

**The sender accepts a request only if** it decrypts under the vault-key
subkey with the server's metadata as AAD, it is signed by the target it names,
its ids and expiry equal the server metadata, it names this device (id and
both keys) as sender, it is unexpired, and the target is an *active* device in
the vault's device list with exactly those keys and a matching fingerprint.

**The target accepts an envelope only if** it is for its own outstanding
request (in memory, one envelope per request), it is unexpired, the vault MAC
and the sender's signature verify, the sender is still an active device with
the keys the target chose, and the envelope decrypts with the target's
wrapping key under the full context. A valid envelope consumes the request
even if the owner then declines.

## Sync service

Authenticated endpoints (existing Ed25519 request signatures, timestamp window
and persisted nonce replay protection) under `/v1/vaults/{vault}/relays`:

| Endpoint | Caller | Effect |
| --- | --- | --- |
| `POST /relays` | target | create; sender must be another active device; expiry ≤ 5 min (+30 s skew) on the server clock |
| `GET /relays` | sender or target | pending, unexpired requests the caller sends or receives |
| `POST /relays/{id}/seal` | sender only | store one envelope while pending and unexpired |
| `POST /relays/{id}/consume` | target only | `pending`, or the envelope exactly once (then `consumed`) |
| `DELETE /relays/{id}` | target only | cancel |

The `relays` table (schema version 7) holds `vault_id`, `id`,
`target_device_id`, `sender_device_id`, `created_at`, `expires_at`, `state`,
`descriptor` (opaque) and `envelope` (opaque). The secret name, reason, value
and the devices' keys are not stored in clear. Descriptor and envelope bytes
are cleared on consume, cancel and expiry. The tombstone row blocks id reuse
for an hour and is then deleted. Limits: 16 KiB create bodies, 8 KiB
descriptors, 160 KiB envelope bodies, 8 active requests per vault, 2 per target
device, 20 created per target device per hour. Errors use fixed messages and
access-event reasons (`relay_*` operations, `rate_limited`).

## Threat model

- **Compromised or curious sync service.** It cannot read the name, reason or
  value. It cannot forge or alter a request (no vault key) or an envelope (no
  vault key, no sender signing key). Replays fail: each request accepts one
  envelope, the target only accepts envelopes for its own outstanding
  request, and every field is bound. It *can* withhold, delay or delete
  messages (denial of service), and it learns that a relay happened between
  two devices and the envelope size.
- **Substituted devices.** A server that injects a fake device into the
  device list still cannot produce a vault MAC or descriptor. A wrong but
  enrolled device, or a confused request, shows a different relay code.
  Because the code is only six digits, it is a confusion check, not the
  primary authenticator: the vault-key subkeys and device signatures are.
- **Agents.** The agent chooses only the name and reason, both sanitized
  before display. It cannot pick the sender, see the code's inputs, or
  receive the value. The owner approves on both devices. The same residual
  risks as the [agent broker](agent-broker.md) apply: same-user processes and
  computer-use agents that can read or type into the broker terminal.
- **Compromised enrolled device.** Any device holding the vault key and an
  active enrollment can act as sender or target. Revoke lost devices
  (`envbank device-revoke`). Revocation is checked at request time and again
  before the target accepts an envelope. Revocation does not rotate the vault
  key; see the [cryptographic review report](cryptographic-review-report.md).
- **Clocks.** Each side checks expiry against its own clock and the server
  against its clock. Badly skewed clocks make relays expire early or fail.

## Limits and not done

- Only the vault-ingest sink exists. The vault passphrase prompt and protected
  browser fill sinks are not built.
- Only the Go `envbank serve` service implements `/relays`. The Cloudflare
  Worker runtime does not yet, so hosted vaults cannot relay.
- The broker's owner terminal is busy while it waits for the envelope (up to
  five minutes). Ctrl-C locks the broker; the agent can cancel by
  disconnecting.
- The target polls `consume` every two seconds. Each poll is a signed request
  and records an access event, so one relay can add up to about 150 events to
  the bounded access history.
- If the consume response is lost in transit after the server commits, the
  request is consumed but nothing is stored; start a new relay.
- Values are text, entered on one line (no multi-line values), up to the
  terminal reader's 4 KiB line limit.
- Buffers are wiped best effort. Go strings (the stored record) and garbage
  collector copies cannot be wiped.
- Not independently reviewed. The SAS length, the HMAC same-vault proof and
  the polling transport are candidates for review.

## Tests

- `internal/relay`: round trip, the code and its inputs, each bound context
  field tampered (with otherwise valid signature and MAC), wrong recipient
  key, wrong signer, wrong vault key, expiry on both sides, replay and second
  envelope, server-metadata tampering, enrolled-device checks, value bounds.
- `internal/server`: authentication and replay, single use and second fetch,
  actor checks, cancellation, revoked sender, server-clock expiry, creation
  validation and rate limits, envelope size and shape, no plaintext in the
  database file or WAL, and cleared ciphertext after consume.
- `internal/agentbroker` and `cmd/envbank`: broker outcomes with fakes, prompt
  sanitization, and `relay send` against an in-process server with two
  devices.
- `e2e/relay` (macOS, `ENVBANK_E2E_RELAY=1`): the real binary, loopback
  `envbank serve`, two devices enrolled into a throwaway vault, the broker and
  `relay send` driven through pseudo-terminals, and an agent. It asserts that
  the value is stored on the target and absent from the agent's output, both
  terminal transcripts, the server log and the server database.
