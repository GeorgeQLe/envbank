# EnvBank architecture

EnvBank is a local-first environment-variable store with an untrusted sync
service. Clients encrypt all secret material before it leaves a device. The
release deliberately has a small operational surface: one CLI, one HTTP sync
service, one encrypted local identity file, and an optional macOS browser
bridge that never moves a secret through extension background state before a
user selects a target field.

## Goals

- Keep variable names and values confidential from the sync service.
- Let several explicitly approved devices use the same vault.
- Inject values directly into child processes without creating a `.env` file.
- Track rotation policy and make overdue secrets visible without exposing them.
- Keep development and self-hosted production deployments easy to reproduce.
- Use only the Go standard library in the security-sensitive core.

## Non-goals for the first release

- Protect a secret after it has been injected into a compromised process.
- Recover a vault if every approved device and every recovery copy is lost.
- Automatically log in to third-party dashboards and rotate credentials.
- Hide record count, update time, device count, or ciphertext sizes.
- Replace a managed KMS/HSM for high-assurance production workloads.

## Trust and threat model

The sync service is treated as honest-but-curious and potentially
compromisable. It can delete, replay, or withhold ciphertext, but it cannot
decrypt records or enroll a device without an approved device's signature.
TLS remains required in production to reduce metadata leakage and active
network attacks.

Each device owns two key pairs:

- Ed25519 signs every mutating and secret-reading API request.
- X25519 receives a wrapped copy of the vault key during enrollment.

The local identity file is encrypted with AES-256-GCM. Its key is derived from
a passphrase with PBKDF2-HMAC-SHA-256 using a per-file random salt and 600,000
iterations. This is a portable baseline, not a substitute for a platform
keychain or hardware-backed key. File permissions are restricted to `0600`.

## Record encryption

Each vault has a uniformly random 256-bit vault key. A record identifier is:

```
base64url(HMAC-SHA-256(vault_key, "envbank.record.id.v1" || name))
```

The record payload contains the name, value, rotation policy, creation time,
rotation time, revision, and exact browser-origin allowlist. It is serialized
as JSON and encrypted with a new random nonce under AES-256-GCM. The vault ID
and record identifier are bound as additional authenticated data. Old records
decode with an empty allowlist and therefore cannot be browser-filled.

Optimistic revisions prevent silent concurrent overwrites. The server retains
only the newest ciphertext and therefore does not provide rollback protection
on its own; signed append-only audit checkpoints are a future hardening item.

## Device enrollment and pairing invitations

Production CLI enrollment retains the original indefinite `/enrollments`
workflow for compatibility. The disposable pairing lab uses version-1
`/invitations`, whose state machine is:

```text
pending ──approve──> approved
        ├─cancel───> cancelled
        ├─reject───> rejected
        ├─server───> expired
        └─5 failures> attempts_exhausted
```

The new device generates fresh signing and wrapping key pairs locally and
publicly creates an invitation. The server assigns the device ID and uses its
own clock to set `expires_at = created_at + 10 minutes`; `now >= expires_at`
expires the invitation. An active device verifies the complete fingerprint,
wraps the vault key to the intended X25519 key, and signs approval. Approval is
the one-time consumption point, while status and intended-device envelope
retrieval are retryable.

Approval, rejection, requester cancellation, expiry, and attempt exhaustion
are terminal. The first terminal transition committed under SQLite's immediate
transaction wins. A confirmed cancellation therefore prevents approval; if
approval commits first, cancellation receives the authoritative approved
state as a conflict. Status exposes no envelope to an inspecting active device;
only the intended device receives it after approval.

Five failed, validly signed transition attempts exhaust a still-pending
invitation. Counted failures are malformed transition data, an incorrect actor
role, or a version/device/fingerprint/envelope binding failure. Status polls,
invalid or unknown signatures, stale timestamps, replayed nonces, network
failures, and retries against a terminal invitation do not consume attempts.
The existing five-minute signed-request timestamp window is independent of the
ten-minute invitation lifetime.

Invitation-created enrollment rows cannot be approved through the legacy
endpoint. Existing enrollment rows are not backfilled, expired, or otherwise
converted.

The wrapping envelope uses ephemeral X25519, an HMAC-SHA-256 extract/expand
construction, and AES-256-GCM with vault and device IDs as authenticated
context.

The proposed QR-first presentation, its trust boundaries, and the isolated
developer stress lab are documented in [device pairing](device-pairing.md).

## Recovery artifacts

Version-2 recovery artifacts contain sorted snapshots of decrypted
`SecretRecord` values and encrypted vault-object plaintext, including their
source sync revisions, inside a single AES-256-GCM payload. Version-1
record-only artifacts remain readable. Artifacts deliberately exclude the
vault key, device private keys, provider credentials, and server authorization
or access-history data. A separate recovery
passphrase derives the 256-bit artifact key using PBKDF2-HMAC-SHA-256, a random
16-byte salt, and 600,000 iterations. The format version, KDF identifier, salt,
and iteration count are additional authenticated data.

Offline verify, list, get, and child-process execution decrypt only the local
artifact. Synchronized restoration creates a new server vault, random vault
key, and device identity; it re-encrypts records under the new vault ID and
resets their optimistic revisions to 1. The encrypted local config is saved
before uploads and bound to the exact artifact digest. Resume authenticates to
the configured replacement service, verifies already uploaded records and
vault objects with the new vault key, skips identical state, resets restored
sync revisions to 1, and fails closed on changed or unrelated target state.

This is a new authorization domain. Recovery cannot reproduce old device
authorization, revocation history, replay state, access events, or the original
vault key.

## Provider-neutral rollout state

Provider automation crosses a narrow local adapter boundary. Each adapter
declares create, metadata-read, update, validate, revoke, idempotency, and
masked-presence capabilities. A write request exposes its secret bytes only to
an in-process callback; formatting is redacted, JSON encoding is rejected, and
the request is cleared after the adapter returns. Arbitrary provider errors and
response bodies are discarded in favor of bounded status, code, and retry
metadata. Provider evidence accepts only bounded identifiers, canonical UTC
timestamps, presence, and explicit verified-or-limited results.

Metadata-only planning binds the manifest digest, current encrypted snapshot
revision, exact logical record revisions, immutable provider identity, project,
environment, service IDs, ordered actions, and a 15-minute expiry into a
digest-addressed encrypted plan. A new apply must use an unexpired plan and
revalidate every binding. It requires an interactive confirmation immediately
before the first write and a separate confirmation before revoke actions.

Each action is durably checkpointed as `in_flight` before calling the adapter
and as `committed` immediately after valid provider evidence returns. Resume
skips committed actions. An ambiguous write is retried only when the provider
accepts an idempotency key or the exact write is itself idempotent; otherwise metadata inspection must
prove committed or absent state, and an unprovable outcome stops for explicit
reconciliation. A confirmed operation may resume after its plan expires, but
all identity, target, snapshot, and record bindings remain mandatory. Final
verification distinguishes verified presence from provider limitations and
stops at `ready-to-deploy`; the engine has no deployment behavior.

The Railway adapter accepts only a project-scoped token stored under
a bundle-scoped macOS Keychain account. `railway bind` first uses Railway's
`projectToken` query to prove the immutable project and environment IDs, then
resolves the manifest's exact `postgres`, `migrator`, `api`, and `web` names to
service IDs before storing the credential. Its read document resolves project,
environment, and service metadata. It does not use the
documented Railway variable query because that query returns values rather than
names-only metadata.

Consequently, `railway plan` marks every desired-present and desired-absent
name `unverifiable`, binds record-backed names to exact encrypted snapshot
revisions, and saves a 15-minute encrypted `names-only` plan. Record-backed
values and manifest-declared public constants become ordered upsert actions;
unresolved public imports and intended absence remain non-actions. Apply
revalidates every binding, requires an interactive confirmation, and issues
only one `variableUpsert` at a time with `skipDeploys: true`. The exact upsert
is safely repeatable after an ambiguous response, while committed actions are
never repeated.

Railway verification re-resolves immutable identity and service IDs, validates
the current local snapshot, and reports committed local operation evidence.
Provider presence remains `unknown` because reading Railway variables would
also read values. Staged writes and deployed state are reported separately;
there is no delete, staged-change commit, deploy, redeploy, restart, domain,
service-create, or service-delete GraphQL document.

## Device revocation

Approved devices have an optional server-side revocation timestamp. Device
listing includes public identity metadata and active/revoked state, but no
vault key, encrypted record contents, or other secret material. A revocation
authenticates the caller, counts active devices, marks the target revoked, and
deletes the target's stored replay nonces in one immediate transaction. The
same transaction refuses to revoke the final active device, so concurrent
cross-revocation through multiple service processes still leaves one device
active.

Authentication verifies a known identity's signature before applying device
state authorization. A valid signature from a pending or revoked identity can
therefore be truthfully attributed while access remains denied. Invalid
signatures may be associated with an existing claimed identity, but an unknown
attacker-provided identity is never copied into access history. Pending
enrollments may access only their own enrollment status; an approved
enrollment-status request also requires the corresponding device to remain
active. Revoked identities and wrapped enrollment envelopes remain stored for
history, and the local CLI deliberately preserves its encrypted config and
Keychain entry.

This is access revocation, not cryptographic recall. A revoked device may retain
the vault key and ciphertext it obtained earlier, so it can continue to decrypt
that cached material offline. Vault rekeying and record re-encryption are out
of scope for this workflow.

## Access events

The server maintains a privacy-preserving operational history for recognized
enrollment, invitation, device-management, record, and access-event routes. Successful
operations, verified business rejections, authentication failures, and public
enrollment requests receive random public event IDs and a server-side sequence
for deterministic newest-first pagination. Events contain only the vault,
timestamp, operation, outcome, bounded reason, optional known acting identity
and verification state, and optional target device identity.

Events never contain request bodies, ciphertext, record identifiers, secret
names or values, signatures, nonces, IP addresses, forwarded headers, or
User-Agent strings. Vault creation, health checks, unknown routes, and requests
for nonexistent vaults are omitted. The service prunes each vault
transactionally after 90 days and maintains independent caps of 10,000
verified-identity events and 2,000 unverified events, so unauthenticated traffic
cannot evict verified history.

Nonce consumption, a verified operation or policy rejection, and its event
commit together. A verified read or mutation fails closed if its event cannot
be persisted. Accepted public enrollment requests also commit with their event;
unverified authentication failures and rejected public enrollment requests
retain their original response when event persistence is unavailable.

This history supports operator review and future risk scoring. It is not
encrypted, signed, append-only, tamper-proof, or rollback-resistant. Signed
audit checkpoints remain a separate later hardening item.

## Rotation workflow

Records may specify `rotate_every_days`. `envbank due` reports names and age,
never values. `envbank rotate --bytes N NAME` retains the original
cryptographically random URL-safe token workflow. `envbank generate NAME`
instead creates a random-character password from individually selected fixed
character classes. It uses rejection sampling rather than modulo reduction,
guarantees every enabled class, performs a cryptographic Fisher-Yates shuffle,
stores the result, and prints only the record name and revision. Integration
with computer-use automation should follow a two-phase adapter:

1. Create or request the new credential at the provider.
2. Commit the new value to EnvBank, validate it, and revoke the old credential.

Provider adapters and UI automation must never place credentials in model
prompts, screenshots, logs, shell arguments, or clipboard history. That
automation is intentionally left outside the core until provider-specific
flows can meet those requirements.

## Browser boundary

The Manifest V3 extension has only `activeTab`, `scripting`, and
`nativeMessaging` permissions. It declares no host permissions and uses no
extension storage, clipboard, remote code, telemetry, or incognito access.
Only exact HTTPS origins and HTTP loopback origins are eligible. Wildcards,
paths, credentials, opaque origins, and browser-internal pages are rejected.

On macOS, the native host retrieves the local passphrase from a generic
password Keychain item scoped to the vault and device. The item uses
`WhenUnlockedThisDeviceOnly` accessibility and user-presence access control.
The passphrase unlocks the encrypted device config once per host process and is
then zeroed. Decrypted device material and the vault key remain only in native
host memory until the port disconnects, the user locks it, or ten minutes pass
without a native request.

Listing returns record names, revisions, allow status, and rotation metadata,
never values. Approval and denial use the normal encrypted-record optimistic
revision update. A fill is a separate request made only after the user chooses
a variable and clicks an eligible top-frame field. Immediately before
returning the value, the native host refetches current ciphertext and rechecks
the exact origin. Navigation, origin changes, iframe targets, unsupported
fields, Escape, disconnect, and the 30-second timeout cancel the operation.

Password generation is an additive native protocol v1 action. The popup sends
only the name, policy, confirmed exact origin, and expected revision. The
native host generates and encrypts the password, then returns redacted record
metadata. New records begin at revision 1. Replacement requires the exact
listed revision, preserves creation time, rotation policy, and existing origin
permissions, and adds the confirmed origin in the same optimistic write. The
extension revalidates the tab origin before storage and again before arming the
field selector. A navigation race after storage cannot undo the write, so the
UI explicitly says the password remains stored and authorized.

The extension uses the platform input/textarea value setter and emits `input`
and `change` events for framework compatibility. Once inserted, the value is
part of the page: page scripts, extensions with page access, and a compromised
site may read it. Browser filling does not protect against that page-level
threat.

## Server persistence and deployment

The service stores ciphertext, public metadata, invitation lifecycle state,
and bounded access events in a normalized SQLite database. Enrollment or
invitation approval, optimistic record revision checks, replay nonce
consumption, and verified access-event persistence execute
in the same `BEGIN IMMEDIATE` transaction as their associated operation. WAL
journaling and a busy timeout allow multiple service processes on one host to
share the database safely. SQLite files must remain on a local filesystem;
multi-host deployments should use a client/server database adapter instead.

An existing version-1 JSON state file is imported transactionally on first
startup, and the source is retained as a `.json.bak` recovery copy. Version-1
and version-2 SQLite databases migrate through version 3 to version 4;
version-3 events retain their sequence and contents. Existing devices remain
active, legacy enrollments are not backfilled into invitations, and older
databases without event history start empty. Production must
still follow the [single-host production runbook](production-deployment.md):
place the service behind TLS on an authenticated private network, restrict its
published port to loopback, and back up the database. The HTTP server limits
headers to 16 KiB, applies bounded read/write/idle timeouts, marks API responses
`no-store` and `nosniff`, and allows ten seconds for graceful SIGINT/SIGTERM
shutdown.

## Cryptographic agility

Every encrypted object, local identity, and recovery artifact carries an
explicit format version. Ciphertext formats are intentionally distinct for
local identity, vault records, device envelopes, and recovery snapshots.
Algorithm or KDF changes should add a version and a migration rather than
reinterpret existing bytes.
