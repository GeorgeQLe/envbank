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

## Device enrollment

1. A new device generates signing and wrapping key pairs locally.
2. It uploads only its public keys as a pending request.
3. An approved device fetches the request, verifies its fingerprint out of
   band, wraps the vault key to the pending X25519 public key, and signs the
   approval.
4. The new device authenticates with its pending Ed25519 key and downloads the
   wrapped vault key.
5. The new device decrypts the envelope locally and becomes active.

The wrapping envelope uses ephemeral X25519, an HMAC-SHA-256 extract/expand
construction, and AES-256-GCM with vault and device IDs as authenticated
context.

## Rotation workflow

Records may specify `rotate_every_days`. `envbank due` reports names and age,
never values. `envbank rotate NAME --generate` creates a cryptographically
random value, stores it, and optionally prints only a confirmation. Integration
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

The extension uses the platform input/textarea value setter and emits `input`
and `change` events for framework compatibility. Once inserted, the value is
part of the page: page scripts, extensions with page access, and a compromised
site may read it. Browser filling does not protect against that page-level
threat.

## Server persistence and deployment

The initial service uses an atomically replaced JSON state file protected by an
in-process mutex. It is suitable for a single-process personal/team deployment.
Production must place it behind TLS, restrict network access, back up the state
file, and run exactly one writer. A transactional database adapter is the next
step for multi-instance service operation.

## Cryptographic agility

Every encrypted object and local identity carries an explicit format version.
Ciphertext formats are intentionally distinct for local identity, vault
records, and device envelopes. Algorithm changes should add a version and a
migration rather than reinterpret existing bytes.
