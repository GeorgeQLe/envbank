# Agent-operated setup, owner input and cross-device secret relay

Status (November 4, 2026): **design accepted. Read-only planning and status are
implemented (`envbank setup plan|status`); apply, the desktop-host input
provider, hosted and local-only modes, and the relay are not built yet.**

Goal: an agent can install, set up, store and sync EnvBank end to end, while
every secret (vault passphrase, recovery passphrase, values) is typed by the
owner on an owner-held surface and reaches EnvBank without ever passing
through, or being observable by, the agent.

## Owner decisions

| Topic | Decision |
| --- | --- |
| Sync | Support all three modes: `local_server` (loopback `envbank serve` as an owner-approved launchd agent), `hosted` (the EnvBank Cloudflare service) and `local_only` (single host, no server). |
| Storage | Split layout. Vault ciphertext lives in a dedicated private directory on an ownership-enforcing volume, bound to that volume's UUID; unplugging the volume makes the vault unavailable. The device identity (passphrase-encrypted config) lives on an internal volume. Recovery artifacts go on a different backup volume. |
| Owner input | A trusted desktop host's secure input surface is the primary path. The agent broker's terminal is the fallback. |

## Flow

```text
 agent ──setup plan / status (read-only)──▶ envbank CLI / MCP
   │
   └──setup apply (plan)──▶ owner-held broker ──confirm / secret entry──▶ owner surface
                                 │                                      (desktop host or broker terminal)
                                 ├─ prepare private dirs (UUID-checked)
                                 ├─ install service (owner confirms)      local_server
                                 ├─ create vault (passphrase from owner surface)
                                 ├─ recovery export (separate recovery passphrase)
                                 ├─ write non-secret layout.json
                                 └─ unlock itself with the new vault ⇒ normal broker
```

`envbank agent-broker` starts in **setup mode** when the device has no
identity. Agents propose plans; the broker shows each plan to the owner,
performs it, and then unlocks the vault it just created without asking for the
passphrase again. Secret entry never happens in the agent's terminal: a
prompt there would be agent-observable.

### Checks before any change (`setup plan`, implemented)

- Paths must be absolute, normalized and free of symlinks through every
  existing component.
- The volume must enforce ownership (`GlobalPermissionsEnabled` and no
  `MNT_IGNORE_OWNERSHIP`) and be writable. Its UUID is recorded.
- Existing directories must be 0700 and owned by the owner.
- The device identity must be on an internal volume, and must not already
  exist.
- The backup must be on a different volume from the vault.
- Every refusal is a fixed, caller-safe reason.

## Desktop-host owner-input provider (to build)

The provider is the trusted desktop app (for example the owner's agent-host
app) that shows a native secure field and returns the value directly to
EnvBank. **The provider must be authenticated, not merely same-user.** A
same-user agent can create a socket or window first. An impostor *supplying*
a passphrase would let the agent choose the vault passphrase.

- **Authenticated channel.** The broker dials the provider. The provider
  proves its identity in two ways:
  1. The peer process's code signature, checked against a Team ID and
     designated requirement the owner pins once in the broker terminal.
  2. A per-pairing key, also established in the broker terminal.

  Every request is bound to a fresh nonce, purpose, plan digest and expiry.
- **Request:** `{v, nonce, purpose, title, detail, min_bytes, confirm, plan_digest, expires_at}`.
  The provider renders `detail` sanitized, collects the value twice where
  `confirm` is set, and returns it once. The provider never logs, caches or
  echoes it. The broker zeroes its copy after use.
- **No-leak acceptance.** Before the provider is enabled, the secure window
  must pass the native capture harness against an installed build on the
  release OS:
  - accessibility exposes no value (secure text field) during or after entry;
  - screen capture and OCR of the window show no characters;
  - input from other processes cannot type into, or read, the field;
  - it never uses the clipboard;
  - nothing reaches logs or crash reports.

  Until that passes, the terminal fallback is the supported path.

## Cross-device secret relay (to build)

To type a password on one device (for example a phone) and use it on another,
the relay reuses EnvBank device keys. Each enrolled device already has an
X25519 wrapping key, verified by fingerprint at pairing.

1. **Target.** The target's owner surface requests a value for one sink and
   shows a short authentication code (SAS) derived from the request.
2. **Sender.** The sending device shows the same code. The owner confirms it
   matches and types the value into a secure field.
3. **Sealing.** The sender seals the value to the target device's wrapping
   key. The sealed message is bound to the target device, request nonce,
   sink, expiry (a few minutes) and single use.
4. **Transport.** The sync service carries only the sealed message. It cannot
   read, replay or redirect it, and an expired or reused message is refused.
5. **Delivery.** The target decrypts in its owner-held process and delivers
   **only to an EnvBank sink**: vault ingest under a name, the vault
   passphrase prompt, or a protected browser fill.

The relay never types into arbitrary apps and never uses the clipboard: both
expose the value to whatever has focus, and arbitrary native injection stays
unsupported until a separately qualified input boundary exists.

## Remaining units

1. `setup apply` through the broker in setup mode (`local_server` end to end),
   including launchd install, vault creation without a passphrase file,
   recovery export and the self-unlock.
2. Hosted mode via the existing Cloudflare commands, with owner confirmations.
3. Desktop-host provider protocol, authentication and no-leak qualification.
4. Cross-device relay.
5. `local_only` through the desktop host's local-vault adapter.
