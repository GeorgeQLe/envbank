# Owner-input provider protocol v1 (`envbank.owner-input/v1`)

Status (November 4, 2026): **specification; client and provider in progress;
not qualified.**

A desktop host app (the *provider*) collects owner secrets: the vault
passphrase, the recovery passphrase, and later values for ingest. It hands each
one directly to the owner-held EnvBank broker (the *client*). Agents never
see the request contents, the value or the channel. The broker's own
terminal remains the fallback whenever no qualified provider is paired.

## Threat model

The adversary is a coding agent running as the **same macOS user**, with a
shell, computer use and the ability to create files, sockets, windows and
processes. It does not have the vault passphrase. It wins if it:

- learns any entered value;
- **supplies** a value the broker accepts as owner-entered (for example
  choosing the vault passphrase);
- gets the owner to enter a value for a purpose other than the one shown.

Because the agent can read any file the user can, **no on-disk secret can
authenticate the provider**. The provider's identity is its **code
signature**.

## Transport

- **Socket.** The provider listens on a Unix socket at
  `~/Library/Application Support/EnvBank/owner-input/provider.sock`. Its
  directory must be 0700 and owned by the user, and the socket 0600.
- **Direction.** The broker always dials, one request per connection.
- **Framing.** One JSON object per line, at most 16 KiB per frame. The value
  is base64 inside the response frame.

## Mutual authentication (both directions, before any value moves)

**Both ends must authenticate each other.** If the provider cannot identify
its requester, a same-user agent can dial it, request a "vault passphrase"
prompt, and receive what the owner types. That is a direct leak. Node
exposes no peer PID, so an Electron provider needs a small native helper
that reads `LOCAL_PEERPID` and validates the requester's code signature: a
pinned EnvBank Team ID with hardened runtime. Until requester authentication
is implemented, the provider must stay disabled for real secrets. An
on-screen request code is advisory only.

## Provider authentication (broker side, before sending anything)

1. Peer uid equals the user (`LOCAL_PEERCRED`).
2. Peer pid (`LOCAL_PEERPID`): its executable is validated with the Security
   framework (`SecCodeCreateWithPID` / `SecStaticCodeCheckValidity` against the
   running code, not a path re-read):
   - the signature is valid and the **Team ID equals the pinned Team ID**;
   - the hardened runtime is on;
   - the code does not allow `get-task-allow`, DYLD environment variables or
     unsigned executable memory;
   - the bundle identifier equals the pinned one.
3. For Electron providers, the app must ship with the
   `RunAsNode`, `EnableNodeOptionsEnvironmentVariable` and
   `EnableNodeCliInspectArguments` fuses **off** and
   `EnableEmbeddedAsarIntegrityValidation` / `OnlyLoadAppFromAsar` **on**.
   Otherwise the genuine signed binary could be started by an agent as a
   generic runtime. The broker records the fuse state the provider reports
   at pairing. The no-leak qualification verifies it on the installed build.
4. **Pinning.** The pin (Team ID, bundle ID) is set once by the owner in the
   broker terminal: `envbank agent-broker --owner-input pair`. Pairing shows
   the peer's signing identity and asks for confirmation. It also shows a
   6-digit code that the provider displays in its own window, which binds
   the confirmation to the window the owner can see.
5. **Development builds.** Unsigned or ad-hoc-signed providers are accepted
   only with `--owner-input-dev-unqualified`. The broker then labels every
   request and status `unqualified` and refuses to use the provider for the
   vault passphrase of an existing vault.

If authentication fails, the broker sends nothing and falls back to the
terminal.

## Pairing frame

Broker → provider: `{"v","nonce","pairing_code":"6 digits","expires_at"}`.
The provider shows the code in its own window and answers `displayed` with
its self-reported fuse and hardened-runtime state. The owner confirms the code
in the broker terminal.

## Messages

Request (broker → provider):

```json
{"v":"envbank.owner-input/v1","nonce":"<32 hex>","purpose":"new_vault_passphrase|recovery_passphrase|unlock_passphrase|secret_value",
 "title":"<=80 chars","detail":"<=300 chars, untrusted, render as plain text","subject":"vault/secret NAME or empty",
 "min_bytes":12,"max_bytes":1024,"confirm":true,"expires_at":"RFC3339 (<=120 s ahead)"}
```

Response (provider → broker):

```json
{"v":"envbank.owner-input/v1","nonce":"<same>","outcome":"entered|declined|cancelled|expired|busy","value":"<base64, only when entered>"}
```

Rules:

- `max_bytes` is at most 4096, so a base64 response always fits in a 16 KiB
  frame.
- `cancelled` means the owner cancelled or the connection dropped;
  `declined` means the provider refused or failed.

- **Requests.** The provider rejects any request with unknown fields, the
  wrong version, an oversized frame or an expired timestamp. It handles one
  request at a time and answers `busy` otherwise.
- **The prompt window.** The provider shows `title`, `subject` and `detail`
  as **plain text**, with no markup or links. `detail` is agent-influenced
  (for example a reason), so it is labelled "requested by an agent".
- **Entry.** With `confirm`, the value is entered twice and compared in the
  provider. Length is checked against `min_bytes`/`max_bytes` before
  returning.
- **Handling the value.** The value exists only in the provider's main
  process memory long enough to write the response. It is never logged,
  persisted, sent to a renderer that hosts agent-reachable content, put on
  the clipboard, or included in crash reports. The provider zeroes its
  buffers afterwards (best effort).
- **Broker checks.** The broker accepts a response only for the outstanding
  nonce, before expiry, from the same authenticated connection, and zeroes
  the value after use.

## Provider UI requirements (no-leak)

- **The window.** A dedicated owner-only window that no agent tool or browser
  broker can target. It has no web content from any origin, DevTools are off,
  and `setContentProtection(true)` is set as defense in depth.
- **The field.** A secure text field (`<input type="password">` in an isolated
  renderer that contains only this form, or a native `NSSecureTextField`).
  No autofill, spellcheck or IME candidate window may echo the value.
- **The window shows:**
  - the purpose;
  - the subject;
  - the agent-supplied detail, clearly labelled;
  - an explicit **Cancel**.

  Focus is not taken silently: the window comes to the front with a visible
  indicator.

## Qualification (required before `qualified` status)

Against the **installed, signed** provider on the release macOS build, using
the native capture harness:

- **Accessibility:** a walk with forced `AXManualAccessibility` and
  `AXStringForRange` exposes no value (or partial value) during entry, after
  submit and after cancel.
- **Capture:** ScreenCaptureKit window capture plus OCR shows no characters
  of the value.
- **Input:** synthetic input from another process cannot read the field.
  Any typing it achieves is distinguishable from owner typing, or the
  provider refuses when not frontmost.
- **Other channels:** pasteboard history is unchanged, and log, crash and
  diagnostic greps are free of the sentinel.
- **Impersonation:** a same-user impostor socket, an unsigned copy, the
  genuine binary launched with Node/inspect flags, and a different Team ID
  are all refused by the broker, which falls back to the terminal.

Until every check passes on the installed build, the provider status is
`unqualified` and the terminal remains the supported path.
