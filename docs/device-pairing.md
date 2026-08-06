# QR-first device pairing

EnvBank presents its versioned invitation protocol as a QR-first pairing flow
without turning the QR code into an access credential. The interaction is
inspired by the convenience of [Brave Sync's QR/code
setup](https://support.brave.app/hc/en-us/articles/360021218111-How-do-I-set-up-Sync),
but not by Brave's authorization model. Possession of an EnvBank pairing
payload is insufficient to join a vault.

## Versioned invitation protocol

The wire cryptography and canonical pairing payload remain unchanged, and the
production enrollment CLI continues to use the legacy compatibility API. The
disposable lab now uses server-enforced version-1 invitations end to end:

1. The new device creates fresh Ed25519 signing and X25519 wrapping key pairs.
2. It submits the public keys as a pending invitation with a server-assigned
   ten-minute expiry.
3. An already approved device imports a locator, fetches that pending request
   from the server, checks the authoritative state/expiry, and recomputes the
   fingerprint over both public keys.
4. A human compares and types the complete 16-hex-character (64-bit)
   fingerprint. No shortened code or word phrase is authentication.
5. The approved device wraps the in-memory vault key specifically to the
   pending X25519 key and signs a version/device/fingerprint-bound approval.
6. The new device signs its own status request, downloads the envelope, and
   unwraps it locally. The key is never rendered.

The screens mirror these roles. The new-device pane creates a named
synthetic identity, shows a QR and copyable payload, then polls or refreshes for
approval. The approved-device pane imports the payload, displays the grouped
fingerprint, requires the full value to be typed, and performs approval. A
final success state proves both devices hold the same vault key without
displaying it. The server also supports requester cancellation, active-device
rejection, terminal-state rendering, and five counted transition failures.

## Transfer format

Version 1 is:

```
envbank-pairing:v1:<base64url-without-padding(canonical-json)>
```

The canonical JSON object has exactly these ordered fields: `server`,
`vault_id`, `device_id`, `fingerprint`, and `created_at`. It contains no bearer
secret, private key, vault key, signature, nonce, envelope, record identifier,
or ciphertext. Decoders reject payloads over 8 KiB, unknown fields,
non-canonical JSON or base64url, malformed IDs, fingerprints other than 16
lowercase hexadecimal characters, invalid RFC 3339 timestamps, and unsupported
versions.

The server must be a normalized HTTPS origin or an HTTP loopback origin. User
information, paths (including a trailing slash), queries, and fragments are
invalid. The approving side treats every field as untrusted: server and vault
must exactly match its own context, and device ID, creation time, fingerprint,
and the recomputed fingerprint over both server-returned public keys must all
agree.

QR images are generated locally with the pinned pure-Go `go-qrcode` encoder.
The browser obtains the current session's QR from a no-store endpoint; pairing
data is never placed in a URL query.

## Threat boundaries

The QR is a transport convenience, not proof of physical proximity or device
ownership. A copied or photographed payload can reveal the loopback lab
address, random vault and device IDs, creation time, and public-key
fingerprint. It cannot authenticate, decrypt data, or approve an enrollment.
Explicit fingerprint verification remains necessary to detect payload or
server substitution and a compromised transport.

TLS is mandatory for non-loopback production service origins. The approved
device must trust its configured server and still verify the entire
fingerprint through a channel appropriate to its threat model. A compromised
approved device can approve an attacker because it already holds the vault
key; QR design cannot repair that trust failure.

Revocation stops future authenticated synchronization but cannot recall a
vault key or ciphertext already held by a device. Removing a device therefore
does not provide cryptographic erasure. Vault-key rotation and record
re-encryption remain separate future work.

The server clock alone decides invitation expiry: creation plus ten minutes,
with equality already expired. UI countdowns are advisory and periodically
refresh authoritative status. Approval, cancellation, rejection, expiry, and
attempt exhaustion are mutually exclusive terminal outcomes; the first
committed transaction wins. The UI reports cancellation only after the server
confirms it.

Only malformed, validly signed pending transitions, incorrect actor roles, and
version/device/fingerprint/envelope binding failures consume the five-attempt
budget. Polling, bad signatures, stale timestamps, nonce replay, network
failure, and terminal retries do not. Legacy production enrollments remain
indefinite and are intentionally outside this lifecycle; invitation-created
rows cannot use legacy approval.

## Cross-platform transport model

The pairing protocol and transfer format are platform-neutral. QR, text,
AirDrop, a file, or a future retrieval code are transports for the same public
payload; they are not separate authorization models. Adding a transport must
not change fingerprint verification, approved-device signing, vault-key
wrapping, invitation consumption, or audit behavior.

The universal baseline should be QR, copy/paste or stdin, and a versioned
`.envbank-pairing` file. Platform integrations sit above that baseline:

| Transport | Windows | macOS | iPhone | Headless VPS | Primary drawback |
| --- | --- | --- | --- | --- | --- |
| QR | Display or scan | Display or scan | Best scanning experience | Terminal QR or generated PNG | Cameras and screen sharing can copy metadata |
| Text/stdin | Native UI or CLI | Native UI or CLI | Paste into app | Best CLI fallback | Chat, clipboard, and shell history can retain metadata |
| Pairing file | Open or import | Open, import, or AirDrop | Files/share sheet/AirDrop | Read from stdin or an explicit file | File copies can persist after enrollment |
| Native deep link | Requires desktop handler | Requires desktop handler | Requires installed app | Not recommended | Links may be forwarded and handlers can be spoofed |
| Retrieval code | Future | Future | Future | Strong cross-platform convenience | Adds an online relay and guessing/abuse surface |
| Local discovery | Optional | Optional | OS-constrained | Often unavailable across networks | Network attackers can advertise misleading devices |
| Bluetooth or NFC | Optional and device-dependent | Device-dependent | OS-constrained | Usually unavailable | Complex permissions and inconsistent platform support |

AirDrop is therefore an Apple-only convenience for moving the standard pairing
file or deep link. It cannot be the only documented path. A Windows-to-iPhone
or VPS-to-iPhone pairing should normally use QR; two headless systems should
use stdin, an explicitly transferred file, or eventually a retrieval code.
Production pairing must not require exposing a VPS web port.

Transport capability should be detected locally without sending a platform or
device inventory to the sync service. Unsupported choices remain visible only
when that helps explain why instructions differ; they must not appear as
broken actions.

## Communicating choices and drawbacks

The product should ask first where the other device is: **phone or tablet**,
**computer**, or **headless/server**. It can then recommend a transport without
making the user understand protocol terminology:

- Phone or tablet: recommend **Scan QR**.
- Computer: recommend **QR** when a camera is available, then **pairing file**
  or **copy text**.
- Headless/server: recommend **terminal QR**, then **stdin/file**; later,
  recommend an expiring retrieval code when direct transfer is inconvenient.
- Apple-to-Apple: offer **AirDrop** as an additional convenience, labeled
  “Apple devices only.”

Each choice card must display the same four pieces of information before it is
selected:

1. **Works with:** concrete supported device types and operating systems.
2. **What is shared:** server address, random vault/device IDs, creation time,
   and public-key fingerprint; never a vault key or private key.
3. **What can go wrong:** the transport-specific persistence, observation,
   forwarding, spoofing, or relay risk.
4. **Still required:** compare the complete 16-character fingerprint and
   approve from an already active device.

Use stable safety labels rather than vague colors:

| Label | Meaning | Examples | Required presentation |
| --- | --- | --- | --- |
| **Recommended** | Direct, short-lived interaction with minimal persistence | QR scanned from the other device's screen | Preselected when compatible; normal explanation |
| **Private channel** | Safe when the operator controls the channel, but copies may remain | stdin, SSH-transferred pairing file, AirDrop | State where a copy may remain and offer cleanup instructions |
| **Metadata may persist** | Common tools can retain or forward the public locator | clipboard, chat, email, deep link | Warning beside the action, not hidden in help text |
| **Advanced / larger attack surface** | Depends on relay or discovery infrastructure | retrieval code, LAN discovery, Bluetooth | Off by default until prerequisites pass; explicit confirmation |

These labels describe transport risk, not vault authorization strength. The UI
must not call a copied payload “secret,” claim that proximity proves identity,
or imply that a green label makes fingerprint verification optional.

For **Metadata may persist** and **Advanced** choices, require an unchecked
acknowledgement immediately beside Continue:

> I understand this method can expose pairing metadata. I will compare the
> complete fingerprint before approving the device.

Do not use a generic “Are you sure?” dialog. The warning must name the actual
drawback and a safer alternative, retain keyboard and screen-reader access, and
avoid prechecked acknowledgements. When a future retrieval code is used, show
its exact expiry, remaining attempts when appropriate, one-time status, and a
visible Cancel invitation action. Never describe a short retrieval code as the
fingerprint or as sufficient approval.

After completion, show transport-specific cleanup: clear a copied payload,
delete exported pairing files, close terminal QR output, and cancel any
unconsumed invitation. Cleanup improves privacy but does not substitute for
server-side expiration and one-time consumption.

## Cross-platform implementation roadmap

The milestones are ordered security and product gates.

### Phase 0 — protocol and lab baseline

- [x] Define and validate the canonical version-1 public pairing payload.
- [x] Exercise real enrollment, approval, wrapping, acceptance, QR rendering,
  state conflicts, concurrency, and local-web defenses in disposable storage.
- [x] Document the legacy enrollment lifecycle gap that Phase 1 preserves only
  for production CLI compatibility.

Exit gate: the lab remains unable to load normal configs, Keychain entries,
recovery artifacts, production vaults, or non-loopback services.

### Phase 1 — invitation lifecycle (complete)

- [x] Introduce a separate versioned invitation protocol without changing existing
  enrollment compatibility.
- [x] Enforce server-side expiry, explicit cancellation/rejection, atomic
  single-use consumption, attempt limits, and auditable terminal states.
- [x] Bind invitation use to the intended vault and pending device identity.
- [x] Define clock-skew behavior and make cancellation win safely against approval
  races.

Exit gate: concurrency, replay, expiry, cancellation, revocation, rollback, and
multi-process database tests pass; no UI claims an invitation was cancelled
until the server confirms it.

### Phase 2 — universal CLI and file transport

- Add stdin import/export so payloads need not enter shell arguments or
  histories.
- Add a MIME type, safe filename convention, strict permissions, and
  versioned parser for `.envbank-pairing` files.
- Add terminal QR output and optional local PNG creation without opening a
  public listener.
- Provide equivalent command examples for Windows shells, macOS terminals, and
  Linux VPS sessions.

Exit gate: Windows, macOS, and Linux integration tests consume identical test
vectors; private keys, vault keys, authentication headers, and secret values
never enter files, QR data, logs, errors, or process arguments.

### Phase 3 — transport chooser and education

- Build the device-type question, ordered recommendations, choice cards,
  stable safety labels, acknowledgements, and post-pair cleanup guidance.
- Keep the selected transport and current state visible throughout the flow.
- Provide “Why is fingerprint verification still required?” in context.
- Test mismatch, expiry, cancellation, offline, lost-file, forwarded-link, and
  abandoned-flow messaging.

Exit gate: accessibility and comprehension studies confirm that users can
identify what is shared, why approval is still required, and which option has
greater persistence or infrastructure risk.

### Phase 4 — native platform adapters

- macOS and iPhone: share sheet, pairing-file association, approved deep links,
  camera permission, and AirDrop instructions.
- Windows: pairing-file association, desktop deep-link handler, camera
  capability fallback, and CLI parity.
- VPS/Linux: terminal-first instructions, stdin/file import, SSH-safe examples,
  and no assumption of GUI, camera, Bluetooth, or inbound connectivity.
- Verify that unknown deep-link schemes and competing file handlers cannot
  silently approve or bypass the import review screen.

Exit gate: every supported platform can fall back to the universal file or text
path, and platform convenience features do not alter cryptographic state before
the review step.

### Phase 5 — expiring retrieval relay

- Store only the public pairing payload behind a random, expiring,
  rate-limited, single-use locator.
- Separate the human retrieval code from the device fingerprint in language,
  layout, protocol fields, and logs.
- Add enumeration resistance, abuse monitoring without payload logging, global
  and per-invitation attempt budgets, and immediate revocation.

Exit gate: external threat review, load/abuse testing, privacy review, and
verified atomic one-time retrieval. The relay remains optional and the direct
transports continue to work.

### Phase 6 — optional proximity transports

- Evaluate LAN discovery, Bluetooth, and NFC separately based on demonstrated
  demand.
- Threat-model malicious advertisements, device-name spoofing, background
  permission behavior, shared networks, and platform lifecycle restrictions.
- Treat discovery as locating a request only; never auto-approve based on
  proximity.

Exit gate: a transport-specific security review and reliable fallback on every
platform where the adapter is offered.

### Release-wide acceptance

For every phase:

- The same complete fingerprint and active-device approval are required.
- A transport failure or retry cannot create duplicate active devices or
  consume an invitation twice.
- Security labels and warnings have snapshot, accessibility, and downgrade
  tests.
- Documentation contains Windows, macOS, iPhone, and headless VPS examples.
- Telemetry, if added later, records only coarse transport choice and outcome
  with explicit privacy review; it never records payloads, fingerprints, IDs,
  addresses, device names, or authentication material.
- Recovery and revocation limitations remain visible before and after pairing.

## Disposable developer lab

Run:

```sh
go run ./cmd/pairing-mvp
```

The command accepts no flags. It selects separate ephemeral `127.0.0.1` ports
for a real EnvBank sync service and its controller, creates a temporary SQLite
database, disposable vault, approved device, and random vault key, and retains
all private and vault-key material only in process memory. It never calls the
normal config loader, macOS Keychain, recovery code, production vault paths,
or an existing service. Shutdown closes both listeners, zeroes the in-memory
vault-key buffer, and removes the temporary directory.

The controller is explicitly non-production and exposes only:

- `GET /api/state`
- `POST /api/request`
- `POST /api/import`
- `POST /api/approve`
- `POST /api/accept`
- `POST /api/reset`

It also serves the embedded page and a session-scoped `GET /api/qr` image.
Mutations are JSON-only and follow `idle → requested → imported → approved →
accepted`; invalid, repeated, and out-of-order actions fail without changing
lab or server cryptographic state.

The HTTP boundary requires the exact loopback `Host`, exact same origin on
mutations, an HttpOnly SameSite=Strict session cookie, and a per-process CSRF
token. It applies strict no-store, no-CORS, body and header limits, MIME
sniffing prevention, `frame-ancestors 'none'`, and a nonce-based CSP. HTML,
CSS, and JavaScript are embedded and use no analytics, fonts, remote assets, or
non-loopback destinations.

## Validation checklist

Automated coverage exercises payload parsing and fuzzing, the complete
request/import/approve/accept workflow, fingerprint mismatch and replayed
actions, concurrent approvals, and local-web Host, Origin, CSRF, content-type,
body-size, framing, and CORS defenses. Release validation should run:

```sh
go test ./...
go vet ./...
go test -race ./...
node --test extension/test/*.test.js
```

A manual browser pass should cover success, fingerprint mismatch, reset, and
replay attempts while developer tools confirm that the page contacts only its
own loopback controller. Screenshots, logs, HTML, responses, and errors must be
reviewed for private keys, vault keys, dummy secret values, and authentication
headers. The pairing payload is expected only in its designated QR/copy field
and controller state response; it must not appear in URLs, logs, or errors.
