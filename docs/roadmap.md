# EnvBank product roadmap

EnvBank is an API-key lifecycle manager for individual developers. Its product
promise is safe cross-device access to API keys and low-risk rotation without
exposing secret values through model prompts, logs, screenshots, shell
arguments, or clipboard history.

This roadmap describes product priorities and sequencing. The
[architecture and threat model](architecture.md) remains the technical source
of truth for security boundaries, cryptographic formats, and deployment
constraints.

The [SiftCut staging use-case gap analysis](siftcut-use-case-gaps.md) applies
this roadmap to a concrete multi-service Railway and Clerk workflow and defines
the minimum bundle, derived-value, provider-adapter, and resumability work that
would make EnvBank useful there.

## Foundation complete

EnvBank already provides:

- A zero-knowledge vault whose sync service stores ciphertext rather than
  plaintext secret names or values
- Explicit, fingerprint-verified device enrollment and wrapped vault-key
  delivery
- Direct child-process environment injection without plaintext `.env` files
- Exact-origin browser filling through a local, Keychain-gated native host
- Transactional SQLite synchronization with atomic replay protection and
  optimistic revisions

## Milestones

Milestones are ordered. Safe access and recovery come before provider
automation, and the first provider will be selected using actual usage
frequency and lifecycle-API capability rather than chosen in advance.

### 1. Safe access and recovery

- [x] Revoke an enrolled device without disrupting remaining approved devices.
- [x] Record device-access events without logging secret values.
- [x] Verify backup and restore procedures, including recovery drills.
- [x] Export an encrypted recovery artifact that can restore access without help
  from the sync service.
- [x] Prepare hardened single-host production deployment guidance.
- [x] Prepare an immutable cryptographic review packet.
- [x] Complete an independent cryptographic review and remediate its findings
  before recommending broader production use.

### 2. Cross-platform device pairing

The detailed transport, platform, safety-label, and release sequence is in the
[device-pairing roadmap](device-pairing.md#cross-platform-implementation-roadmap).
Every transport carries the same public pairing payload and preserves explicit
fingerprint verification and approval by an active device.

- [x] Validate QR and copyable-text enrollment in a disposable lab using the
  real service and cryptographic protocol.
- [x] Add server-enforced expiration, single-use consumption, rejection, and
  cancellation for pending invitations before shipping a production UI.
- Add universal CLI import/export over stdin and a versioned
  `.envbank-pairing` file so Windows, macOS, iPhone, and headless VPS workflows
  share one baseline.
- Add a transport chooser that recommends compatible options and explains
  metadata exposure, verification requirements, platform limits, and recovery
  behavior before the user selects one.
- Add native share/deep-link adapters as optional conveniences; keep AirDrop
  and Apple share sheets explicitly labeled as Apple-only.
- Add an expiring, rate-limited retrieval code only after the invitation
  lifecycle and relay-abuse controls are complete.
- Treat local-network discovery, Bluetooth, and NFC as optional later adapters
  requiring separate threat reviews and platform-specific test plans.
- Complete Windows, macOS, iPhone, and headless VPS pairing walkthroughs,
  accessibility review, and downgrade-warning tests before general release.

### 3. Rotation engine

The version-2 lifecycle and hermetic testlab foundation is implemented. Live
provider acceptance and production workflow wiring remain required before the
rotation-engine milestone can be marked complete.

- Implement a durable create/store/validate/rollout/revoke state machine.
- Resume safely after partial failures without losing the old credential or
  repeating irreversible operations.
- Support provider grace periods and staged rollout.
- Require explicit confirmation immediately before an irreversible action such
  as revoking a credential.

### 4. Provider adapters

- Prefer official provider APIs and SDKs.
- Require every adapter to declare whether it can create, validate, list, and
  revoke credentials.
- Keep provider-specific behavior outside the cryptographic core and preserve
  the rotation engine's resumability and confirmation boundaries.

### 5. Browser fallback

- Add provider-specific, deterministic local runners only when a suitable
  lifecycle API is unavailable.
- Keep agent and model processes outside secret-bearing page state.
- Never send secret values or secret-bearing screenshots through prompts,
  logs, shell arguments, or clipboard history.
- Preserve local user confirmation for irreversible provider actions.

### 6. Automation

- Schedule rotations and notify locally when credentials are overdue.
- Track rollout completion before old credentials become eligible for
  revocation.
- Provide an emergency-rotation path with the same safety boundaries.
- Prefer short-lived credentials when a provider supports them.

### 7. Later hardening

- Detect rollback and add signed audit checkpoints.
- Add service rate limiting and support for additional platform keychains.
- Add scoped access controls for local clients and devices.
- Consider PostgreSQL and multi-host operation after the single-user workflow
  is reliable.

## Explicitly deferred

Enterprise IAM, organizations, broad team roles, and high availability are
deferred until the individual-developer access, recovery, and rotation workflow
is reliable. EnvBank is not intended to replace a managed KMS or HSM for
high-assurance production workloads.
