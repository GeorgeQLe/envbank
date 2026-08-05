# EnvBank product roadmap

EnvBank is an API-key lifecycle manager for individual developers. Its product
promise is safe cross-device access to API keys and low-risk rotation without
exposing secret values through model prompts, logs, screenshots, shell
arguments, or clipboard history.

This roadmap describes product priorities and sequencing. The
[architecture and threat model](architecture.md) remains the technical source
of truth for security boundaries, cryptographic formats, and deployment
constraints.

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
- [ ] Export an encrypted recovery artifact that can restore access without help
  from the sync service.
- [ ] Harden deployment guidance and complete an external cryptographic review
  before recommending broader production use.

### 2. Rotation engine

- Implement a durable create/store/validate/rollout/revoke state machine.
- Resume safely after partial failures without losing the old credential or
  repeating irreversible operations.
- Support provider grace periods and staged rollout.
- Require explicit confirmation immediately before an irreversible action such
  as revoking a credential.

### 3. Provider adapters

- Prefer official provider APIs and SDKs.
- Require every adapter to declare whether it can create, validate, list, and
  revoke credentials.
- Keep provider-specific behavior outside the cryptographic core and preserve
  the rotation engine's resumability and confirmation boundaries.

### 4. Browser fallback

- Add provider-specific, deterministic local runners only when a suitable
  lifecycle API is unavailable.
- Keep agent and model processes outside secret-bearing page state.
- Never send secret values or secret-bearing screenshots through prompts,
  logs, shell arguments, or clipboard history.
- Preserve local user confirmation for irreversible provider actions.

### 5. Automation

- Schedule rotations and notify locally when credentials are overdue.
- Track rollout completion before old credentials become eligible for
  revocation.
- Provide an emergency-rotation path with the same safety boundaries.
- Prefer short-lived credentials when a provider supports them.

### 6. Later hardening

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
