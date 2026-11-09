# Agent-driven rotation: hands-free after the trigger

Status (November 8, 2026): **rotation engine implemented and unit-tested
(`internal/rotation`); Neon adapter in review (#58); Vercel workflow in review
(#50). Standing approval, remote approval and leak response below are
design, not code.** Nothing here has run against a real provider.

## Goal

The owner triggers once ("rotate the Neon and Stripe keys used by this Vercel
project", or "rotate now, these keys leaked") and everything after that is
done by agents and EnvBank: mint the new credential, store it encrypted, push
it to Vercel, prove the deployment is healthy, retire the old credential after
a grace period, and leave signed evidence. The trigger can come from a phone
or a Windows machine. No step may expose a value to a model prompt, a
screenshot, a log, a shell argument or the clipboard. Computer use is allowed
where a provider has no API, as long as the value never crosses an
agent-readable channel.

## What exists

| Piece | Where | State |
| --- | --- | --- |
| Lifecycle state machine, signed policies, leases, evidence chain | `internal/lifecycle` | merged |
| Rotation engine: resumable driver over the state machine | `internal/rotation` | merged (#59) |
| Vercel `Deployer` for the engine, standing rotation approval | `internal/vercelworkflow` (`RotationDeployer`, `Backend.StandingPolicyID`) | this branch |
| Neon adapter (role password, API key) | `internal/provider/neon` | merged (#58) |
| Stripe adapter (webhook secret automatic; secret/restricted keys interactive) | `internal/provider/stripe` | merged |
| Vercel secret-only writes, staged promotion, health, rollback | `internal/vercelworkflow`, `cmd/envbank/vercel.go` | merged (#50) |
| Owner approval: Secure Enclave P-256 signature over the policy | `internal/ownerapproval` | merged (#50) |
| Agent broker: agents use secrets by name, output redacted | `internal/agentbroker` | merged |

The engine is deliberately ignorant of providers and approval channels. It
takes a `lifecycle.CredentialAdapter`, a `Deployer`, a `Store` and an
`OwnerVerifier`, and it re-checks the policy before every mutation.

```
 trigger ─▶ Plan ─▶ Acquiring ─▶ Stored ─▶ Staging ─▶ Staged ─▶ Activating ─▶ Healthy
                      │ create                │ deployer.Stage      │ deployer.Activate + health
                      ▼                       ▼                     ▼
                 Retryable / Reconciliation  RollingBack ─▶ RolledBack ─▶ Quarantined (new credential revoked)
                                                                    │
 Healthy ─▶ GracePeriod ─(policy grace)─▶ Revoking ─▶ Complete      ▼
                                           │ adapter.Revoke(previous)
```

Each transition is saved with an optimistic revision **before** its evidence
is appended, so a crash can never replay a mutation; it can only leave a
reporting gap. A run that finds the operation in a mutating state it did not
enter itself (`acquiring`, `staging`, `activating`, `revoking`) treats the
earlier mutation as interrupted: credential steps stop for reconciliation,
deployment steps roll back. Every run is fenced to its bundle lease: the
context expires with the lease and no step starts after it, so two runners
can never mutate the same bundle. Provider errors carry their own retry class: `safe` retries
within the policy budget with the same idempotency key, `ambiguous` stops in
`reconciliation-required` (a retry might mint a second secret), `never` ends
the operation.

## Remaining work, in order

### 1. Deployer for Vercel — done on this branch

`vercelworkflow.RotationDeployer` wraps the backend: `Stage` plans the
current snapshot (refusing one whose record revisions differ from what the
engine stored) and drives the workflow to the promotion gate, or to
completion for Preview; `Activate` promotes and returns the backend's
`HealthEvidence`; `Rollback` restores the previous production deployment.
Blocker codes map to the engine's retry classes: waits are safe,
reconciliation and unexpected upstream state are ambiguous, the rest never.

### 2. Standing rotation approval — done on this branch

Today every Vercel plan needs a fresh owner signature bound to one plan ID.
That is right for an ad-hoc deployment and wrong for rotation, where the
owner's intent is "keep these credentials fresh in this target".

A **standing policy** is the existing `lifecycle.AutomationPolicy` with:

- `schedule` set (`on-demand`, `every 30d`, or `on-leak`), not `manual`;
- `credential_classes`, `provider_identities` and `targets` enumerating
  exactly the credentials and the one Vercel project/environment;
- `operations` = create, stage, activate, verify, rollback, revoke;
- `expires_at` ≤ 90 days (already enforced), after which a new owner
  signature is needed;
- one owner signature (Secure Enclave **or** a remote approval, below) over
  the whole statement.

The engine already authorizes each step against such a policy, and
`vercelworkflow.Backend` now accepts one when configured with
`StandingPolicyID`: it matches manifest digest, bundle, scope fingerprint and
health path instead of a plan ID, resolves the source deployment at run time
(current production deployment, or the caller's `source_deployment_id` for
other scopes), and still requires the owner signature. Remaining:

- A `rotation.Trigger` entry point (CLI `envbank rotate --policy ID`, MCP
  `envbank_rotation_run`, and a due-date check for `envbank_rotation_due`)
  that builds `PlanInput` from the manifest: for Neon role passwords it picks
  the standby role (the one not named in the current record's credential
  ID), so two roles alternate and the application never loses its
  connection.

With this, the human does exactly one thing per 90 days per project: sign
the standing policy. Every rotation, scheduled or emergency, runs without
them.

### 3. Remote owner approval (phone, Windows)

Owner approval is a P-256 ECDSA signature over `OwnerStatement`. WebAuthn
passkeys (iPhone Face ID, Windows Hello, security keys) are **also** P-256
ECDSA. The difference is only what gets signed: a WebAuthn assertion signs
`authenticatorData || SHA-256(clientDataJSON)`, with the challenge inside
`clientDataJSON`.

Design:

- **Enrol** a passkey as an owner key: `envbank owner-approval enroll
  --webauthn` opens a page served by the Cloudflare Worker (or the local
  server) that creates a resident, user-verification-required credential;
  the public key and credential ID are pinned in the encrypted device config
  next to the Secure Enclave pin. Several owner keys may be pinned.
- **Request**: the machine running the rotation (or its agent, through the
  broker) posts an *approval request* object to the sync service:
  `{policy statement, statement digest, requested_at, expires_at}`. It is
  ciphertext to the service like every other vault object.
- **Approve**: the owner opens the approval page on the phone or Windows
  device, which is an enrolled EnvBank device and can decrypt the request. It
  renders the statement in full (which credentials, which project, until
  when, what operations), then performs a WebAuthn assertion whose challenge
  is the statement digest. The assertion (`authenticatorData`,
  `clientDataJSON`, signature) is written back as the approval.
- **Verify**: `ownerapproval.Verify` gains a second mode: recompute the
  statement digest, check it equals the challenge in `clientDataJSON`, check
  `rpId` hash and the **user-verified flag** in `authenticatorData`, then
  verify the ECDSA signature with the pinned passkey public key. The
  `OwnerApproval.Presence` field records `webauthn-user-verification` instead
  of `secure-enclave-user-presence`.

Security properties kept: an agent on the Mac cannot produce the approval
(it has no passkey private key and cannot pass user verification); the
approval is bound to the exact statement; the sync service sees ciphertext.
New: the owner can approve from anywhere they have an enrolled device.

Fallback with no passkey: the existing cross-device relay model (a six-digit
code shown on the requesting side and typed on the approving side) is **not**
acceptable here because it proves presence of a human, not of the owner.
Approval needs a key.

### 4. Leak detection and response

A value counts as *suspect* when any of these fires:

| Signal | Source | Available |
| --- | --- | --- |
| A value appears in an agent-reachable channel: a redaction hit in broker command output, a protected-fill capture violation reported by the Chromux host, a value found in a file an agent session can read | agent broker, `pkg/protectedfill`, repo scanner | partly: redaction counts exist; scanner does not |
| A value appears where it should not persist: git history, CI logs, Vercel build logs, shell history | scanner over owner-chosen paths | no |
| The provider reports unexpected use: Neon `last_used_from_addr` on an API key, Stripe key last-used IP, GitHub secret-scanning alert | adapters' `Validate` extended with usage metadata | no |
| Deployment health fails right after an unrelated change, or a target's variable metadata drifts without an EnvBank operation | Vercel backend drift check | partly |

The scanner never holds plaintext. The vault keeps, per record revision, an
HMAC fingerprint under a vault-derived key; the scanner tokenizes candidates
by provider prefix (`npg_`, `napi_`, `sk_live_`, `whsec_`, `postgresql://`)
and compares HMACs. A hit names the record and revision, never the value.

Response is a policy decision, not a human one:

- If a standing policy with `schedule: on-leak` (or any schedule) covers the
  record: start an **emergency operation**: the same state machine with the
  grace period floored at the minimum the contract allows for the
  environment, and the retired credential revoked the moment the new
  deployment is healthy. Evidence records `trigger: leak:<signal>`.
- If no policy covers it: write a `suspect` marker on the record (names
  only), and notify the owner through the remote approval channel with a
  one-tap "approve emergency rotation" request. The notification carries the
  record name and the signal, nothing else.
- A leak of the **control credential** (the Neon/Stripe/Vercel API token
  EnvBank itself uses) cannot be rotated by that same credential safely:
  mark it, refuse further automatic runs that would use it, and notify.

### 5. Stripe secret and restricted keys

Stripe exposes no API to roll these. Options, in preference order:

1. Prefer **restricted keys** created with exact permissions; still
   dashboard-only to create, but the blast radius of a leak is bounded.
2. Dashboard rotation through the protected computer-use host (Chromux):
   the host drives the Stripe dashboard, EnvBank's protected-fill captures
   the show-once key into the vault, and the agent sees only `stored`. This
   is exactly the capture path the
   [protected computer-use checklist](../tasks/protected-computer-use-2026-11-03.md)
   gates; it is allowed by the goal above once that checklist passes.
3. Until then, Stripe key rotation is the one step that stays interactive.

## Acceptance before any real rotation

1. Disposable Vercel preview project, disposable Neon project with two
   API-created roles, Stripe test mode.
2. Standing policy signed once; `envbank rotate` run by an agent through the
   broker with no owner present; evidence chain exported and checked.
3. Kill the process at every state and resume; confirm no duplicate mint.
4. Inject a fake leak signal; confirm emergency rotation and the owner
   notification.
5. Approve a policy from a phone passkey and from Windows Hello.
