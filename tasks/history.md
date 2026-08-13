# History

## 2026-08-13

- Added the version-2 lifecycle contract and safety foundations: signed,
  expiring policies and evidence; encrypted operations and rollback material;
  callback-scoped secret sinks/sources; optimistic per-bundle leases; and
  ordered deployment with reverse rollback.
- Added private-pipe provider intake, a terminal-safe Clerk/Keychain helper,
  Stripe webhook lifecycle support, and a strict workflow-only MCP surface
  that accepts and returns no credential-shaped fields.
- Added the separate `envbank-testlab` executable with encrypted temporary
  SQLite state, ephemeral signer/oracle keys, loopback provider emulators,
  signed protocol-v2 simulated browser capture, virtual time, bounded fault
  injection, resumable checkpoints, lease races, rollback/quarantine, and
  boolean-only end-to-end secret-flow assertions.
- Verified the full Go and extension suites, full Go race suite, formatting,
  vet, build/smoke behavior, and the repository secret-scan self-test.
- Addressed all five automated PR review findings by binding every immutable
  revocation field, rolling back all staged targets, requiring Stripe
  idempotency, enforcing exact activation permutations, and routing testlab
  Stripe acquisition through the loopback emulator and production adapter.

## 2026-08-10

- Merged PR #23 through protected `main`, published the immutable annotated
  v0.2.0 prerelease and `v0.2.0`/`0.2` multi-architecture GHCR image, and
  completed every release workflow gate.
- Verified the release anonymously across the exact eight assets, checksums,
  Sigstore provenance, archive safety, native macOS Keychain linkage, both OCI
  platforms, and the live container health endpoint; recorded immutable hashes
  in `docs/release-evidence-v0.2.0.md`.
- Installed the verified Darwin/ARM64 binary at `~/.local/bin/envbank`, confirmed
  v0.2.0 metadata at the protected-main commit, and advanced the public website
  installation and evidence surface from v0.1.1 to v0.2.0.
- Prepared the v0.2.0 feature-alpha release for the completed manifest, bundle,
  provider-rollout, and Railway milestones while preserving v0.1.x tags and
  release assets.
- Fixed the first scheduled full-history Gitleaks run, which exposed that the
  newer plural global-allowlist syntax was ignored by the action's pinned
  Gitleaks 8.24.3 binary. Replaced it with the compatible singular form, kept
  only two narrow known non-secret patterns, and added a full-history regression
  before the synthetic-secret assertion.
- Changed release archives to build macOS with cgo and assert linkage to
  `Security.framework`, ensuring the downloadable binary contains the
  Keychain implementation required by Railway credentials and the native host;
  retained cgo-free Linux archives.

## 2026-08-09

- Hardened the Milestone 8 Railway rollout after PR #22 review: environment
  binding now requires the manifest name and token-scoped ID on the same unique
  node, and unusable HTTP 2xx write responses retain ambiguous retry semantics.
  Added cross-environment, malformed, oversized, unreadable, GraphQL-envelope,
  mutation-decoding, sanitization, and status-classification regressions.
- Added interactive `railway apply`, confirmed-operation `railway resume`, and
  read-only `railway verify` commands over encrypted rollout state, with exact
  credential, target, snapshot, manifest, service-ID, and record-revision
  revalidation.
- Allowlisted only Railway single-variable upserts with `skipDeploys: true`.
  Writes checkpoint before and after each request, committed actions are
  skipped on resume, and ambiguous exact upserts are safely repeatable without
  regenerating values.
- Kept Railway verification names-only: immutable metadata is re-resolved,
  provider presence is reported as unknown, local committed-write evidence is
  shown separately, and staged changes are distinguished from uninspected
  deployed state. Intended absence never becomes a blind deletion.
- Covered partial service failure, post-failure resume, committed-write
  non-repetition, public constants, secret and provider-body redaction,
  skip-deploy enforcement, forbidden GraphQL operations, and names-only CLI
  verification with loopback integration tests.
- Added `railway bind` with trusted-stdin project-token intake, verification of
  the token-scoped immutable project/environment identity, exact four-service
  name-to-ID resolution, and bundle-scoped macOS Keychain storage only after a
  successful bind.
- Added a bounded in-process Railway GraphQL transport whose production
  allowlist contains only project-token identity and project metadata queries;
  redirects, oversized responses, arbitrary GraphQL bodies, unsafe error codes,
  wrong token scopes, duplicate service names, and service-ID drift fail closed.
- Added encrypted 15-minute names-only plans that bind all four service IDs,
  manifest and snapshot revisions, required and intended-absent variable names,
  and exact record revisions while reporting provider state as `unverifiable`.
  Names-only plans are structurally non-applicable and the Railway adapter has
  no variable-value query, provider mutation, or deployment document.
- Added the provider-neutral rollout boundary with declared capability gates,
  callback-scoped non-serializable secret requests, bounded metadata-only
  evidence, and provider-error sanitization that discards arbitrary bodies.
- Added digest-addressed 15-minute encrypted provider plans and encrypted
  per-action rollout operations with exact identity, target, snapshot, and
  record-revision validation; interactive and destructive confirmations;
  durable in-flight checkpoints; idempotent retry; metadata reconciliation for
  ambiguous writes; per-action verification; and honest limited results that
  stop at `ready-to-deploy` without deployment behavior.
- Covered cancellation, expiry, staleness, partial failure, non-duplication,
  post-expiry resume, ambiguous non-idempotent outcomes, secret/error
  redaction, capability gates, and verification limits with fake-adapter tests.
- Added local `envbank bundle prepare` and `bundle status` workflows with
  deterministic bundle-scoped physical names, exact JSON stdin imports,
  policy-based generation, bounded topological derivation, optimistic record
  writes, encrypted per-record journals, final revision checks, and encrypted
  snapshot publication with prior revision evidence retained for recovery.
- Added names-only missing/prepared/stale reporting with dependent-staleness
  propagation plus regression coverage for independent generated values,
  exact in-process derivations, plaintext exclusion, idempotency, resumability,
  physical-name stability, input conflicts, and expansion limits.
- Added the public EnvBank website under `website/` with focused marketing,
  getting-started, and install routes for the released v0.1.1 alpha.
- Built a security-focused responsive visual system, accessible copy controls,
  exact platform and architecture selection, checksum and Sigstore guidance,
  unsigned-macOS warnings, and prominent product limitations.
- Added canonical metadata, sitemap, robots policy, generated favicon and a
  bespoke redacted Open Graph card, plus a Node 24 website CI lane.
- Defined the SiftCut staging gap analysis and implementation plan around a
  public versioned contract, encrypted runtime state, trusted local derivation,
  provider capability gates, resumable rollout, honest reconciliation,
  readiness, recovery, and rotation.
- Added the strict version-1 YAML manifest contract with bounded data-only
  parsing, semantic validation, derivation AST and deterministic dependency
  ordering, canonical JSON/SHA-256 digests, redacted errors, and the read-only
  `envbank bundle check` command.
- Added table, canonicalization, malicious-YAML, derivation-cycle,
  secret-sentinel, CLI-output, fuzz-seed, and race coverage for the contract
  foundation without adding vault or provider mutations.
- Added opaque encrypted vault-object CRUD across protocol, client, and server
  layers with domain-separated IDs and AAD, optimistic revisions, private
  access events, and the transactional SQLite version-6 migration.
- Added versioned bundle-snapshot and provider-plan schemas plus encrypted
  recovery artifact v2, including legacy artifact reads, restored revision
  reset, resumable object upload, and server-opacity regression coverage.
- Advanced backup/recovery validation to SQLite schema version 6 and hardened
  the drill against mistaking an unrelated service on its default port for the
  disposable service it launched.
- Removed both empty accidental `recovery-drill` vaults from the separate local
  showcase database with exact-ID transactional assertions and a retained,
  mode-`0600`, SHA-256-verified SQLite backup. Revalidated schema version 5,
  integrity and foreign keys, preserved the configured showcase vault, device,
  and encrypted record, passed authenticated list/decryption and health smoke
  tests, and left the service stopped with port 17337 free.

- Prepared the corrective v0.1.1 alpha release without changing the v0.1.0 tag
  or assets, including downloadable Sigstore provenance bundles for release
  artifacts and the multi-architecture image.
- Added credential-isolated anonymous verification of the canonical and legacy
  repository URLs, exact release asset set, safe archives, checksums, SPDX
  metadata, release identity, source ref and commit, OCI platforms, immutable
  image pull, and health response.
- Merged the preparation through all 11 required CI/security checks, published
  the annotated v0.1.1 corrective prerelease and AMD64/ARM64 GHCR image from
  protected `main`, and preserved both provenance bundles as release assets.
- Passed the complete anonymous verifier after replacing an optional Buildx
  inspection dependency with the public GHCR manifest API; recorded exact
  asset/platform digests, signer identity, redirect chain, binary metadata, and
  health evidence while preserving v0.1.0.
- Updated the release workflow's artifact upload/download actions to pinned
  Node 24 generations after the immutable tagged run exposed Node 20
  deprecation warnings.

## 2026-08-08

- Published the renamed `GeorgeQLe/envbank` repository and verified public
  visibility, private vulnerability reporting, vulnerability alerts,
  Dependabot security updates, secret scanning and push protection, plus the
  active security-analysis workflow.
- Verified protected-branch enforcement for `main`, the annotated `v0.1.0` tag,
  the published alpha prerelease, and the public GHCR package.
- Added an unbiased cryptographically secure random-character password
  generator with configurable length and character classes, enabled-class
  guarantees, and a cryptographic shuffle.
- Added `envbank generate` with explicit replacement, optimistic revisions,
  creation/origin/rotation metadata preservation, and name-and-revision-only
  output while retaining `rotate --bytes` for URL-safe tokens.
- Extended native protocol v1 and the Chrome popup with native-only password
  generation, exact-origin and replacement confirmation, navigation-race
  handling, and the existing 30-second field-selection flow.
- Added Go and extension regression coverage for generation policy, encrypted
  persistence, stale revisions, metadata preservation, origin revalidation,
  and plaintext-exposure prohibitions; updated user, architecture, extension,
  and security documentation.

## 2026-08-06

- Prepared the EnvBank v0.1.0 alpha open-source launch under Apache-2.0,
  including public contribution, security, changelog, and issue-reporting
  policies while deferring a standalone Code of Conduct until a private
  conduct-reporting channel exists.
- Renamed the Go module and internal imports to `github.com/GeorgeQLe/envbank`,
  added link-time version/commit/build-date reporting, and documented supported
  release platforms, unsigned macOS binaries, GHCR installation, checksums,
  SPDX SBOMs, and GitHub provenance verification.
- Added immutable-action CI, full-history Gitleaks, Go and JavaScript CodeQL,
  Dependabot, release license/vulnerability gates, four native-validated
  archives, and an attested multi-architecture non-root shell-free image.
- Completed the independent cryptographic review of
  `59446421f10bc3465adb1d70f30ad50259b9209d`, remediating one high-severity
  enrollment-identity finding and two medium-severity replay/runtime findings
  in `505de15f6bc4840db3b9084866163ea3e5aba2b9`.
- Re-reviewed the remediation from a clean detached clone with formatting,
  module verification, Go, race, vet, extension, native/Linux build, recovery,
  file/link, and vulnerability checks passing.
- Advanced replay persistence to schema version 5, pinned Go 1.25.12 and the
  official Docker builder digest, and retained crypto-v2 changes as explicit
  deferred hardening recommendations.
- Added version-1 device-pairing invitations with server-clock expiration,
  atomic single-use approval, cancellation, rejection, attempt exhaustion, and
  authenticated status retrieval for the intended pending device.
- Added schema version 4 persistence and migration coverage for invitation
  lifecycle state while preserving legacy enrollment compatibility.
- Added a disposable QR-first pairing lab that uses the real service and
  cryptographic protocol while isolating normal configs, Keychain material,
  recovery artifacts, production vaults, and non-loopback services.
- Documented the canonical public pairing payload, fingerprint-verification
  boundary, transport risks, cross-platform roadmap, operational controls, and
  backup/review implications.

## 2026-08-05

- Added a hardened single-host Docker production runbook covering a non-root
  read-only container, resource limits, loopback-only exposure, private-network
  TLS proxy controls, backup/recovery, upgrades, monitoring, and incidents.
- Added a self-contained cryptographic review brief with immutable-revision
  validation, threat model, exact primitives and constructions, code/test map,
  limitations, reviewer questions, and private finding format.
- Added a 16 KiB HTTP header limit, no-store/nosniff API headers, and graceful
  SIGINT/SIGTERM shutdown with a ten-second deadline.
- Fixed clean container builds to copy the dependency checksum file into the
  build stage.
- Split prepared deployment/review materials from the still-outstanding
  independent review and remediation milestone.
- Added versioned AES-256-GCM recovery artifacts with a separate
  PBKDF2-HMAC-SHA-256 recovery passphrase, strict format validation, bounded
  reads, atomic `0600` creation, and overwrite refusal.
- Added offline recovery verification, listing, value access, and child-process
  execution without a service or device config.
- Added new-vault restoration with new cryptographic identities, metadata
  preservation, revision reset, config-before-upload durability, and safe
  resume that rejects conflicting or unrelated target records.
- Verified the online SQLite backup and isolated restore procedure with a
  disposable, localhost-only recovery drill covering encrypted device configs,
  device revocation, access-history continuity, recovery-point boundaries, and
  post-restore writes across a second restart.
- Added the reusable recovery drill and operator runbook, including integrity,
  schema, permission, truncated-backup, future-schema, WAL-sidecar quarantine,
  RPO, and RTO checks.

## 2026-08-04

- Added privacy-preserving access events for recognized vault operations,
  including truthful verified identity attribution, bounded outcomes and
  reasons, authenticated cursor pagination, client support, and TSV CLI output.
- Added schema version 3 migration and per-vault transactional pruning after 90
  days with separate 10,000 verified and 2,000 unverified event caps.
- Made verified reads, mutations, policy rejections, replay-nonce consumption,
  and their events atomic; accepted public enrollments now commit atomically
  with their unverified event.
- Added soft device revocation across the SQLite service, authenticated API,
  client, and CLI, including deterministic device listings, fingerprint
  verification, explicit self-revocation confirmation, and an atomic
  last-active-device safeguard.
- Added schema version 2 migration, revoked-device authentication gates,
  multi-service cross-revocation coverage, and documentation of the
  cryptographic limits of access revocation.
- Created the [API-key lifecycle product roadmap](../docs/roadmap.md), ordered
  around safe access and recovery before provider-backed rotation automation.
- Replaced the single-process JSON state file with a normalized transactional
  SQLite backend supporting multiple service processes on one host.
- Added atomic replay-nonce consumption, transactional optimistic revisions,
  automatic version-1 JSON migration with a retained backup, and multi-instance
  regression coverage.
- Updated the CLI, container defaults, deployment guidance, and production
  readiness checklist for database-backed persistence.

## 2026-08-03

- Shipped the initial EnvBank implementation, including the Go CLI and sync
  service, encrypted record and enrollment protocols, macOS native host, and
  Chrome extension.
- Added the canonical GitHub module path and project designation.
- Verified the initial release with Go tests, extension tests, vet, race
  detection, formatting, and a local build.
