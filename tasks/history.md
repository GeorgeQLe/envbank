# History

## 2026-08-09

- Prepared the corrective v0.1.1 alpha release without changing the v0.1.0 tag
  or assets, including downloadable Sigstore provenance bundles for release
  artifacts and the multi-architecture image.
- Added credential-isolated anonymous verification of the canonical and legacy
  repository URLs, exact release asset set, safe archives, checksums, SPDX
  metadata, release identity, source ref and commit, OCI platforms, immutable
  image pull, and health response.

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
