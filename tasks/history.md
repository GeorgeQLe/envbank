# History

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
