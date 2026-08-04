# History

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
