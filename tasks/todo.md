# Current work

## Milestone 1: Safe access and recovery — complete

- [x] Verify backup and restore procedures with a documented recovery drill.
- [x] Add an encrypted recovery export.
- [x] Prepare hardened single-host production deployment guidance.
- [x] Prepare a cryptographic review packet.
- [x] Complete an independent cryptographic review and remediate its findings.

Later milestones are tracked in the [product roadmap](../docs/roadmap.md).

## Completed

- [x] Implement the initial zero-knowledge EnvBank CLI, sync service, browser
  extension, native host, cryptographic record storage, and multi-device
  enrollment flow.
- [x] Add automated Go, browser-extension, race, vet, formatting, and build
  validation.
- [x] Initialize and publish the repository on GitHub.
- [x] Replace the single-process JSON state file with a transactional SQLite
  backend and an automatic version-1 state migration.
- [x] Add soft device revocation with fingerprint verification, self-revocation
  confirmation, and an atomic final-active-device safeguard.
- [x] Add bounded, privacy-preserving device-access events with authenticated
  pagination and transactional fail-closed persistence.
- [x] Add encrypted offline recovery artifacts and resumable restoration into a
  new vault, key, and device identity.
- [x] Add a versioned, server-enforced device-pairing invitation lifecycle with
  expiration, cancellation, rejection, attempt exhaustion, atomic approval,
  and a disposable QR-first developer lab.

## Blockers

- None.
