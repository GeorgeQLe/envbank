# Current work

## Milestone 1: Safe access and recovery

- [ ] Verify backup and restore procedures with a documented recovery drill.
- [ ] Add an encrypted recovery export.
- [ ] Harden production deployment guidance and complete an external
  cryptographic review.

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

## Blockers

- None.
