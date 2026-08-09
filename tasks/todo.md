# Current work

## Milestone 2: EnvBank OSS v0.1.0 launch — in progress

- [x] Prepare the Apache-2.0 license, public governance and security policy,
  alpha documentation, release metadata, and narrowly scoped Gitleaks policy.
- [x] Add pinned CI, security analysis, dependency updates, release archives,
  checksums, SPDX SBOM, provenance, and multi-architecture GHCR automation.
- [x] Validate formatting, modules, Go and extension tests, race tests, vet,
  recovery, vulnerability and license audits, full-history secret scanning,
  cross-builds, and the hardened container.
- [x] Rename the GitHub repository to `GeorgeQLe/envbank`, make it public, and
  enable private vulnerability reporting and GitHub security features.
- [x] Protect `main`, create the annotated `v0.1.0` tag, publish the prerelease
  and GHCR image, and make the package public.
- [ ] Verify clone, downloads, checksums, SBOM, attestations, image health and
  digest pull, and the legacy repository redirect anonymously.

## Milestone 1: Safe access and recovery — complete

- [x] Verify backup and restore procedures with a documented recovery drill.
- [x] Add an encrypted recovery export.
- [x] Prepare hardened single-host production deployment guidance.
- [x] Prepare a cryptographic review packet.
- [x] Complete an independent cryptographic review and remediate its findings.

Later milestones are tracked in the [product roadmap](../docs/roadmap.md).

## Completed

- [x] Add cryptographically secure random-character password generation to the
  CLI and Chrome extension without exposing generated plaintext through output,
  metadata, clipboard, extension storage, or popup JavaScript.
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
