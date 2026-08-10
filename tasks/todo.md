# Current work

## Milestone 9: EnvBank OSS v0.2.0 feature release — preparation complete

- [x] Repair the scheduled full-history Gitleaks scan with version-compatible,
  narrowly scoped allowlists and an executable history regression.
- [x] Prepare an exact-tag v0.2.0 prerelease workflow, release notes, current
  installation guidance, anonymous verifier, and a cgo-enabled macOS archive
  that includes Keychain-backed Railway credential support.
- [ ] Merge the preparation through protected `main`, create the annotated
  `v0.2.0` tag, and publish the prerelease plus `v0.2.0`/`0.2` GHCR tags.
- [ ] Verify the public release anonymously, record immutable evidence, update
  the website to v0.2.0, and install the verified macOS binary on PATH.

## Milestone 8: Railway apply, resume, and names-only verification — complete

- [x] Add separately confirmed Railway variable writes, partial-failure resume,
  and sanitized verification while forbidding deployment mutations and blind
  deletion.

## Milestone 7: Railway identity binding and names-only planning — complete

- [x] Add an in-process Railway metadata adapter that binds the credential,
  project, environment, and exact service IDs, then creates names-only plans
  without value reads, provider writes, or deployment mutations.

## Milestone 6: Provider-neutral rollout engine — complete

- [x] Define redaction-safe provider capabilities and request types, then add
  expiring encrypted plans and a resumable local rollout state machine with a
  fake adapter before any live-provider integration.

## Milestone 5: SiftCut trusted bundle preparation — complete

- [x] Add local `bundle prepare` and `bundle status` workflows with trusted
  stdin import, deterministic bounded derivation, optimistic record writes,
  resumable journals, and encrypted snapshot persistence.

## Milestone 4: Public EnvBank website — implementation complete

- [x] Add a static TypeScript Next.js website with public marketing,
  first-vault tutorial, and platform-specific installation routes.
- [x] Present only released v0.1.1 capabilities, verification evidence, and
  candid alpha limitations without including unreleased provider automation.
- [x] Add responsive, keyboard-accessible controls, reduced-motion support,
  route metadata, canonical URLs, favicon, sitemap, robots metadata, and a
  bespoke social preview.
- [x] Add a Node 24 website build, lint, and typecheck lane to CI.

## Milestone 3: SiftCut staging foundation — complete

- [x] Document the SiftCut staging use-case gaps, security invariants,
  capability gates, phased implementation sequence, and acceptance criteria.
- [x] Add the strict version-1 YAML manifest contract, canonical digest,
  derivation AST and dependency ordering, semantic validation, and the
  read-only `envbank bundle check` command with redacted regression coverage.
- [x] Add encrypted vault-object CRUD with domain-separated IDs and AAD,
  optimistic revisions, server-opacity integration coverage, bundle snapshot
  and provider-plan schemas, and recovery artifact v2 compatibility.

## Milestone 2: EnvBank OSS v0.1.1 corrective launch — complete

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
- [x] Prepare a corrective tag-only v0.1.1 workflow with downloadable artifact
  and image provenance bundles plus credential-isolated public verification.
- [x] Merge the preparation, create the annotated `v0.1.1` tag on protected
  `main`, and publish the new prerelease and `v0.1.1`/`0.1` GHCR tags.
- [x] Verify clone, redirect, exact downloads, checksums, SBOM, local Sigstore
  bundles, image platforms, health and immutable digest pull anonymously, then
  record the evidence without changing v0.1.0.

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
- [x] Remove both empty accidental `recovery-drill` vaults from the separate
  local showcase service while preserving its configured vault, device, and
  encrypted record plus a verified rollback backup.

## Blockers

None.
