# Provider actions — agents provision and rotate Stripe/Neon for Vercel (2026-11-05)

Goal: agents, through EnvBank and Chromux, set up Stripe and Neon for a Vercel project and rotate keys on demand, with only an owner Touch ID prompt. The contract is [provider-actions.md](../docs/provider-actions.md). The branch is `feat/provider-actions` at d9c1395, not pushed. It holds the authz work, the PR #50 Vercel integration, adapters, the broker ops, bindings, production promote and rollback, and fixes from two security reviews.

Owner decisions:
- The Stripe API key comes from Vercel Connect managed keys.
- Throwaway live acceptance is allowed: Stripe test mode only, Touch ID for each action, and everything deleted afterwards.

- [x] Adapters, broker `provider_action`/`provider_status`, bindings, locks, live factory, synthetic e2e, production promote with rollback.
- [x] Review 1 (10 findings) fixed in f867fe2.
- [x] Review 2 (H1, M1–M3, L1–L5, group role) fixed in d9c1395. Partial fixes:
  - L2: the create-time windows in neon.project.create and Stripe create/rotate are not resumable.
  - L4: a deployed *previous* Stripe secret does not block a delete.
  - L5: the production source is checked at execute, not before the prompt.
- [x] Third independent review of d9c1395 (2026-11-05): no Critical or High findings; go test and go vet are clean.
- [x] Fix review 3 (5 November 2026; see `docs/provider-actions.md`, tests in `internal/provideraction/review3_test.go`):
  - M1: `envClaims` returns every claimant (sorted); rotations and env.remove refuse an env var with more than one claimant (`ENV_NAME_TAKEN`); a `replace_existing` push releases every other claimant. Tested: failed push, failed release, partial release.
  - M2: revoked claims count; env.remove only by the sole claimant.
  - M3: names-only `VercelPort.EnvPresent` (adapter `Present`) before the prompt and again before the write; an unclaimed value is `ENV_NAME_TAKEN` unless `replace_existing`, text `REPLACES a value NOT written by this broker in ENV`. Rotations check names they newly write the same way. An all-branches preview entry does not count for a branch scope (Vercel keeps it and prefers the branch entry).
  - L-a: a push is refused `ROTATION_INCOMPLETE` (new code) while any Neon group member is pending. The retry itself stays allowed (the only way out).
  - L-b: `pending_host` (SHA-256 of the URI host) stored at `vault.mark_pending`; R+1 is accepted only if its user is the pending role and its host matches.
  - L-c: push refuses `ROTATION_UNSCOPED_PREVIEW`, `ROTATION_SCOPE_LIMIT` and `PLAN_TOO_LONG` (shortest rotation summary through `provideraction.WithPlanFit`, wired in authz).
  - L-d: env.push and env.remove lock each record's Neon project or Stripe endpoint and lineage.
  - L-e: Stripe drift covers `status` (must be enabled) and the recorded `api_version`; the copy is created with the live version, recorded in provenance (create records the default it got).
  - Missing tests added: Stripe `previous_record` RECORD_CHANGED and RECORD_NOT_BOUND, `replaced_records` after a partial release, live env.remove of a plain or ambiguous entry, live hand-set env var refusal.
- [ ] Live check: the Touch ID prompt shows a 600-byte reason in full. If not, move REPLACES and INVALIDATE text earlier.
- [x] Chromux mirror of the d9c1395 and review-3 wire changes (Chromux feat/authorized-agents, local; Chromux also found its gateway clipped the provider_action description to 1024 characters, now fixed) (XPC depth fix done in Chromux 0855ac5; see Chromux `tasks/todo.md`). Review 3 adds: new code `ROTATION_INCOMPLETE`; `ENV_NAME_TAKEN` now also from env.remove (another claimant) and the unclaimed-value check (push and rotations); push refusals `ROTATION_UNSCOPED_PREVIEW` and `PLAN_TOO_LONG`; push approval text `REPLACES records A, B' values in ENV` and `REPLACES a value NOT written by this broker in ENV`; `replaced_records` can be partial on a failed push.
- [x] Build and sign both apps with Developer ID (Team NC56VXK48K) and reinstall (5 November 2026). EnvBank 1411ac1 → `~/.local/bin/envbank` (`com.georgeqle.envbank`, runtime, no entitlements, CDHash 277b9b1c2660…). Chromux feat/authorized-agents 7a772ff → `/Applications/Chromux v2 Rebuild.app` (package report `failures: []`; export `/Volumes/T9/CodexBuildExports/chromux-authz-signed-20261105`). Backups of the previous installs and SHA-256s: `~/Developer/Artifacts/envbank-chromux-signing-20261105/`. Not notarized.
- [x] Owner reconnected (service cdhash 85030bc81cd4…).
- [x] Live Touch ID e2e, synthetic value, throwaway vault (5 November 2026, installed signed builds; driver and broker transcript in `~/Developer/Artifacts/envbank-chromux-signing-20261105/`). Agent: Codex 0.162.1 (GPT 6.1 Terra) launched by Chromux with agent tools.
  - Passed: pairing (Chromux Touch ID, then broker Touch ID; service cdhash 85030bc81cd4… matched); `names` refused NOT_AUTHORIZED before a grant; `run` grant and `provider` grant each with Touch ID naming session fingerprint 07118d0d and label; `names` after grant; `run` of a script with its own Touch ID (executable and interpreter SHA-256, in-directory warnings) returned `value=[REDACTED:E2E_SYNTH_TOKEN]` and length 40; inline `sh -c` refused COMMAND_REFUSED (correct); `grant_status` lists both grants; lock ends them.
  - No leak: token absent from broker terminal and from agent output; no file modified under Chromux app support/logs or `~/.codex` during the run contained it; vault value intact.
  - 3-scope list: a valid `neon.rotate` with 3 scopes crossed the addon and service and passed EnvBank's strict decode + validate (stopped at CONTROL_CREDENTIAL_MISSING). Not proven: that no scope is dropped (Chromux refuses two production scopes locally, so that probe never reached EnvBank). The Touch ID plan text in live acceptance will show all scopes; check it there.
  - Still open: the 600-byte reason (needs CONTROL_* seeded; check in live acceptance).
- [ ] Owner seeds `CONTROL_VERCEL_TOKEN`, `CONTROL_NEON_API_KEY` and `CONTROL_STRIPE_KEY` (test mode) through Chromux secure entry.
- [ ] Throwaway live acceptance: new Vercel project, new Neon project, and a Stripe test-mode webhook; rotate each; then delete everything. Open questions to settle live:
  - Do API-created Neon roles get ADMIN, and does the pooler honour `SET role`?
  - Neon and Vercel response and URL shapes, and the branch filter.
  - Vercel deployment protection (`HEALTH_PROTECTED`).
  - Vercel Connect managed-key rotation (no API, so test the connector swap), and whether managed keys can be test mode.
  - Rollback does not restore old env values.
  - The in-memory operation journal is lost when the broker restarts.
- [ ] Known limitation: StoreSecret/Names/Values still decrypt all records into Go strings (memory hygiene, finding 8).
- [ ] Open PRs (EnvBank feat/provider-actions; Chromux feat/authorized-agents). Do not merge without the owner.
- [ ] Owner: dismiss the PR #50 CodeQL false positives, create the `envbank-notary` notarytool profile, and identify and rotate the Bearer string found in ~/.codex history.

# Current work

## Vercel integration — implementation verified, live acceptance pending

See [scope, verification and remaining acceptance](vercel-workflow-2026-11-03.md).

- [x] Implement exact-scoped Secret writes and the vault-to-deployment CLI/MCP backend.
- [x] Verify synthetic API workflows, policy enforcement, recovery and rollback.
- [x] Add owner hardware-signature enforcement, encrypted pinning and separate
  disposable Preview/Production acceptance runners; execute synthetic checks.
- [ ] Owner imports acceptance credentials privately and approves disposable targets.
- [ ] Qualify real Preview consumption, staged Production promotion and rollback.
- [ ] Qualify the external observation controller before browser key capture.

## Milestone 12: Cloudflare-first migration — foundation complete

- [x] Add the staging EnvBank Worker with one SQLite-backed Durable Object per
  vault, encrypted client-config v2 with Cloudflare Access credentials, and
  redirect-safe Access headers outside the v1 signature.
- [x] Add exact-account/zone/script Cloudflare binding, atomic undeployed
  Worker-version staging, names-only verification, separate promotion and
  rollback, and a marked live-provider acceptance path.
- [ ] Complete the cross-language v1 parity harness and close every Worker
  route, error, audit, pagination, concurrency, and schema-migration gap before
  any production data or hostname is placed on the Worker.
- [ ] Build the authenticated resumable SQLite-to-Durable-Object importer with
  per-vault transactional import and identifier/ciphertext-free count and
  digest comparison.
- [ ] Deploy marked staging resources, run the full migration and restore
  journeys, complete the maintenance-window cutover and seven-day observation,
  then retire the legacy Go/Docker/Railway production paths.

## Milestone 11: $0 end-to-end execution — implementation complete

- [x] Add the required network-free `make e2e` gate, binary restart matrix,
  fault coverage, recovery/extension/website orchestration, and leakage scan.
- [x] Add local release, disposable headed-browser, interactive Keychain, and
  explicitly authorized provider-acceptance entry points plus a full runbook.
- [x] Execute disposable browser and production native-host Keychain/Touch ID
  approval/denial observations on the release Mac and record sanitized evidence.
- [ ] Execute the explicitly authorized Stripe, Clerk Development, and
  Cloudflare observations against dedicated marked resources before the next
  release.

## Milestone 10: Hermetic agent-operable lifecycle testlab — complete

- [x] Add version-2 lifecycle contracts, signed automation policy and evidence
  foundations, callback-scoped secret sinks/sources, encrypted operations,
  optimistic bundle leases, ordered deployments, and reverse rollback.
- [x] Add private-pipe provider intake, the Stripe webhook adapter, the
  terminal-safe Clerk helper, and the workflow-only production MCP surface.
- [x] Add a separate `envbank-testlab` binary with encrypted ephemeral state,
  loopback provider emulators, signed simulated browser capture, virtual time,
  bounded faults, strict test-only MCP controls, resumable flow assertions,
  rollback/quarantine, and leakage regression coverage.

## Milestone 9: EnvBank OSS v0.2.0 feature release — complete

- [x] Repair the scheduled full-history Gitleaks scan with version-compatible,
  narrowly scoped allowlists and an executable history regression.
- [x] Prepare an exact-tag v0.2.0 prerelease workflow, release notes, current
  installation guidance, anonymous verifier, and a cgo-enabled macOS archive
  that includes Keychain-backed Railway credential support.
- [x] Merge the preparation through protected `main`, create the annotated
  `v0.2.0` tag, and publish the prerelease plus `v0.2.0`/`0.2` GHCR tags.
- [x] Verify the public release anonymously, record immutable evidence, update
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

- SiftCut Cloud implementation belongs to the separate `short-editor`
  repository, which is outside this workspace's writable scope. Its D1/R2/
  Queues/Workers AI/Containers refactor and PostgreSQL-to-D1 importer remain
  unimplemented here.
