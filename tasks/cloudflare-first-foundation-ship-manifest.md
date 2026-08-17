# Cloudflare-first foundation ship manifest

Date: 2026-08-16

## User goal

Replace EnvBank's production direction and active rollout work with a
Cloudflare-native Worker, Durable Objects, Access-aware clients, and
version-before-deployment rollout mechanics, while preserving the legacy
runtime until the migration gates pass. Record SiftCut Cloud work as belonging
to its separate repository.

## Changed files and per-file purpose

- `.gitignore` — excludes dependency trees and local Wrangler runtime state.
- `README.md` — makes Cloudflare the production target and identifies Docker as
  rollback-only during migration.
- `docs/production-deployment.md` — marks the Docker runbook as legacy and
  gated for retirement.
- `docs/cloudflare-migration.md` — documents Access configuration, Worker
  staging/promotion, secret rollout, and cutover gates.
- `cloudflare/envbank-worker/README.md` — states Worker-specific deployment,
  Access, and placement constraints.
- `cloudflare/envbank-worker/package.json`, `package-lock.json`, and
  `tsconfig.json` — pin the TypeScript, Worker types, and Wrangler toolchain and
  expose typecheck/test/deploy commands.
- `cloudflare/envbank-worker/wrangler.toml` — defines the marked staging Worker,
  Smart Placement, SQLite Durable Object binding, migration, and observability.
- `cloudflare/envbank-worker/src/protocol.ts` and `protocol.test.ts` — implement
  the v1 signature-message construction and cross-language golden vector.
- `cloudflare/envbank-worker/src/index.ts` — implements routing, one named
  SQLite Durable Object per vault, signed authentication, replay reservation,
  enrollment/invitation/device/record/object/event behavior, body limits, and
  transactional mutations.
- `internal/client/local.go` and `local_test.go` — add encrypted config v2,
  Access credential storage, transparent unlocked v1 migration, and regression
  coverage.
- `internal/client/api.go` and `api_test.go` — add Access service-token headers
  outside signatures and fail-closed authenticated redirect handling with
  tests.
- `cmd/envbank/main.go` and `cmd/envbank/recovery.go` — add Access
  bind/rotate/remove and bootstrap intake, route Cloudflare commands, and save
  migrated configs.
- `internal/nativehost/host.go` — loads Access credentials and persists unlocked
  v1-to-v2 migration for native-host clients.
- `internal/provider/provider.go` — adds atomic-batch staging and provider
  revision/version evidence to the provider boundary.
- `internal/provider/cloudflare/adapter.go`, `api.go`, `credential.go`, and
  `planner.go` — implement immutable Cloudflare target binding, Keychain token
  storage, names-only inspection, one-version atomic staging, deployment, and
  rollback.
- `internal/provider/cloudflare/api_test.go` — verifies multipart staging,
  strict inheritance, exact binding metadata, and a single version upload.
- `internal/rollout/plan.go`, `state.go`, and `engine.go` — add binding-name
  plans, provider revision checks, atomic staging, staged-version verification,
  and encrypted promotion/rollback evidence.
- `internal/rollout/engine_test.go` — covers one-shot atomic staging and
  staged-version verification without plaintext persistence.
- `cmd/envbank/cloudflare.go` — implements bind, plan, apply, resume, verify,
  promote, and rollback with fresh confirmation and health policy.
- `e2e/live/main.go` and `scripts/e2e-live.sh` — add the marker-gated
  Cloudflare sentinel stage/promote/health/rollback/delete acceptance path and
  forbid environment-token intake.
- `internal/mcpserver/server.go` — points provider guidance at the Cloudflare
  command surface.
- `tasks/todo.md` and `tasks/history.md` — record the completed foundation,
  remaining parity/import/cutover gates, external SiftCut scope, and session
  evidence.
- `tasks/cloudflare-first-foundation-ship-manifest.md` — records this exact
  shipping boundary and its quality evidence.

Generated `.codex/skills`, dependency trees, and local `.wrangler` databases
are excluded from the shipping boundary. `.agents/project.json` did not change.

## User-goal mapping

- Cloudflare-native EnvBank maps to the Worker package, Durable Object schema,
  Access-aware client, and migration runbook.
- Upload-before-promotion secret rollout maps to the Cloudflare provider,
  atomic rollout engine, CLI promotion/rollback workflow, and encrypted
  version/deployment evidence.
- Safe provider acceptance maps to the explicit authorization marker,
  hidden-token intake, randomized binding, three health checks over at least 30
  seconds, rollback, and disposable-version cleanup.
- Gate-ordered retirement maps to the retained legacy code plus explicit parity,
  importer, staging, observation, and restore tasks.
- SiftCut's Cloudflare refactor maps to a documented external-repository
  blocker; no unsupported edits outside this workspace are claimed.

## Tests run

- `go test ./...` — passed the complete Go suite, including client, rollout,
  provider, CLI, server, recovery, testlab, and live-runner regressions.
- `go vet ./...` — passed. The existing macOS Security framework deprecation
  diagnostics are accepted because the legacy unsigned-CLI Keychain fallback
  remains intentionally supported during migration.
- `node --test extension/test/*.test.js` — passed all 15 extension tests.
- `npm run check` in `cloudflare/envbank-worker` — passed TypeScript checking.
- `npm test` in `cloudflare/envbank-worker` — passed the v1 signature golden
  test.
- `npx wrangler deploy --dry-run` — passed Worker bundling and Durable Object
  binding validation without contacting or changing a deployment.
- Local `wrangler dev` smoke — returned 200 from `/healthz` and created a vault
  with 201 through the SQLite Durable Object; the process was then stopped.
- `scripts/test-gitleaks-config.sh` — passed the history scan and expected
  synthetic-secret detection fixture.
- `gitleaks git --staged --redact --config .gitleaks.toml .` — passed the exact
  staged shipping boundary with no leaks.
- `git diff --check` — passed whitespace/error-marker validation.

Executable checks, rather than documentation-only checks, cover both the Go
and Worker implementation surfaces.

## Skipped tests

- The marked live Cloudflare acceptance was not run because no API token or
  explicitly marked disposable account/zone/Worker was placed in scope. No
  live Cloudflare state was read or changed.
- Full Go-server-versus-Worker response golden coverage, concurrent Durable
  Object mutations, replay/invitation/pagination schema cases, and migration
  import/restore journeys remain pending in `tasks/todo.md`; the current smoke
  proves runtime wiring, not complete v1 equivalence.
- The seven-day cutover observation and legacy retirement were skipped because
  staging, import, restore, and production migration have not occurred.
- SiftCut D1/R2/Queues/Workers AI/Containers and PostgreSQL importer tests were
  skipped because the `short-editor` repository is outside this workspace's
  writable scope.

## Adversarial review

Method: failure-oriented inspection of the exact Go/TypeScript/provider diff,
comparison of Worker routes against the legacy Go router and protocol structs,
and targeted checks for plaintext persistence, redirect forwarding, path
ambiguity, request bounds, provider identity drift, stage/deploy separation,
health timing, rollback, cleanup, and generated artifacts.

Findings fixed:

- Local Wrangler SQLite/WAL/SHM state was visible as untracked content;
  `.wrangler/` is now excluded from commits.
- Authenticated Worker handlers could buffer bodies without enforcing the
  legacy 1 MiB limit; all non-GET request paths now use a shared bounded reader.
- Extra path segments could be dispatched to otherwise valid resources; the
  Durable Object router now requires the exact v1 method and segment shape.
- Legacy enrollment approval returns HTTP 200 with an enrollment status, while
  the Worker returned 204; the Worker now validates the full wrapped envelope,
  rejects invitation-linked legacy approval, handles already-approved state,
  and returns the compatible public-device response.

## Residual risk

- The Worker is a staging foundation, not yet proven byte-for-byte compatible
  across every v1 success and error response. The expanded parity harness is
  the first remaining executable task and blocks production data.
- Cloudflare API behavior is covered by bounded fake transports and current
  official API contracts, but has not been exercised against a marked account.
- The migration importer does not yet exist, so no production vault can be
  moved safely and the legacy server/provider code must remain available.
- Smart Placement and North American account configuration are preferences,
  not strict residency guarantees.

## Rollback note

Revert the Cloudflare foundation commit to restore the prior client and rollout
surface. No provider deployment or production data mutation occurred, so there
is no external state to undo. Local ignored Wrangler state is disposable.

## Next command

Run `$exec` to build the cross-language v1 parity harness and close all Worker
compatibility gaps before implementing the importer.
