# $0 end-to-end execution ship manifest

Date: 2026-08-15

## Implemented and executed

- `go test ./...`: passed, including the expanded fault/restart matrix,
  circuit-open lease release, lifecycle policy expiry, native-host protocol,
  CLI/recovery, provider emulator, and plaintext persistence regressions.
- `node --test extension/test/*.test.js`: passed, including the new bounded
  silent-native-host request test.
- Binary `envbank-testlab` restart matrix: passed with encrypted SQLite and
  stdout/state leakage scan.
- `make e2e`: passed locally through Go, testlab, recovery, extension, website
  lint/typecheck/build/live smoke, and final observable-output scan.
- `make e2e-release-local`: passed all four archive/extraction/version and
  checksum checks, disposable container health, website production build/live
  smoke, and randomized image/container cleanup.
- `make e2e-browser`: passed in headed Chrome for Testing 151 with the pinned
  Playwright 1.62.1 harness, disposable profile/home/manifest, test-only native
  host, disconnect/timeout handling, and observable-surface marker scan.
- Randomized macOS Keychain approval path: passed, including wrong-account,
  deletion, and post-deletion absence checks.
- Randomized macOS Keychain cancellation path: passed after the user selected
  **Deny**; cancellation did not return the synthetic value and cleanup ran.
- Production native-host installer no-overwrite guard: implemented and covered
  by a regression test that preserves an existing manifest byte-for-byte.
- Chrome for Testing native-host target: implemented for the distinct Chrome
  146+ user manifest path, with matching uninstall behavior and path tests.
- Real Chrome for Testing fill through the production native host: manually
  verified with the randomized sentinel, exact loopback origin, and a
  disposable profile; the ordinary Chrome profile remained untouched.
- Real browser Keychain denial: manually verified. The denied request failed
  closed, the password field remained empty, and the randomized installation,
  Keychain item, host, locator, profile, and diagnostic files were removed.
- Isolated-profile native-host installation: implemented with
  `--profile-dir`, exclusive manifest creation, matching uninstall behavior,
  and path validation tests. Chrome Safe Storage is isolated with its mock
  browser Keychain while EnvBank continues to exercise the real macOS
  Keychain.

## Implemented, release-machine execution required

- `make e2e-keychain`: every human-observed surface was executed on the release
  Mac: randomized approval/cancellation, production host installation, one real
  Chrome fill, denial with an empty destination field, fail-closed unavailable
  state, and cleanup. The wrapper itself exited before its final scan because
  its source changed during that long-running interactive invocation; the
  current script passes shell parsing and the remaining scans are covered by
  the offline/browser gates.
- Stripe, Clerk Development, and Railway Free probes: not executed; they are
  deliberately opt-in and require dedicated marked local resources.
- Vercel lifecycle: `PRODUCTION_ADAPTER_UNAVAILABLE` by design. Website HTTP
  route validation remains in the offline and release-local gates.

No provider credentials, credential values, screenshots of secret-bearing
pages, or provider recovery records were created or committed.

## Pre-commit quality gate

### User goal

Deliver the `$0` end-to-end testing milestone: a required offline merge gate,
local release and browser checks, interactive macOS Keychain acceptance, and
strictly opt-in free-provider probes with disposable state and secret-free
evidence.

### Changed files and per-file purpose

- `.github/workflows/ci.yml` — makes the offline E2E gate a required CI surface.
- `Makefile` — exposes the five stable E2E developer commands.
- `CONTRIBUTING.md`, `README.md` — document the gate, browser targets, and the
  remediated minimum Go version.
- `Dockerfile`, `go.mod`, `docs/production-deployment.md` — advance Go from
  1.25.12 to vulnerability-fixed 1.25.13 and pin the official Alpine image
  index by digest.
- `cmd/envbank/main.go`, `cmd/envbank/main_test.go` — add browser-target and
  isolated-profile manifest paths, exclusive no-overwrite creation, matching
  uninstall behavior, and regression coverage.
- `extension/core.js`, `extension/test/core.test.js` — bound native-host calls,
  allow a five-minute user-presence window, and test timeout/disconnect cleanup.
- `internal/keychain/keychain_darwin.go` — retain the modern user-presence path
  and add an unsigned-CLI file-Keychain fallback with no trusted applications.
- `internal/keychain/keychain_integration_darwin_test.go` — add an explicit
  cancellation-only randomized Keychain check with cleanup.
- `internal/testlab/testlab_test.go` — extend restart/fault, circuit-open, and
  concurrent-lease terminal-state coverage.
- `scripts/recovery-drill.sh` — choose an unused loopback port by default.
- `scripts/e2e.sh`, `scripts/testlab-matrix.sh` — implement the hermetic merge
  gate, binary restart matrix, and observable-output scans.
- `scripts/e2e-release-local.sh` — validate cross-built archives, versions,
  checksums, optional container health, and website production smoke.
- `scripts/e2e-browser.sh`, `e2e/browser/package.json`,
  `e2e/browser/package-lock.json`, `e2e/browser/run.mjs`, and
  `e2e/browser/nativehost/main.go` — provide the pinned disposable headed
  browser harness and in-memory production-framing host.
- `scripts/e2e-keychain.sh` — provide the interactive production-host check,
  isolated profile, unambiguous approval/denial handoffs, persistence scan, and
  cleanup.
- `scripts/e2e-live.sh`, `e2e/live/main.go`, `e2e/live/main_test.go` — provide
  marked-target Stripe, Clerk, Railway, and unsupported-Vercel behavior with
  hidden/Keychain credentials, atomic private recovery state, and fail-closed
  tests.
- `docs/e2e-testing.md` — document prerequisites, prompts, recovery, cleanup,
  evidence, and `$0` limitations.
- `docs/roadmap.md`, `tasks/todo.md`, `tasks/history.md` — record milestone
  progress, the remaining provider observations, and completed evidence.
- `tasks/lessons.md` — encode the user correction about distinguishing repeated
  approval and denial prompts.
- `tasks/zero-dollar-e2e-ship-manifest.md` — record the exact shipping boundary,
  execution evidence, review findings, and residual risk.

All listed changes belong to this session. No unrelated worktree changes are
included, and generated `.codex/skills` or `.claude/skills` artifacts are not
part of the boundary.

### User-goal mapping

- Offline merge safety maps to the CI job, `make e2e`, testlab fault matrix,
  recovery drill, website smoke, and marker scans.
- Browser and macOS acceptance map to the pinned Playwright harness,
  production native-host installer, isolated profile support, Keychain tests,
  and interactive runbook.
- Free-provider acceptance maps to the authorization guard, marked immutable
  targets, hidden/Keychain credential intake, bounded Stripe cleanup, Clerk
  names/revisions-only checks, deploy-suppressed Railway sentinel, and explicit
  Vercel unsupported result.
- Release confidence maps to cross-build/archive/checksum/container checks and
  the Go 1.25.13 vulnerability remediation found during pre-ship validation.

### Tests run

- `make e2e` — passed on the final diff: Go, binary restart matrix, recovery,
  extension, website lint/typecheck/build/live smoke, and leakage scan.
- `make e2e-browser` — passed headed Chrome for Testing acceptance and marker
  scan on a disposable profile.
- `make e2e-release-local` — passed four cross-build archives, extraction,
  version/linkage, checksums, the Go 1.25.13 container health check, and website
  production smoke.
- `make race` — passed the complete Go race suite on Go 1.25.13.
- `make vet` — passed; the intentional deprecated file-Keychain compatibility
  API emitted the accepted warning described under residual risk.
- `/Users/georgele/go/bin/govulncheck ./...` — passed after the 1.25.13 upgrade
  with `No vulnerabilities found`.
- `make secret-scan-test` — passed the full-history Gitleaks regression and
  synthetic-secret assertion.
- `go mod verify && go mod tidy -diff` — passed with no module drift.
- `go test ./e2e/live ./cmd/envbank ./internal/keychain` — passed focused live,
  installer/profile, and Keychain coverage.
- `bash -n` for every new/changed E2E shell script, `node --check` for the
  browser runner, and `git diff --check` — passed.
- Manual release-Mac observation — randomized Keychain approval and denial,
  production-host Chrome fill, fail-closed denial, empty destination field,
  and cleanup were verified without secret-bearing screenshots or output.

### Skipped tests

- Stripe, Clerk Development, and Railway live probes were not run because no
  dedicated marked provider resources or credentials were placed in scope.
  Their local contract tests and hermetic adapters passed; the real probes
  remain the sole executable item in `tasks/todo.md`.
- Vercel live lifecycle was not run because no production adapter exists; the
  runner reports `PRODUCTION_ADAPTER_UNAVAILABLE`, while emulator and public
  website HTTP coverage passed.
- The interactive Keychain wrapper was not repeated as one uninterrupted final
  invocation after its source stabilized because doing so would repeat multiple
  human authentication prompts. Every human-observed surface was completed,
  the current script parses, focused Keychain tests pass, and generated state
  was independently confirmed absent.

### Adversarial review

Method: failure-oriented review of every changed executable surface plus
targeted scans for port selection, marker persistence, recovery-state modes,
credential inputs, cleanup paths, and browser manifest locations.

Findings fixed:

- Existing live-provider recovery files could retain permissive modes; recovery
  writes are now atomic mode-`0600` replacements and the directory is forced to
  mode `0700`, with a regression test.
- The Keychain persistence scan omitted SQLite WAL/SHM bytes; it now includes
  the database, sidecars, encrypted config, profile, and logs.
- Website smokes selected random ports without proving availability; both now
  ask the OS for an unused loopback port before launch.
- The security lane exposed five reachable Go 1.25.12 standard-library
  vulnerabilities; all toolchain/container/documentation pins moved to
  1.25.13, and the vulnerability scan and container gate now pass.
- Repeated generic authentication instructions caused an approval during a
  denial check; the runner and lesson now label every handoff as an explicit
  approval or denial check.
- The required Actions E2E job failed inside the binary matrix while discarding
  the only useful child-process output. Failure handling now emits at most 8192
  bytes per known output stream, but only after a full marker scan; diagnostics
  are withheld entirely if any synthetic plaintext is present.
- Leakage scanners used match-printing mode, which could echo the marker they
  were meant to detect. They now use quiet detection and report only fixed
  failure text.
- GitHub's Ubuntu image did not provide ripgrep, although the offline gate used
  it for assertions and marker scans. Testlab assertions now use ubiquitous
  tooling, and marker scans select ripgrep when present with a quiet recursive
  grep fallback when it is absent.

**Correction enforcement:** `tasks/lessons.md` records the repeatable rule, and
`scripts/e2e-keychain.sh` enforces distinct **APPROVAL CHECK — Allow Once** and
**DENIAL CHECK — Deny** prompts at both integration and real-browser stages.

### Residual risk

- Real provider behavior remains unverified until dedicated marked Stripe,
  Clerk Development, and Railway Free resources are supplied locally. Those
  probes fail closed without the exact marker and explicit authorization.
- The fallback `SecAccessCreate` API is deprecated by macOS. Its use is
  intentionally limited to unsigned CLI builds that receive
  `errSecMissingEntitlement`; signed builds continue to prefer the modern
  user-presence Keychain path. Vet/race warnings are accepted for this reason.
- Loopback selection necessarily has a small bind race between releasing the
  probe socket and starting the child server; startup health and ownership
  checks fail closed if another process wins.

### Rollback note

Revert the shipping commits to remove the E2E interfaces and Go-pin update. If
a failed manual run leaves native-host state, run the matching
`envbank browser-uninstall --browser chrome-for-testing --profile-dir <profile>
--delete-keychain`; the runner refuses unrelated existing installations.

### Next command

Install the guided-walkthrough pack before preparing the first marked live
provider observation: `npx skillpacks install guided-walkthrough`.
