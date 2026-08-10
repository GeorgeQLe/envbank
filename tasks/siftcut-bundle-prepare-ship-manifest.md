# SiftCut bundle preparation ship manifest

## User goal

Implement Milestone 5 local `bundle prepare` and `bundle status` workflows,
then wrap up the feature on the primary branch.

## Changed files

- `README.md`
- `cmd/envbank/main.go`
- `cmd/envbank/bundle_test.go`
- `cmd/envbank/device_test.go`
- `docs/bundles.md`
- `internal/bundle/prepare.go`
- `internal/bundle/prepare_test.go`
- `internal/bundle/snapshot.go`
- `internal/bundle/snapshot_test.go`
- `internal/contract/manifest.go`
- `internal/contract/manifest_test.go`
- `internal/vaultobject/object.go`
- `tasks/history.md`
- `tasks/todo.md`
- `tasks/siftcut-bundle-prepare-ship-manifest.md`

## Per-file purpose

- `internal/bundle/prepare.go` implements deterministic physical naming,
  trusted JSON stdin intake, one-time generation, bounded topological
  derivation, expected-revision record writes, encrypted checkpoints, final
  concurrency checks, encrypted snapshot publication, and names-only status.
- `internal/bundle/snapshot.go` retains bounded non-secret prior revision
  evidence after records advance so recovery artifacts preserve rollout
  history without carrying values or reversible fingerprints in bookkeeping.
- `cmd/envbank/main.go` adds the `bundle prepare` and `bundle status` command
  surfaces while sharing bounded manifest loading with `bundle check`.
- `internal/contract/manifest.go` bounds logical record names so every valid
  name maps collision-free to a valid physical record name without truncation.
- `internal/vaultobject/object.go` designates the encrypted prepare-journal
  object kind.
- `cmd/envbank/bundle_test.go`, `cmd/envbank/device_test.go`, and the bundle and
  contract package tests cover the complete CLI, failure-injection, schema,
  mapping, parsing, derivation, recovery-evidence, and redaction behavior.
- `docs/bundles.md` and `README.md` document stdin safety, local-only scope,
  durability, conflicts, revision evidence, output rules, and Go memory limits.
- `tasks/todo.md` and `tasks/history.md` close Milestone 5, record the shipped
  work, and promote the provider-neutral rollout engine as the next executable
  milestone.
- This manifest records the exact quality-gated shipping boundary.

## User-goal mapping

The CLI validates the public manifest before unlocking, imports only missing
values from an exact bounded JSON object on stdin, generates missing passwords
once, derives dependents in deterministic bounded topological order, and
persists every record with an expected revision. Encrypted names-and-revisions-
only journal checkpoints make partial operations resumable. A final refetch
rejects concurrent source changes before snapshot publication, and a
post-publication status check detects changes across the publication window.

`bundle status` compares the manifest, current deterministic bundle records,
and encrypted snapshot. It reports only logical names and missing, stale, or
prepared states, propagating source staleness through derived dependencies.
Changed records retain prior revision numbers in the replacement snapshot for
encrypted recovery evidence. Neither command contacts a provider.

## Tests run

Executable verification:

- `go test ./...` passed for every Go package, including pairing tests run with
  permission to bind disposable loopback ports.
- `go test -race ./internal/bundle ./internal/contract ./cmd/envbank` passed;
  the CLI package completed in 209.614 seconds because its fixtures use the
  production passphrase KDF.
- Final focused tests passed for `internal/bundle`, `internal/contract`,
  `internal/recovery`, and `cmd/envbank` after the quality-audit revision-
  history fix.
- `go vet ./...` and `go build ./...` passed without warnings.
- `node --test extension/test/*.test.js` passed all 13 browser-extension tests.

Documentation and boundary verification:

- `gofmt -l cmd internal` and `git diff --check` passed with no output.
- Patch-scoped Gitleaks scans passed for every modified and new file. A broad
  no-git scan reported six generic-key matches solely under ignored
  `website/.next/` build output; `git check-ignore` confirmed all six paths are
  generated and excluded from the shipping boundary.

## Skipped tests

- The recovery drill was not rerun because this feature does not change the
  service database, recovery format, restore algorithm, or deployment state;
  full and focused recovery package tests passed, including snapshot carriage
  through the existing artifact-v2 object path.
- Live Railway and Clerk tests were skipped because Milestone 5 forbids
  provider contact and adds no provider adapter.
- Cross-platform builds were not repeated because the implementation uses
  portable Go APIs and `go build ./...` compiled every changed package.
- Vulnerability and license audits were not repeated because dependencies and
  module metadata are unchanged; patch secret scanning directly covered the
  new boundary.
- Website build, lint, and visual checks were not repeated because only a
  README link changed; no website source or rendered artifact changed.

## Adversarial review

An explicitly justified equivalent targeted quality sweep reviewed manifest
validation, stdin ambiguity, plaintext propagation, deterministic-name
collisions, generation retry boundaries, journal contents, derivation bounds,
dependency staleness, record/object compare-and-swap behavior, concurrent
source replacement, the snapshot publication window, recovery evidence, and
normal/error output.

The review found and fixed duplicate JSON-key acceptance, reflection of
unexpected stdin keys in errors, unbounded logical names, stale-state failure
to propagate through derived records, a publication-window verification gap,
and loss of prior revision evidence when snapshots advanced. Regression tests
cover each fix. No unresolved high- or medium-confidence finding remains.

## Residual risk

Go strings and garbage collection prevent guaranteed immediate erasure of all
plaintext copies; temporary byte buffers are overwritten where practical and
the limitation is documented. A source can change immediately after the final
status check, making a just-published snapshot stale; the next status or
prepare detects that revision mismatch, and no provider consumes the snapshot
in this milestone. The ignored local Next.js build directory contains generated
secret-shaped framework values and must remain excluded from commits.

## Rollback note

Revert the feature commit to remove the commands and preparation engine.
Existing encrypted bundle records, journals, and snapshots may remain in vaults
that used the feature; rollback does not contact or alter a provider. Retain a
recovery artifact before manually deleting any such records or objects.

## Next command

Run `$exec Implement Milestone 6 provider-neutral rollout engine.`
