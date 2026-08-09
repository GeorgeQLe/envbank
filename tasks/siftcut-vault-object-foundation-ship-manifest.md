# SiftCut vault-object foundation ship manifest

## User goal

Add encrypted vault-object CRUD from the active SiftCut staging milestone, then
wrap up the session by updating project records, committing, and pushing the
coherent foundation slice.

## Changed files

- `cmd/envbank/recovery.go`
- `cmd/envbank/recovery_test.go`
- `docs/architecture.md`
- `docs/backup-and-restore.md`
- `docs/cryptographic-review.md`
- `docs/recovery.md`
- `internal/bundle/snapshot.go`
- `internal/bundle/snapshot_test.go`
- `internal/client/api.go`
- `internal/client/objects.go`
- `internal/protocol/protocol.go`
- `internal/recovery/artifact.go`
- `internal/recovery/artifact_test.go`
- `internal/rollout/plan.go`
- `internal/rollout/plan_test.go`
- `internal/server/events.go`
- `internal/server/events_test.go`
- `internal/server/integration_test.go`
- `internal/server/invitations_test.go`
- `internal/server/server.go`
- `internal/vaultobject/object.go`
- `internal/vaultobject/object_test.go`
- `scripts/recovery-drill.sh`
- `tasks/history.md`
- `tasks/siftcut-vault-object-foundation-ship-manifest.md`
- `tasks/todo.md`

The upstream public-website commit was already present on `origin/main` before
this boundary was pushed. Its website, CI, README, and website ship-manifest
files are not owned by this session and are not part of this feature commit.
The shared task files are reconciled so both shipped milestones remain recorded.

## Per-file purpose

- `internal/protocol/protocol.go`, `internal/client/api.go`, and
  `internal/client/objects.go`: define the opaque wire contract and authenticated
  low-level/high-level client CRUD, including local encryption and optimistic
  revisions.
- `internal/vaultobject/object.go`: derive domain-separated HMAC identifiers,
  encrypt with vault/object-bound AAD, validate bounded plaintext envelopes,
  and reject metadata substitution or duplicate server state.
- `internal/server/server.go`: add the SQLite version-6 object table and
  migration, authenticated opaque list/get/put/delete routes, bounded envelope
  validation, and compare-and-swap updates and deletes.
- `internal/server/events.go`: extend the privacy-preserving event vocabulary
  for object operations without recording object IDs or plaintext metadata.
- `internal/bundle/snapshot.go` and `internal/rollout/plan.go`: add explicit
  version-1 bundle-snapshot and 15-minute provider-plan schemas with complete
  mappings, canonical UTC timestamps, target/action bindings, and plan digests.
- `internal/recovery/artifact.go` and `cmd/envbank/recovery.go`: emit recovery
  artifact v2 with decrypted vault objects inside the outer encryption, retain
  v1 reads, reset restored sync revisions, and resume with fail-closed target
  verification.
- The corresponding `_test.go` files cover cryptographic separation,
  optimistic conflicts, server opacity and events, malformed input, schema
  migration, typed schemas, artifact compatibility, and CLI restore behavior.
- `docs/architecture.md`, `docs/cryptographic-review.md`, and `docs/recovery.md`:
  document the exact new object-ID/AAD constructions and recovery-v2 behavior.
- `docs/backup-and-restore.md` and `scripts/recovery-drill.sh`: advance the
  recovery drill to SQLite schema version 6 and prevent an unrelated listener
  from producing a false-positive service-health result.
- `tasks/todo.md` and `tasks/history.md`: close the foundation item and record
  the implementation while preserving the independently shipped website work.
- This manifest records the exact shipping boundary and evidence.

## User-goal mapping

The protocol, client, and server changes provide the requested encrypted CRUD
while revealing only opaque IDs, ciphertext, revisions, and timestamps to the
sync service. Domain-separated IDs and AAD prevent record/object, kind, ID, and
vault substitution. Bundle snapshots and provider plans provide the typed
payloads required by the milestone. Recovery v2 ensures that this new durable
state participates in encrypted backup and resumable restore without breaking
version-1 artifacts.

## Tests run

- `go test ./...` — passed for every Go package on the source boundary.
- `go vet ./...` — passed with no warnings.
- `go build ./...` — passed for every Go command and package.
- `go test -race ./internal/server ./internal/client ./internal/vaultobject
  ./internal/recovery ./internal/bundle ./internal/rollout ./cmd/envbank` —
  passed for all changed executable packages; the CLI package completed in
  281.767 seconds because recovery tests intentionally use the production KDF.
- `go test ./internal/server` — passed after the final malformed-envelope test
  split, covering both negative revisions and invalid encrypted blobs.
- `node --test extension/test/*.test.js` — 13/13 extension regressions passed.
- `./scripts/recovery-drill.sh --port 27337` — passed outside the command
  sandbox with schema version 6, database checks, permissions, device state,
  access history, restart persistence, truncation rejection, and future-schema
  rejection all verified. A negative run against the occupied default port
  failed safely before mutation; a sandboxed retry then reached the known Go
  module-cache write restriction before the approved run passed.
- `npm --prefix website run lint`, `npm --prefix website run typecheck`, and
  `npm --prefix website run build` — passed after fast-forwarding the already-
  shipped website commit, proving the final integrated branch remained clean.
- `gitleaks detect --no-banner` — scanned repository history and the worktree;
  no leaks found.
- `make secret-scan-test` — the synthetic credential was detected as required.
- `gofmt -l cmd internal` and `git diff --check` — passed with no output.
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` — the official
  scanner found no vulnerabilities in called code or imported dependencies.

## Skipped tests

- Live Railway and Clerk tests are excluded because this foundation slice does
  no provider I/O and the accepted plan forbids use of real SiftCut credentials
  in automated tests.
- Manual visual testing is not applicable because no UI or rendered artifact
  changed in this feature boundary; the extension regression suite still ran.
- Cross-platform builds were not repeated because the changed code uses only
  portable Go APIs and `go build ./...` plus the full package tests compiled
  every changed package on the supported development platform.

## Adversarial review

A failure-oriented changed-file review traced opaque object metadata from HMAC
derivation through AEAD, signed HTTP requests, SQLite persistence, recovery,
and typed payload validation. It looked for plaintext server leakage, weak ID
domain separation, cross-vault/kind/AAD substitution, clear-metadata tampering,
duplicate list state, malformed base64/AEAD envelopes, stale create/update/delete
revisions, noncanonical timestamps, incomplete snapshot mappings, duplicate
plan actions, recovery downgrade breakage, conflicting resume targets, and
migration data loss.

The review found that list decryption initially accepted duplicate returned
objects, snapshot mappings could omit source/revision entries, plan timestamps
could use noncanonical offsets, and duplicate plan action IDs were accepted.
Those cases now fail closed and have regression tests. It also found that the
server accepted negative expected revisions and structurally invalid encrypted
blobs; both are rejected with direct integration coverage. No accepted review
finding remains unfixed.

## Residual risk

This slice does not yet prepare bundles or contact providers. The new snapshot
and plan types are therefore validated in package tests rather than through a
complete provider rollout. Users would observe this as unavailable
`bundle prepare`, `bundle status`, and provider commands, not as partial remote
mutation. A disposable-provider milestone must validate adapter identity and
capabilities before these schemas authorize external changes.

The first pre-ship recovery drill collided with an unrelated local showcase
service on port 17337 before the occupied-port guard existed and created one
empty `recovery-drill` vault there. The drill wrote no secret records before it
detected the mismatch. Removing that external vault requires operator approval;
the retained temporary device credentials were deleted.

## Rollback note

Revert the feature commit to remove object CRUD, schemas, and recovery-v2
emission. Servers that already migrated to schema version 6 would require an
explicit forward cleanup migration if physical removal of the empty
`vault_objects` table were desired; version-2 recovery artifacts should be
retained because older binaries cannot read them. No provider state is changed
by this slice.

## Next command

Obtain operator approval and remove the accidental empty `recovery-drill` vault
from the separate local showcase service.
