# Milestone 6 provider rollout ship manifest

## User goal

Implement the provider-neutral rollout engine, then wrap up the completed
milestone on the primary branch.

## Changed files

- `docs/architecture.md`
- `internal/provider/provider.go`
- `internal/provider/provider_test.go`
- `internal/rollout/plan.go`
- `internal/rollout/engine.go`
- `internal/rollout/engine_test.go`
- `internal/rollout/state.go`
- `internal/rollout/store.go`
- `internal/rollout/store_test.go`
- `tasks/history.md`
- `tasks/todo.md`
- `tasks/milestone-6-provider-rollout-ship-manifest.md`

## Per-file purpose

- `internal/provider/provider.go` defines capability declarations, immutable
  identity and target metadata, metadata-only presence, callback-scoped secret
  requests, bounded evidence, the adapter interface, and sanitized errors.
- `internal/provider/provider_test.go` proves secret requests redact every
  formatting path, reject JSON, clear callback views, and discard arbitrary
  provider error text while retaining safe typed metadata.
- `internal/rollout/plan.go` makes plans digest-addressed and applies fixed
  expiry, ordered-action, operation, target, and record-revision validation.
- `internal/rollout/state.go` defines the encrypted per-action operation
  journal and validates status, attempts, evidence, write keys, sanitized
  errors, timestamps, and terminal-state consistency.
- `internal/rollout/store.go` persists plans and operations through encrypted
  vault objects and validates the current snapshot plus every current record
  revision before apply retrieves a value.
- `internal/rollout/engine.go` implements metadata-only planning, interactive
  and destructive confirmations, durable pre-call checkpoints, ordered writes,
  partial resume, idempotent retries, explicit reconciliation, and verified or
  limited terminal results without deployment behavior.
- `internal/rollout/engine_test.go` and `internal/rollout/store_test.go` cover
  cancellation, destructive confirmation, partial failure, expiry, staleness,
  post-expiry resume, ambiguous outcomes, non-duplication, local-load failure,
  exact current revisions, redaction, and honest verification limits.
- `docs/architecture.md` records the secret boundary, encrypted bindings,
  confirmations, state transitions, reconciliation rule, and deployment limit.
- `tasks/todo.md` closes Milestone 6 and promotes Railway identity binding and
  names-only planning as Milestone 7; `tasks/history.md` records the session.
- This manifest records the exact reviewed shipping boundary.

## User-goal mapping

The engine exposes no provider-specific or deployment behavior. Planning calls
only identity and metadata inspection, binds the provider identity and exact
target IDs to the manifest, snapshot, local record revisions, ordered actions,
and 15-minute expiry, then stores the plan as an encrypted vault object.

Apply revalidates every binding and all current referenced record revisions
before confirmation or provider writes. Each action is persisted `in_flight`
immediately before its adapter call and persisted `committed` immediately after
bounded evidence. Resume skips proven writes, reuses stable idempotency keys
when supported, and otherwise requires metadata to prove the outcome before it
continues. New apply rejects expired plans; already-confirmed operations may
resume later while retaining all identity, target, snapshot, and revision
checks. Verification reports `verified` or `limited` and never deploys.

## Tests run

Executable verification:

- `go test ./...` passed for every Go package, including loopback pairing tests
  run with the required outside-sandbox permission.
- `go test -race ./internal/provider ./internal/rollout` passed for both changed
  concurrency-sensitive packages.
- Focused `go test` runs passed for `internal/provider`, `internal/rollout`, and
  `internal/bundle` after the adversarial-review fixes.
- `go vet ./...` passed without warnings.
- A clean CLI build passed using writable Go build and module caches.
- `node --test extension/test/*.test.js` passed all 13 extension tests.

Documentation and boundary verification:

- `gofmt` and `git diff --check` passed with no output.
- `scripts/test-gitleaks-config.sh` passed; its `synthetic secret detected`
  diagnostic is the harness's expected proof that the test fixture is caught.
- A final patch-scoped Gitleaks scan passed for the complete shipping boundary.
- Generated `.claude/skills/**` and `.codex/skills/**` roots are already
  untracked and ignored; the authorized hygiene operation required no diff.

## Skipped tests

- Full-repository race testing was not repeated because the focused race run
  covers every changed source package and the full non-race suite covers all
  integration packages.
- The recovery drill was skipped because this milestone changes neither the
  server schema nor recovery format; the full recovery tests passed and plans
  and operations use the existing encrypted vault-object path.
- Live-provider tests were skipped because Milestone 6 intentionally has only
  the provider-neutral interface and fake adapter. Railway is Milestone 7.
- Website lint, typecheck, build, and visual checks were skipped because no
  website source or rendered asset changed.
- Cross-platform builds were skipped because the new code uses portable Go
  APIs and the changed CLI dependency graph built successfully.
- `govulncheck` was unavailable locally. Dependencies and module metadata are
  unchanged, so this is an accepted residual validation gap rather than a new
  dependency risk.

## Adversarial review

An explicitly justified equivalent targeted quality sweep reviewed plaintext
lifetimes, formatting and JSON behavior, arbitrary error/body propagation,
evidence bounds, plan expiry and digest coverage, target and identity drift,
record changes before and during apply, cancellation boundaries, journal write
ordering, crashes before and after provider calls, idempotent and non-idempotent
resume, partial verification, and accidental deployment behavior.

The review found and fixed four material edge cases: snapshot validation did
not compare every current record before the first write; local value loading
occurred after the `in_flight` checkpoint and could falsely imply an ambiguous
provider call; callback consumers could accidentally retain the request's
backing secret slice; and decrypted operation journals did not revalidate
sanitized error metadata and write-key shape. It also stopped labeling a local
idempotency key as a provider operation ID during inspection reconciliation.
Regression tests cover the revision and pre-call-state fixes plus callback-view
clearing. No unresolved high- or medium-confidence finding remains.

## Residual risk

Go strings and garbage collection prevent guaranteed erasure of every local
plaintext copy, though request-owned and callback-view byte slices are cleared.
Adapters remain responsible for constructing provider request bodies only in
memory and for not copying callback bytes into logs or durable state. This
milestone validates encrypted store bindings with existing client encryption
tests and focused binding tests, but does not contact a live provider; exact
Railway API behavior remains blocked on the next provider-specific milestone.

## Rollback note

Revert the Milestone 6 feature commit to remove the provider package and
rollout engine. Encrypted plan or operation objects created by downstream
development may remain opaque in a vault but are not read by the prior build;
rollback performs no provider write, revocation, verification, or deployment.

## Next command

Run `$exec Implement Milestone 7 Railway identity binding and names-only
planning.`
