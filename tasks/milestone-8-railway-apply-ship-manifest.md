# Milestones 7–8 Railway rollout ship manifest

## User goal

Ship the previously uncommitted Milestone 7 Railway identity/names-only base
together with Milestone 8 separately confirmed writes, durable resume, and
sanitized names-only verification, without provider value reads, blind
deletion, or deployment mutations.

## Changed files and per-file purpose

- `cmd/envbank/main.go` — adds Railway bind, plan, apply, resume, verify,
  interactive confirmation, encrypted evidence selection, and sanitized
  operator output.
- `cmd/envbank/railway_test.go` — exercises the encrypted CLI workflow against
  a loopback GraphQL server, including partial failure and resume.
- `docs/architecture.md` — records the provider identity, plan, checkpoint,
  retry, verification, and no-deploy boundaries.
- `docs/bundles.md` — documents operator commands and names-only limitations.
- `go.mod` — promotes the existing `go-isatty` module to a direct dependency
  for terminal-only apply confirmation.
- `internal/bundle/load.go` — loads and strictly validates the current
  encrypted bundle snapshot for planning.
- `internal/provider/provider.go` — extends the provider-neutral capability
  contract with semantic write idempotency.
- `internal/provider/railway/adapter.go` — implements bounded Railway GraphQL
  identity/target reads and the sole allowlisted `variableUpsert` mutation
  with `skipDeploys: true`; requires the requested environment name and
  token-scoped ID on one unique metadata node and treats unusable successful
  write responses as ambiguous.
- `internal/provider/railway/adapter_test.go` — covers authentication, target
  drift, cross-environment name/ID rejection, response redaction, ambiguous
  malformed-write responses, HTTP-status retry classes, mutation shape, and
  read-free verification.
- `internal/provider/railway/credential.go` — defines bundle-scoped Keychain
  credential storage and names-only loading.
- `internal/provider/railway/credential_test.go` — covers account derivation,
  missing credentials, and credential-output redaction.
- `internal/provider/railway/planner.go` — binds the exact four SiftCut
  services and builds deterministic names plus safe upsert actions.
- `internal/provider/railway/planner_test.go` — covers exact service shape,
  deterministic ordering, public constants, absence, and record revisions.
- `internal/rollout/engine.go` — permits confirmed names-only-plan actions,
  supports semantically idempotent ambiguous retries, and exports the canonical
  full plan/operation binding check used by verification.
- `internal/rollout/engine_test.go` — covers names-only non-action plans and
  existing confirmation, resume, reconciliation, and verification behavior.
- `internal/rollout/plan.go` — adds names-only plan entries, public-constant
  action sources, duplicate-target rejection, and action/name correspondence.
- `internal/rollout/plan_test.go` — covers names-only digests, invalid state
  substitution, and confirmed action validation.
- `internal/rollout/store.go` — validates names as well as actions against the
  current encrypted snapshot and record revisions.
- `internal/rollout/store_test.go` — covers stale names-only bindings.
- `tasks/history.md` — records the Milestone 7 and 8 implementation evidence.
- `tasks/todo.md` — marks both milestones complete.
- `tasks/milestone-7-railway-names-only-ship-manifest.md` — preserves the
  Milestone 7 boundary and handoff into Milestone 8.
- `tasks/milestone-8-railway-apply-ship-manifest.md` — records this exact
  combined shipping boundary and quality gate.

## User-goal mapping

- Separately confirmed writes: `railway apply` accepts only an encrypted,
  unexpired plan, revalidates credential identity, target, snapshot, manifest,
  services, and record revisions, then requires an interactive terminal
  confirmation immediately before provider writes.
- Safe Railway mutation: the adapter contains one mutation document,
  single-variable `variableUpsert` with `skipDeploys: true`; intended absence
  and unresolved imports never become actions.
- Durable resume: every action is persisted `in_flight` before HTTP and
  `committed` after success; resume skips committed writes and safely repeats
  an ambiguous exact upsert because the same service/name/value write is
  semantically idempotent and cannot deploy.
- Names-only verification: immutable metadata and the current snapshot are
  revalidated, remote presence remains honestly `unknown`, and local committed
  evidence is reported separately from uninspected deployed state.
- Forbidden operations: there is no variable-value query, deletion,
  staged-change commit, deploy, redeploy, restart, domain, service-create, or
  service-delete GraphQL document or CLI route.

## Tests run

Executable verification completed successfully on 2026-08-09:

- `go test ./internal/provider/railway ./internal/rollout ./cmd/envbank`
- `go vet ./internal/provider/railway ./internal/rollout ./cmd/envbank`
- `go test ./...`
- `go test -race ./internal/provider/... ./internal/rollout ./cmd/envbank`
- `go vet ./...`
- `scripts/test-gitleaks-config.sh`
- `gitleaks dir --redact --config .gitleaks.toml .`

Documentation/task and repository checks completed successfully:

- `git diff --check`
- `go mod tidy` produced only the expected direct-dependency classification.
- No `scripts/audit-task-docs.mjs` exists, so no task-doc audit command applies.

The loopback CLI test injects a failure after one committed write, proves
resume does not repeat that write, completes limited names-only verification,
and rejects secret/provider-body leakage. Adapter and rollout tests cover the
operation allowlist, `skipDeploys: true`, target drift, error sanitization,
stale/expired plans, cancellation, partial failure, semantic idempotency,
non-idempotent reconciliation, and bounded persisted evidence.

## Skipped tests

- No live Railway or real SiftCut test was run because automated shipping must
  not use real provider credentials or mutate a real environment.
- The production terminal prompt was not driven through an OS PTY; its
  confirmation callback is covered through injected CLI confirmation and the
  rollout engine's cancellation/no-write tests. A real PTY smoke test would
  require a disposable Railway target to validate the complete provider path.
- No deployment test applies because the implementation deliberately contains
  no deployment command and this repository has no `deploy.md` or
  `tasks/deploy.md` manual deploy contract.

## Adversarial review

A targeted, threat-focused review inspected the exact diff for credential and
value leakage, unsafe error propagation, non-interactive mutation paths,
identity/target drift, stale snapshot or record use, ambiguous response retry,
duplicate actions, blind deletion, and forbidden deployment operations.

Findings fixed before shipping:

- Railway transport and response byte buffers are wiped after use where Go
  permits; arbitrary response bodies remain excluded from persisted errors.
- Names-only action plans now reject duplicate variable targets and actions
  that do not exactly match a desired-present name.
- Semantic idempotency is represented separately from provider idempotency
  keys, preserving reconciliation for genuinely non-idempotent adapters while
  allowing exact Railway upsert resume after an ambiguous response.
- CLI verification now uses the rollout package's canonical full
  plan/operation binding check instead of duplicating only a subset.
- Verification reports incomplete operations as incomplete and cannot claim
  deployment readiness before the operation reaches a terminal state.
- PR #22 review found that separate environment nodes could independently
  satisfy the requested name and token-scoped ID. Binding now requires one
  unique node to match both while retaining the duplicate-name and duplicate-ID
  rejection, with a production-name/staging-ID regression returning
  `ENVIRONMENT_MISMATCH`.
- PR #22 review found that an HTTP 2xx Railway write with an unreadable or
  malformed response could be recorded as definitively failed after the
  provider had committed it. Body-read failures, oversized bodies, malformed
  and null GraphQL envelopes, GraphQL errors, and invalid mutation-result
  decoding now return sanitized `RetryAmbiguous` errors. Adapter regressions
  cover every path and preserve safe retry for 429, ambiguous retry for
  write-side 5xx, and no retry for definitive 4xx responses.
- A full-tree secret scan found six generated Next.js cache values under the
  ignored `website/.next` directory. The cache was moved intact to
  `/tmp/envbank-website-next-pre-ship-20260809`; a second full-tree scan found
  no leaks, and no cache file entered the shipping boundary.

No unresolved test failures, warnings, secret findings, or quality-gate
blockers remain.

## Residual risk

Railway exposes variable names only through a query that also returns values,
so remote presence and intended absence cannot be proven. Verification is
deliberately limited and does not attest deployed state. Public destination
imports remain non-actions until a later trusted-intake milestone stores their
values locally. Go strings created for HTTP headers and JSON string fields
cannot be guaranteed to be erased immediately, although owned byte buffers are
wiped. Rate-limit responses stop the operation for operator-controlled resume;
there is no automatic retry loop. macOS Keychain remains the sole supported
credential store.

Malformed successful write responses can require an exact idempotent upsert on
resume even when Railway did not commit the first request; this is deliberate
and safe only while the allowlisted mutation retains its exact-upsert semantics
and `skipDeploys: true`. Binding still trusts Railway's token identity and
project metadata responses, so provider-side identity semantics remain an
external dependency despite same-node and uniqueness enforcement.

## Rollback note

Revert the Milestones 7–8 feature commit. Already staged Railway variable
changes remain provider-side and must be reviewed manually; rollback must not
deploy, delete, or overwrite them. Encrypted plan/operation objects may remain
opaque in the vault. Remove the bundle-scoped Keychain item separately only if
credential cleanup is explicitly required.

## Next command

None until a new executable milestone is promoted into `tasks/todo.md`.
