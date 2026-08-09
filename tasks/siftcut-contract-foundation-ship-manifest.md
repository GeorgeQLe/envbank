# SiftCut contract foundation ship manifest

## User goal

Start implementing the accepted SiftCut staging implementation plan, then wrap
up the session by updating project task records, committing, and pushing the
coherent first implementation slice.

## Changed files

- `cmd/envbank/main.go`
- `cmd/envbank/main_test.go`
- `docs/roadmap.md`
- `docs/siftcut-implementation-plan.md`
- `docs/siftcut-use-case-gaps.md`
- `go.mod`
- `go.sum`
- `internal/contract/manifest.go`
- `internal/contract/manifest_test.go`
- `internal/contract/template.go`
- `tasks/history.md`
- `tasks/siftcut-contract-foundation-ship-manifest.md`
- `tasks/todo.md`

The three SiftCut documentation changes predated the source-code slice in the
same worktree. They are intentionally included because they define the user-
accepted contract, security boundary, delivery sequence, and roadmap link that
the implementation follows. No unrelated worktree changes are included.

## Per-file purpose

- `cmd/envbank/main.go`: dispatch and document the read-only
  `envbank bundle check --manifest PATH` command and emit bounded, names-only
  validation output.
- `cmd/envbank/main_test.go`: prove the new command reports only approved public
  contract metadata and does not print logical record names or target names.
- `docs/roadmap.md`: connect the product roadmap to the concrete SiftCut gap
  analysis.
- `docs/siftcut-use-case-gaps.md`: define the motivating workflow, missing
  capabilities, security invariants, and acceptance criteria.
- `docs/siftcut-implementation-plan.md`: define architecture, capability gates,
  phased delivery, test matrix, and definition of done.
- `go.mod` and `go.sum`: pin the maintained YAML v3 parser and checksums.
- `internal/contract/manifest.go`: add typed manifest structures, strict
  data-only YAML inspection, known-field decoding, bounded semantic validation,
  deterministic derivation ordering, canonical JSON, and SHA-256 digests.
- `internal/contract/template.go`: parse derivations into literal/reference AST
  nodes without expanding secret values.
- `internal/contract/manifest_test.go`: cover valid SiftCut-shaped contracts,
  digest stability, malicious YAML, semantic failures, cycles, limits,
  derivation AST, redacted invalid-type errors, and a fuzz corpus.
- `tasks/todo.md`: make encrypted vault-object CRUD the next executable SiftCut
  milestone item.
- `tasks/history.md`: record the completed planning and contract work.
- `tasks/siftcut-contract-foundation-ship-manifest.md`: record this exact
  shipping boundary and its evidence.

## User-goal mapping

The planning documents establish what "implement SiftCut" means without
authorizing real-provider mutation. The contract package implements Phase 1's
first safe dependency: malformed or ambiguous manifests fail before vault or
provider access, valid manifests receive stable public digests, and derivation
dependencies can be ordered without evaluating values. The CLI exposes that
capability as the planned read-only `bundle check` command. Tests enforce the
zero-plaintext-output boundary. Task records identify the next foundation work
rather than implying the full SiftCut MVP is complete.

## Tests run

- `go test ./...` — passed for all Go packages on the final source boundary.
- `go vet ./...` — passed on the final source boundary with no warnings.
- `go build ./...` — passed for every Go command and package.
- `node --test extension/test/*.test.js` — 13/13 passed with no warnings.
- `go test -race ./internal/contract ./cmd/envbank` — passed before the final
  AST representation fix, covering the new CLI and its existing auth paths.
- `go test -race ./internal/contract` — passed after the final AST and
  error-redaction fixes.
- `go test ./internal/contract -run '^$' -fuzz '^FuzzParse$' -fuzztime=5s` —
  passed 5,076 executions with 22 additional interesting inputs and no crash.
- `go test ./internal/contract ./cmd/envbank` — passed after upstream `main`
  integration and after the AST/error-redaction review fixes.
- `gofmt -l .` and `git diff --check` — passed with no output.
- `gitleaks detect --no-banner` — scanned the repository and final worktree
  with no leaks found.
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` — no vulnerabilities
  found in called code or imported dependencies.

## Skipped tests

- Live Railway and Clerk checks are deliberately excluded: the accepted plan
  requires disposable provider credentials and separate capability reports,
  while this slice performs no provider I/O.
- Browser/manual visual validation is not applicable because no UI or rendered
  artifact changed; the extension suite still passed as regression coverage.
- A globally installed `govulncheck` binary was unavailable, but the official
  scanner was run successfully through `go run`; no vulnerability check was
  therefore left uncovered.

## Adversarial review

A failure-oriented changed-file review traced untrusted YAML through raw-node
inspection, typed decoding, semantic validation, digesting, and CLI output. It
checked ambiguity features, unbounded input, source-field confusion, missing
references, nondeterministic map iteration, derivation cycles, error/output
plaintext, and accidental vault/provider contact. The review found that the
first placeholder parser returned only references rather than the literal and
reference AST required by the plan; it was replaced with an explicit AST. It
also found missing direct proof that typed decode failures redact scalar data;
a unique sentinel regression test was added. No accepted review finding remains
unfixed in this slice.

## Residual risk

This is only the first Phase 1 slice. It does not yet provide encrypted vault
objects, bundle snapshots, `bundle status`, preparation, provider capability
reports, provider adapters, or recovery v2. Manifest limits and schemas may
need additive revision before a real SiftCut manifest is owner-approved, and
expanded derived-value bounds remain the responsibility of the later trusted
evaluator. Users would notice these limitations as unavailable commands, not
as partial provider mutation, because `bundle check` is read-only.

## Rollback note

Revert the shipping commit to remove the command, contract package, dependency,
planning/task records, and tests together. No data migration, provider state,
vault state, or deployment is created by this slice.

## Next command

`$exec Implement A2 encrypted vault-object CRUD, bundle/plan schemas, and recovery artifact v2 from docs/siftcut-implementation-plan.md`
