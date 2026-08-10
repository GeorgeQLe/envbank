# Milestone 7 Railway identity binding and names-only planning ship manifest

## User goal

Implement Railway identity binding and names-only planning without reading
provider values, writing provider state, or mutating deployments.

## Changed files

- `cmd/envbank/main.go`
- `cmd/envbank/railway_test.go`
- `docs/architecture.md`
- `docs/bundles.md`
- `internal/bundle/load.go`
- `internal/provider/railway/adapter.go`
- `internal/provider/railway/adapter_test.go`
- `internal/provider/railway/credential.go`
- `internal/provider/railway/planner.go`
- `internal/provider/railway/planner_test.go`
- `internal/rollout/engine.go`
- `internal/rollout/plan.go`
- `internal/rollout/plan_test.go`
- `internal/rollout/store.go`
- `internal/rollout/store_test.go`
- `tasks/history.md`
- `tasks/todo.md`
- `tasks/milestone-7-railway-names-only-ship-manifest.md`

## Security boundary

`railway bind` accepts a bounded project token only through trusted stdin,
proves its project/environment scope through Railway's `projectToken` query,
resolves exactly `postgres`, `migrator`, `api`, and `web`, and stores it under a
bundle-scoped macOS Keychain account only after successful verification.

The adapter contains two query documents: project-token identity and project
metadata. It has no variables query, write mutation, deletion mutation, staged
change, deploy, redeploy, restart, service-create, or service-delete document.
Railway's documented variable query returns values, so every remote variable
state is classified `unverifiable` rather than inferred from masked or missing
evidence.

Names-only plans contain provider and target IDs, logical variable and record
names, desired presence/absence, local record revisions, manifest/snapshot
bindings, expiry, and a digest. They contain no values or credential
fingerprints and are explicitly rejected by apply.

## Verification

- Focused tests cover the Railway operation allowlist, project-token header,
  exact identity/service binding, unrelated-service tolerance, drift failure,
  arbitrary error-body redaction, exact four-service manifests, deterministic
  service/name order, intended absence, and local record revisions.
- Rollout tests cover names-only validation, digest binding, action exclusion,
  non-applicability, and current-record revision validation.
- A CLI integration test prepares a disposable encrypted bundle, binds through
  a fake Keychain and `httptest` Railway endpoint, persists the encrypted plan,
  checks names-only output, and rejects credential or mutation leakage.
- `go test ./...` passed for every Go package with loopback tests in the
  approved outside-sandbox context.
- Focused Railway and rollout race tests passed; `go vet ./...`,
  `git diff --check`, and the Gitleaks configuration harness passed.

## Residual limitations

Go strings created by `net/http` for request headers cannot be guaranteed to be
erased immediately, although owned byte buffers are cleared. macOS Keychain is
the only supported credential-storage path. No live Railway credential or real
SiftCut identifier was used in automated tests. Provider variable presence,
writes, resume, verification, and deployment readiness remain Milestone 8.

## Rollback

Revert the Milestone 7 feature commit. Existing encrypted names-only plans may
remain opaque in a vault but cannot be applied by the prior build. Remove the
bundle-scoped Railway Keychain item separately if credential cleanup is
required; rollback itself must not delete credentials or provider state.

## Next command

Run `$exec Implement Milestone 8 Railway apply, resume, and names-only
verification with forbidden-operation tests.`
