# Vercel workflow implementation and acceptance

Branch: `feat/vercel-integration`, based on the protected-host remediation
`12feeb3`. No real credential import, real provider mutation, browser-profile
change or production app/database access was performed for this implementation.
No GitHub Actions workflows were created/modified or Actions enabled.

## Implemented

- [x] Scope to immutable team/project/environment/custom ID/optional Preview branch.
- [x] Reuse encrypted vault records, snapshots, rollout plans and operation objects.
- [x] Owner-controlled Keychain binding; trusted-device signed plan approval.
- [x] Configured CLI/MCP backend; no tool secret values, no unconfigured capability claims.
- [x] Secret-only REST upserts, non-decrypted metadata, fixed errors, no redirects/cookies.
- [x] Project lease within one vault, durable pre-mutation stages, per-send authority.
- [x] Checkpoint confirmed writes; never blindly replay uncertain writes/deployments.
- [x] Rebuild approved Git commit, reject prebuilt/unproven sources.
- [x] Fresh status-only application health, staged Production promotion, prior deployment rollback.
- [x] Surface partial/applied project-variable state separately from deployment outcome.
- [x] Fix Claude Opus 5.5 review findings with explicit regression tests.

## Observed local verification

- `make e2e`: PASS (all Go tests, testlab matrix, recovery, extension, website
  lint/typecheck/build/smoke and synthetic plaintext-leakage scan).
- Scoped race tests: provider/Vercel, workflow, rollout, lifecycle, client,
  contract and MCP PASS. Vercel CLI race test PASS with fake vault, fake provider
  and in-memory Keychain; no OS credential operations.
- Actual HTTP adapter integrated with workflow against loopback fake API:
  Preview completion and Production promotion/rollback PASS. Private response
  canaries do not appear in receipts or journal payloads.
- Regressions: stale health, expiry-only approval renewal, wrong-source recovery,
  unexpected promotion rollback, scope drift, lost checkpoints, ambiguous create,
  absent authorization and unrelated metadata changes PASS.
- Final `go test ./...`: PASS after integration fixes; scoped `go vet`: PASS.
- Redacted staged Gitleaks scan: PASS, no findings.
- Claude Opus 5.5 final closure review: all four follow-up findings closed in
  source, no new concrete blocker identified. It did not run tests.
- Mid-batch policy expiry and expiry-only renewal regression: PASS; confirmed
  records are not read or written again on resume.

These are synthetic results. They do not measure live Vercel behavior, prove
application consumption of a real secret, or qualify the installed external
computer-use confidentiality boundary. Opus reviews are source review, not
independent test execution. The earlier TTY/software-key approval boundary
remains explicitly documented; hardware-backed human presence is not implemented.

## Remaining owner-controlled acceptance

- [ ] Owner selects a disposable project and exact Preview branch, imports the
  Vercel token privately, and optionally supplies the project protection-bypass
  credential. Do not send any credential value through chat or agent tools.
- [ ] Verify actual metadata and upsert response shapes and operation lookup.
- [ ] Verify a fresh build consumes the new fixture without returning it in
  app responses, logs or tool outputs; verify protected-preview health.
- [ ] On a separate disposable production project, verify no early domain
  assignment, staged health, promotion and rollback API behavior. Confirm prior
  deployment substate and alias/domain response shapes.
- [ ] Review scope/permissions, cleanup disposable resources, and approve rollout.

Do not test against the shared app database or real app production deployment.
Vercel variables are changed before a staged build; pause outside deploys in
Production. Rollback does not recover old project-variable values. Unknown
send/crash outcomes remain reconciliation blockers, not retry permission.

## Separate controller dependency

Automatic capture of a provider's show-once key still needs a trusted host
owning all computer-use observations/input. The current CUA interface does not
expose the required global barrier/Driver registration hook. The Vercel REST
path avoids dashboard selectors but does not solve this external integration.
See [remaining gaps](../docs/vercel-integration-gaps.md) and
[operator contract](../docs/vercel.md).
