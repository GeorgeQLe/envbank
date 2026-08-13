# Hermetic testlab ship manifest

## User goal

Provide a separate, hermetic `envbank-testlab` binary that lets an agent drive
the secret lifecycle through MCP without real provider accounts, human input,
or agent-visible synthetic secret values.

## Changed files and per-file purpose

- `Makefile`: build the production and testlab binaries.
- `README.md`: document private provider intake, lifecycle MCP, and testlab use.
- `SECURITY.md`: document private-pipe and MCP security boundaries.
- `docs/architecture.md`: document lifecycle and isolated testlab architecture.
- `docs/provider-intake.md`: define the trusted provider-source workflow.
- `docs/roadmap.md`: record the implemented test foundation and remaining live wiring.
- `tasks/todo.md`: mark Milestone 10 complete.
- `tasks/history.md`: record the session and verification evidence.
- `go.mod`, `go.sum`: add the terminal-detection dependency used by the Clerk helper.
- `cmd/envbank/main.go`: expose private-pipe preparation and workflow-only MCP.
- `cmd/envbank/bundle_test.go`: cover private provider intake at the CLI boundary.
- `cmd/envbank-provider-clerk/main.go`: add terminal-safe Clerk/Keychain intake.
- `cmd/envbank-provider-clerk/main_test.go`: cover helper parsing, refusal, and redaction.
- `cmd/envbank-testlab/main.go`: add the isolated test-only MCP executable.
- `internal/contract/manifest.go`: extend the manifest with lifecycle bindings.
- `internal/contract/lifecycle.go`: validate capabilities, policies, targets, health, and browser recipes.
- `internal/contract/manifest_test.go`: cover strict version-2 lifecycle manifests.
- `internal/intake/command.go`: run trusted sources through a bounded private pipe.
- `internal/intake/command_test.go`: cover environment isolation, bounds, identity pins, and redaction.
- `internal/lifecycle/secret.go`: implement callback-scoped secret sink/source access.
- `internal/lifecycle/state.go`: define lifecycle states, transitions, and leases.
- `internal/lifecycle/operation.go`: bind durable operations and revocation safety evidence.
- `internal/lifecycle/policy.go`: implement signed policy authorization and evidence chains.
- `internal/lifecycle/store.go`: persist encrypted policies, operations, leases, and evidence.
- `internal/lifecycle/deployment.go`: stage and activate in order and roll back in reverse.
- `internal/lifecycle/lifecycle_test.go`: cover secret boundaries, policies, evidence, and transitions.
- `internal/lifecycle/deployment_test.go`: cover deployment order, health, and rollback.
- `internal/mcpserver/server.go`: provide strict production tools and isolated extension support.
- `internal/mcpserver/server_test.go`: cover workflow-only schemas and output redaction.
- `internal/provider/stripe/adapter.go`: implement Stripe webhook creation, validation, and revocation.
- `internal/provider/stripe/adapter_test.go`: cover identity, idempotency, capture, retry, and redaction.
- `internal/testlab/testlab.go`: implement encrypted state, clock, workflow, lease, recovery, and flow state.
- `internal/testlab/mcp.go`: expose five strict test-only controls and boolean-only assertions.
- `internal/testlab/emulators.go`: start loopback Stripe, Clerk, Vercel, and Railway emulators.
- `internal/testlab/browser.go`: implement signed protocol-v2 simulated interactive capture.
- `internal/testlab/testlab_test.go`: cover MCP lifecycle, leakage, restart, rollback, browser safety, and lease races.
- `internal/vaultobject/object.go`: register encrypted lifecycle and rollback object kinds.

## User-goal mapping

- Isolation: test controls and emulators are imported only by `cmd/envbank-testlab`.
- Secret invisibility: synthetic values originate inside emulators, pass through
  callback-scoped APIs, persist only inside authenticated ciphertext, and are
  checked with a session-keyed boolean oracle.
- Lifecycle coverage: MCP drives acquire, store, ordered stage/activate,
  multi-sample health, grace, revoke, retry/reconciliation, rollback, and quarantine.
- Agent control: strict MCP tools advance time, inject/clear faults, assert flow,
  and inspect safe scenario state without accepting values, headers, or arbitrary URLs.

## Tests run

- `go test ./...`
- `go test -race ./...`
- `node --test extension/test/*.test.js`
- `go vet ./...`
- `test -z "$(gofmt -l .)"`
- `./scripts/test-gitleaks-config.sh`
- Built `/tmp/envbank-testlab` and completed a binary-level MCP tools/start smoke test.

The smoke build emitted one accepted sandbox-only warning when Go could not
refresh its user module-download stat cache. Compilation completed, the binary
ran successfully, and all cache-isolated test, race, and vet commands passed;
this is not a source or artifact warning.

## Skipped tests

- Disposable live-provider acceptance was intentionally skipped: the testlab
  validates orchestration and leakage resistance but cannot substitute for
  separately authorized live Stripe, Clerk, Vercel, or Railway accounts.
- Native biometric and real browser UI acceptance were intentionally skipped;
  this change supplies a signed protocol simulator, not human UI acceptance.

## Adversarial review

Reviewed the complete diff for credential-shaped schemas, arbitrary provider
error propagation, stdout/stderr leakage, environment inheritance, unbounded
reads, unsafe network listeners, test-control imports in production, plaintext
SQLite persistence, stale record staging, rollback ordering, and lease races.
Executable regressions cover the highest-risk boundaries. No blocking finding
remains. The source executable hash check has a local filesystem TOCTOU window;
the source is explicitly a trusted local program and unattended callers should
also use OS ownership/permission controls.

## Residual risk

- Loopback sockets may be unavailable in fully socket-denied sandboxes; the
  workflow retains its in-process emulator state and tests that degraded mode.
- Live-provider semantics, native browser UI behavior, and biometric prompts
  remain separate acceptance surfaces.
- The testlab persists a local device key beside ciphertext for restart tests;
  its state directory is test-only and mode `0700`, not a production vault.

## Rollback note

Revert the shipping commit. The production vault schema is unchanged; new
vault-object kinds are additive. Remove any explicitly retained test state
directory separately if one was supplied.

## Next command

`$exec` to wire the lifecycle backend into an authenticated production client
and add disposable live-provider acceptance tests.
