# Current work

> Completed items are archived monthly in `tasks/history/`; the ship log stays in `tasks/history.md`.

## Development status — reviewed 2026-11-06

Reviewed `main` at `0375809`. Source implementation, branch evidence and
integrated release qualification are tracked separately below. A checked source
item does not mean a real vault, provider or protected desktop flow is qualified.

### Merged implementation

- [x] Merge Brave native-host support, protected selection and the host gate SDK
  ([PR #48](https://github.com/GeorgeQLe/envbank/pull/48)). Actual host/Driver
  integration and capture-channel acceptance remain open in the
  [protected computer-use checklist](protected-computer-use-2026-11-03.md).
- [x] Merge the owner-held agent secret broker with exact-command approval,
  names-only operations and output redaction
  ([PR #51](https://github.com/GeorgeQLe/envbank/pull/51)). Disposable local
  end-to-end evidence is recorded in [agent broker](../docs/agent-broker.md);
  owner real-vault acceptance and the placeholder egress proxy remain open.
- [x] Merge agent-operated setup planning/apply through the owner-held broker
  ([PR #52](https://github.com/GeorgeQLe/envbank/pull/52)). Disposable
  `local_server` setup passed; actual launchd installation was not exercised.
  [Setup documentation](../docs/agent-setup.md) records the remaining hosted
  Access, `local_only` and desktop-owner-input work. The legacy socket-based
  desktop input path is disabled on `main`; see the
  [owner-input protocol](../docs/owner-input-protocol.md).

### Unmerged implementations and qualification

These items remain unchecked until reviewed and integrated. Test claims below
are historical branch evidence, not new physical acceptance from this audit.

- [ ] Review and integrate guarded Vercel workflows and Codex lifecycle hooks:
  [PR #50](https://github.com/GeorgeQLe/envbank/pull/50),
  `feat/protected-host-hooks`. `main` was merged into the branch on
  2026-11-08 to clear the conflict GitHub reported. Remaining gates are in
  [the Vercel checklist](vercel-workflow-2026-11-03.md): owner imports
  acceptance credentials privately, disposable Preview/Production acceptance,
  hardware owner approval, actual vendor-runtime hook coverage and the
  external observation controller before browser key capture.
- [ ] Review and integrate XPC owner input: `feat/owner-input-xpc` at `482a14f`.
  The [branch evidence](https://github.com/GeorgeQLe/envbank/blob/482a14f/docs/owner-input-xpc.md)
  records one signed Chromux/broker end-to-end run using a synthetic value;
  installed-build no-leak qualification and independent review remain open.
- [ ] Review and integrate authorized agents: `feat/authorized-agents` at
  `44a0009`. The [branch status](https://github.com/GeorgeQLe/envbank/blob/44a0009/docs/authorized-agents.md)
  reports broker implementation/unit tests and a built, unqualified host side.
  Complete the Chromux session-grant/Touch ID end-to-end qualification.
  This branch also contains the XPC work; reconcile shared ancestry rather
  than treating the branches as independent integrations.
- [ ] Review and integrate cross-device relay: `feat/cross-device-relay` at
  `1079409`. The [branch evidence](https://github.com/GeorgeQLe/envbank/blob/1079409/docs/cross-device-relay.md)
  records disposable loopback vault-ingest acceptance. Independent review,
  Cloudflare Worker support and actual device acceptance remain open.
- [ ] Qualify a real observation-controlling host and protected-fill Driver,
  Brave native messaging/human approval, and every actual capture/trace route
  before enabling real protected transfers. Keep the detailed
  [protected computer-use checklist](protected-computer-use-2026-11-03.md)
  authoritative for these gates.
- [ ] Complete owner real-vault acceptance for the broker; implement the
  separately planned placeholder egress proxy. Existing command-output
  redaction is not that proxy.
- [ ] Live-accept the [Neon credential adapter](../docs/neon.md) (role
  password reset with operation polling, endpoint lookup, API key
  create/list/revoke) on a disposable project; wire it into a rotation
  command with the Vercel workflow. Unit tests use a synthetic transport only.
- [ ] Finish the [agent-driven rotation](../docs/agent-rotation.md). As of
  `main` at `c5d6944` (2026-11-09) the engine, Neon adapter, Vercel
  `RotationDeployer`, standing approval and the `envbank rotation` CLI/MCP
  trigger are merged with synthetic tests only; nothing has run against a
  real Neon or Vercel account. Remaining, in the recommended order:
  1. [ ] Disposable live acceptance: throwaway Neon project with two
     API-created roles, throwaway Vercel Preview project with `/api/health`,
     Stripe test mode. Owner supplies the Neon API key and Vercel token on
     stdin (`envbank rotation bind-provider`, `envbank vercel bind`), binds
     the live role, and signs one standing approval; an agent then runs
     `envbank rotation run` twice (mint/deploy, then retire after grace).
     Record the evidence chain and every field-name assumption the Neon
     adapter makes (endpoint `host`/`type`, operation `status` values).
  2. [ ] Scheduling: implement `envbank_rotation_due` (today it reports
     `ROTATION_SCHEDULE_NOT_IMPLEMENTED`) and run the grace-period retire
     step automatically instead of on a second trigger.
  3. [ ] Remote owner approval from a phone or Windows device: WebAuthn
     passkey as a second owner key, approval request relayed as ciphertext,
     `ownerapproval.Verify` WebAuthn mode (design §3).
  4. [ ] Leak detection and response: HMAC-fingerprint scanner over
     owner-chosen paths, broker redaction hits and provider last-used
     signals; emergency rotation under a covering standing policy, or a
     one-tap owner notification when none covers the record (design §4).
  5. [ ] Stripe secret/restricted keys: dashboard-only, so rotation goes
     through protected computer-use capture once the
     [host checklist](protected-computer-use-2026-11-03.md) passes.
- [ ] Finish hosted Cloudflare Access setup and `local_only` support after
  reconciling branch implementations; retain actual launchd acceptance as a
  separate physical check.

Validation performed for this audit on macOS arm64: focused Go tests passed
for `internal/agentbroker`, `internal/ownerinput`, `internal/setup`,
`pkg/protectedfill`, `internal/nativehost` and `cmd/envbank` at `0375809`.
These were local automated checks, not new branch, device or live-provider
qualification.

## Priority decision still open

- Milestone 12's parity, importer and staging/cutover items remain unfinished.
  Confirm their order relative to the newer agent/desktop integrations. This
  status update preserves the existing milestone order without inferring a
  new product priority or authorizing deployment.

## Milestone 12: Cloudflare-first migration — foundation complete

- [ ] Complete the cross-language v1 parity harness and close every Worker
  route, error, audit, pagination, concurrency, and schema-migration gap before
  any production data or hostname is placed on the Worker.
- [ ] Build the authenticated resumable SQLite-to-Durable-Object importer with
  per-vault transactional import and identifier/ciphertext-free count and
  digest comparison.
- [ ] Deploy marked staging resources, run the full migration and restore
  journeys, complete the maintenance-window cutover and seven-day observation,
  then retire the legacy Go/Docker/Railway production paths.

## Milestone 11: $0 end-to-end execution — implementation complete

- [ ] Execute the explicitly authorized Stripe, Clerk Development, and
  Cloudflare observations against dedicated marked resources before the next
  release.

Later milestones are tracked in the [product roadmap](../docs/roadmap.md).

## Housekeeping

- [ ] Review the 14 open Dependabot alerts on `main` (7 high); PRs #53-55
  carry the Go module bumps. GitHub Actions was re-enabled on 2026-11-08 so
  required checks run again; the Codex review bot's threads must be
  resolved before merge, and CodeQL's "weak hashing" alerts on
  SHA-256-derived Keychain account names are false positives.

## Blockers

- SiftCut Cloud implementation belongs to the separate `short-editor`
  repository, which is outside this workspace's writable scope. Its D1/R2/
  Queues/Workers AI/Containers refactor and PostgreSQL-to-D1 importer remain
  unimplemented here.
