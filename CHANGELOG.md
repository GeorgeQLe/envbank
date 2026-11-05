# Changelog

Notable changes to EnvBank are documented here. The project follows semantic
versioning after the `v` prefix, while `0.x` releases remain unstable.

## Unreleased

- added `envbank agent-broker`, `envbank agent` and value-free
  `envbank_secret_*` MCP tools: owner-terminal secret ingest and
  owner-approved, redacted command injection for coding agents
  ([agent broker](docs/agent-broker.md)).
- added authorized agents, broker side
  ([authorized agents](docs/authorized-agents.md)):
  - memory-only, Touch ID–approved grants (at most 12 h) for agent sessions
    the desktop host launched, identified by session, workspace and agent
    kind;
  - a policy checked before any owner prompt, which refuses with
    `NOT_AUTHORIZED` and lists only granted names;
  - an XPC agent channel to the owner-input service (`broker_hello`,
    `agent_request` answered with `{v, route_id, response}`).
- changed every broker approval (run once/always, ingest replace, setup plan,
  reuse server, pairing) from a typed `y` to LocalAuthentication Touch ID:
  - biometrics only unless `--allow-password-fallback`;
  - `APPROVAL_UNAVAILABLE` without biometry;
  - typing in the terminal approves nothing.
- changed the Unix-socket agent API to off by default: `--legacy-socket`
  enables it (development only, unqualified); `envbank agent` and
  `envbank mcp serve` reach only such brokers.
- added a `run` request field `always` (`envbank agent run --always`) that
  asks for an "always" approval, scoped to the grant.

## 0.2.0 - 2026-08-10

Feature alpha release for trusted bundle preparation and controlled Railway
variable rollout:

- added a strict versioned manifest contract, encrypted vault objects, bundle
  snapshots, provider plans, and recovery artifact v2 compatibility;
- added resumable trusted-stdin imports, generated values, bounded derivations,
  encrypted snapshots, and names-only bundle status;
- added provider-neutral expiring plans and durable rollout operations with
  explicit confirmation, revision binding, safe resume, and sanitized evidence;
- added Railway project/environment identity binding, exact-service names-only
  planning, single-variable upserts with `skipDeploys: true`, and limited
  verification without variable-value reads or deployment operations;
- added the public EnvBank website and hardened the scheduled full-history
  Gitleaks configuration against two known non-secret historical findings.

## 0.1.1 - 2026-08-09

Corrective alpha release for anonymous supply-chain verification:

- preserved downloadable Sigstore provenance bundles for the release artifacts
  and multi-architecture container image;
- added a credential-isolated verification script for the public repository,
  exact asset set, safe archives, checksums, SPDX metadata, provenance policy,
  immutable image digest, and health endpoint;
- retained the `0.1` image channel while leaving the v0.1.0 tag, release, and
  assets untouched.

## 0.1.0 - 2026-08-06

Initial alpha release:

- encrypted multi-device environment-variable storage and synchronization;
- signed device enrollment, revocation, and access history;
- offline encrypted recovery export, verification, use, and restoration;
- exact-origin browser authorization with a macOS Keychain-gated Chrome host;
- hardened SQLite sync service and non-root, shell-free container image;
- release archives for macOS and Linux on AMD64 and ARM64.
