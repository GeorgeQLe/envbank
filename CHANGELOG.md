# Changelog

Notable changes to EnvBank are documented here. The project follows semantic
versioning after the `v` prefix, while `0.x` releases remain unstable.

## Unreleased

- added `envbank codex-hook` and `pkg/codexhook`: an owner-installable adapter
  for the documented Codex `PreToolUse`/`PostToolUse` lifecycle hooks that
  denies every hooked tool call (and withholds results) while the shared
  `protectedfill.Gate` latch is set or its state is unknown, with bounded
  input, strict fixed JSON output and no tool input/response logging. It is
  additional admission enforcement only: hooks can fail open and do not cover
  every route, so credential release through a hook-observed host remains
  refused. Nothing is installed, enabled or trusted automatically;
- added `protectedfill.ProbeGate`, a read-only view of the same durable latch.
- added `envbank agent-broker`, `envbank agent` and value-free
  `envbank_secret_*` MCP tools: owner-terminal secret ingest and
  owner-approved, redacted command injection for coding agents
  ([agent broker](docs/agent-broker.md)).

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
