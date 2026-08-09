# Changelog

Notable changes to EnvBank are documented here. The project follows semantic
versioning after the `v` prefix, while `0.x` releases remain unstable.

## Unreleased

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
