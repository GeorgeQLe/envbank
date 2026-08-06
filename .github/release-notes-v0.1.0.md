EnvBank v0.1.0 is an alpha release for evaluation. It is not a KMS, HSM, or
enterprise secrets manager. Read the architecture, threat model, cryptographic
review, and production checklist before use.

Supported archives: macOS and Linux on AMD64 and ARM64. The macOS binaries are
unsigned and are not notarized. Browser filling, Chrome native-host
installation, Keychain storage, and local notifications are macOS-only.

Before upgrading, back up the server database and create and verify an
encrypted recovery export. Recovery cannot restore server-side authorization
state, recall keys from revoked devices, or detect rollback. Validate
`SHA256SUMS`, the SPDX JSON SBOM, and GitHub provenance attestations before
installing.
