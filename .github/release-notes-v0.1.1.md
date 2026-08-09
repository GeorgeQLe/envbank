EnvBank v0.1.1 is the corrective alpha release for anonymous verification. It
leaves v0.1.0 and its assets unchanged while adding downloadable Sigstore
provenance bundles for both the release artifacts and the multi-architecture
container image.

Supported archives: macOS and Linux on AMD64 and ARM64. The macOS binaries are
unsigned and are not notarized. Browser filling, Chrome native-host
installation, Keychain storage, and local notifications are macOS-only.

The release contains exactly four archives, `SHA256SUMS`, an SPDX JSON SBOM,
and two Sigstore provenance bundles. Run
`scripts/verify-release-anonymous.sh` from the v0.1.1 source tree to verify the
public repository redirect, release assets, archive paths, checksums, SBOM,
binary metadata, signer identity, source ref and commit, OCI platforms, image
provenance, immutable-digest pull, and `/healthz` response without credentials.

EnvBank remains evaluation software, not a KMS, HSM, or enterprise secrets
manager. Before upgrading, back up the server database and create and verify an
encrypted recovery export. Read the architecture, threat model, cryptographic
review, and production checklist before use.
