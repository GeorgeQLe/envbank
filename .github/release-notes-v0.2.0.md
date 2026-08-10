EnvBank v0.2.0 is the feature alpha release for trusted bundle preparation and
controlled Railway variable rollout.

## Highlights

- Validate a strict, versioned, non-secret bundle manifest before touching
  local encrypted state or a provider.
- Prepare bundles from trusted JSON standard input, generated values, and
  bounded in-process derivations with resumable encrypted journals and
  snapshots.
- Bind a Railway project token to one exact project, environment, and service
  set through macOS Keychain storage.
- Produce names-only Railway plans, require a separate interactive confirmation,
  and upsert one variable at a time with `skipDeploys: true`.
- Resume partial or ambiguous exact upserts without repeating committed writes,
  then report local committed-write evidence separately from uninspected remote
  state.
- Preserve the v0.1.1 supply-chain surface: four native archives, SHA-256
  checksums, SPDX JSON SBOM, downloadable Sigstore bundles, and an attested
  AMD64/ARM64 container image.

## Important limits

This remains prerelease software. Railway support does not read variable values,
delete variables, apply staged changes, deploy, create services or domains, or
prove remote variable presence. Remote presence is reported as unknown. The
current Railway workflow targets the exact four-service SiftCut-shaped contract.
The released macOS archives include its Keychain-backed credential path;
Railway credential storage is unavailable in the Linux archives.

There is no Clerk dashboard adapter. Clerk secrets must still be obtained
manually and supplied through trusted JSON standard input. Deployment, domain
creation, Clerk webhook registration, and live-project acceptance remain
operator-controlled work outside EnvBank.

The macOS archives are unsigned and not notarized. Verify checksums and Sigstore
provenance before extracting. EnvBank is not a KMS, HSM, enterprise secrets
manager, or substitute for provider-side access controls, auditing, rotation,
and recovery.
