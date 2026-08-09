# EnvBank v0.1.1 anonymous release evidence

Verified on 2026-08-09 from a credential-isolated temporary directory on
Darwin/ARM64. The verification unset GitHub token variables, replaced GitHub,
Git, and Docker credential/configuration paths with empty temporary locations,
used only public HTTPS endpoints, and removed its temporary downloads,
container, volume, and newly introduced immutable image reference.

## Publication identity

- Protected-main preparation PR: [#12](https://github.com/GeorgeQLe/envbank/pull/12)
- Protected-main squash commit:
  `d55f49672fd99c4efaf8c411548cf4331a938707`
- Annotated tag object: `fb41aaf71964c0778f180d82c0bb38106cb7c6fc`
- Peeled tag commit: `d55f49672fd99c4efaf8c411548cf4331a938707`
- Successful tag-only [release workflow run](https://github.com/GeorgeQLe/envbank/actions/runs/31334350405)
- Published [v0.1.1 prerelease](https://github.com/GeorgeQLe/envbank/releases/tag/v0.1.1)
  at `2026-08-09T20:40:36Z`; it is non-draft and marked prerelease.

The workflow certificate identity for both bundles is
`https://github.com/GeorgeQLe/envbank/.github/workflows/release.yml@refs/tags/v0.1.1`.
Its issuer is `https://token.actions.githubusercontent.com`; the certificate
records the source ref `refs/tags/v0.1.1`, source digest above, public source
visibility, GitHub-hosted runner environment, and the workflow run/attempt URL.
Both statements use `https://slsa.dev/provenance/v1`.

## Exact public assets

The public release API returned exactly these eight assets, with no missing or
extra names:

| Asset | SHA-256 |
| --- | --- |
| `SHA256SUMS` | `cbd5e4f37ffb1f42c6fd63d12ef167ef4e1d22a4f217bd17d31c9eb9190493d6` |
| `envbank_0.1.1_artifacts.provenance.json` | `368ba9a41b38c603c1653095bab05a60a6e787583eff30c3a30038a0e394a50f` |
| `envbank_0.1.1_darwin_amd64.tar.gz` | `fb41a91a45c2691600b2bea8a58cdd571135b6783cd26c98cd1442cbb5179e78` |
| `envbank_0.1.1_darwin_arm64.tar.gz` | `e56f09bff9b6e2c036ce4bb6dad4a70e58092baf5ddd65325992df730f22424a` |
| `envbank_0.1.1_image.provenance.json` | `62866d917cc8d8e129a8bf3d2b4bc887f4adbc63681d9109fefc98a6f5ebf952` |
| `envbank_0.1.1_linux_amd64.tar.gz` | `177f052ff627bbf1ac83a972418abc40ad94444aa4f0c7c7f14b3282227f35c4` |
| `envbank_0.1.1_linux_arm64.tar.gz` | `74c425cdbe32d679afb1a6c5b6ebc534d2b3dcdad68d957f75d2794b8455dbea` |
| `envbank_0.1.1_sbom.spdx.json` | `10505cde48c25f5e68e710d8d9015414688be7bcb09e1140a056ddb39c1f2eb2` |

Every archive checksum passed. Each archive contained only its versioned root
directory, `envbank`, `LICENSE`, and `README.md`; traversal, absolute,
backslash, empty-component, symlink, hard-link, and unsupported entry types
were rejected before extraction. The SPDX JSON parsed as an SPDX 2.x document
with `SPDXRef-DOCUMENT`, `CC0-1.0` data license, creation metadata, and a
non-empty package list.

The artifact bundle covered the four archives, `SHA256SUMS`, and the SPDX JSON
with exactly the digests above. Local-bundle verification used a trusted root
fetched and verified through `gh attestation trusted-root`; policy enforcement
required the exact repository, workflow, tag ref, and peeled commit. The host
binary reported:

```text
envbank v0.1.1 (commit d55f49672fd99c4efaf8c411548cf4331a938707, built 2026-08-09T16:24:04-04:00)
```

## Repository and redirect

- Anonymous clone of `https://github.com/GeorgeQLe/envbank.git`: passed.
- Anonymous clone of `https://github.com/GeorgeQLe/invisible-envs-bank.git`:
  passed and resolved the same `origin/main` commit.
- Public browser redirect:
  `https://github.com/GeorgeQLe/invisible-envs-bank` →
  `https://github.com/GeorgeQLe/envbank` in exactly one hop.
- Canonical URL required zero redirects.

Both anonymous clones resolved `origin/main` to
`d55f49672fd99c4efaf8c411548cf4331a938707` during verification.

## Public container image

The public `ghcr.io/georgeqle/envbank:v0.1.1` OCI index resolved to immutable
digest `sha256:f5bf5daaca7ed1526a4dfc9ce53fd2bff44f42a5fb480a5ed7323515f9ab95e8`
and contained exactly these runnable platforms:

| Platform | Manifest digest |
| --- | --- |
| `linux/amd64` | `sha256:3c9f00d190fd4be051407f4fb5ea089b2410a459d3a6184c05a2c454528c274b` |
| `linux/arm64` | `sha256:9cfba7b3254277301ed4d368d6ad7f786518d988e5c7ff7a07b23ffff9f0a5b5` |

The local image bundle named `ghcr.io/georgeqle/envbank` at the immutable index
digest and passed the same signer, source-ref, source-digest, SLSA predicate,
and trusted-root policy. The verifier pulled the host platform by immutable
digest, started an isolated container and volume, and required `/healthz` to
return HTTP 200, body `{"status":"ok"}`, and `Cache-Control: no-store`.

## Commands and redacted output

The decisive command was:

```sh
./scripts/verify-release-anonymous.sh
```

Its successful output (network progress and verification internals omitted)
was:

```text
Checking anonymous repository access and redirect...
Downloading and validating the exact release asset set...
envbank_0.1.1_darwin_amd64.tar.gz: OK
envbank_0.1.1_darwin_arm64.tar.gz: OK
envbank_0.1.1_linux_amd64.tar.gz: OK
envbank_0.1.1_linux_arm64.tar.gz: OK
Verifying Sigstore bundles and release provenance...
Verifying the public multi-platform image by immutable digest...
Anonymous verification passed.
tag object: fb41aaf71964c0778f180d82c0bb38106cb7c6fc
tag commit: d55f49672fd99c4efaf8c411548cf4331a938707
main head: d55f49672fd99c4efaf8c411548cf4331a938707
image digest: sha256:f5bf5daaca7ed1526a4dfc9ce53fd2bff44f42a5fb480a5ed7323515f9ab95e8
```

Additional evidence queries used the public GitHub release API, anonymous Git
`ls-remote` and clones, the public GHCR token/manifest endpoints, and
`gh attestation verify --bundle ... --custom-trusted-root ... --format json`
with empty GitHub and Docker configuration directories. No token, credential,
private path, or unredacted secret is present in this report.

The first post-publication verifier run stopped at an unavailable local Buildx
plugin after all artifact assertions passed. No evidence claim was made. The
evidence branch replaced that optional dependency with GHCR's public OCI
manifest API; the complete clean rerun above then passed. The same branch also
updates the workflow's upload/download artifact actions to their pinned Node 24
generations after GitHub reported Node 20 deprecation warnings on the immutable
tagged run.

## v0.1.0 preservation

The annotated v0.1.0 tag still peels to
`4699b0304e77fbaaac795728ff71ca649cc52a03`. Its public release has matching
published/updated timestamps (`2026-08-06T18:48:17Z`) and the same six original
assets. No v0.1.0 tag, release, asset, or image mutation was performed. v0.1.0
remains available but is superseded because it lacks downloadable provenance
bundle assets.
