# EnvBank v0.2.0 anonymous release evidence

Verified on 2026-08-10 from a credential-isolated temporary directory on
Darwin/ARM64. The verifier unset GitHub token variables, replaced GitHub, Git,
and Docker credential/configuration paths with empty temporary locations, used
only public endpoints, and removed its downloads, container, volume, and newly
introduced immutable image reference.

## Publication identity

- Protected-main preparation PR: [#23](https://github.com/GeorgeQLe/envbank/pull/23)
- Protected-main squash commit:
  `ddff78f9c70b3424ebea82c89fc02a6ecdce1ac3`
- Annotated tag object: `969398edd4f39d567f53493a68c9c3f2ec460fed`
- Peeled tag commit: `ddff78f9c70b3424ebea82c89fc02a6ecdce1ac3`
- Successful tag-only [release workflow run](https://github.com/GeorgeQLe/envbank/actions/runs/31396481863)
- Published [v0.2.0 prerelease](https://github.com/GeorgeQLe/envbank/releases/tag/v0.2.0)
  at `2026-08-10T14:21:30Z`; it is non-draft and marked prerelease.

The artifact and image provenance bundles identify
`https://github.com/GeorgeQLe/envbank/.github/workflows/release.yml@refs/tags/v0.2.0`,
the source ref `refs/tags/v0.2.0`, and the peeled commit above. Anonymous
verification required that exact repository, workflow, tag ref, and commit.

## Exact public assets

The public release API returned exactly these eight assets:

| Asset | SHA-256 |
| --- | --- |
| `SHA256SUMS` | `440574dc567216a23e7591878261540a8fc20065973085014da4611a50333ac5` |
| `envbank_0.2.0_artifacts.provenance.json` | `2f6f6315a1e9410b33d917c0cc9ef74f3fd1a9eff97f7cbdba8b6c3957ac531c` |
| `envbank_0.2.0_darwin_amd64.tar.gz` | `48bd43eebf0e8ac00af841a08f8a86fafa1d09477859b14df5aee42a8ea589cf` |
| `envbank_0.2.0_darwin_arm64.tar.gz` | `49e77f2fcc4c1735cde204dfa9502d703940f5ff90fb6ee17a74f4bf61ced3d1` |
| `envbank_0.2.0_image.provenance.json` | `eaff6fc34131571ce3a2f317f300b03b42d3885a4967aaf9c0194eeedbbd288c` |
| `envbank_0.2.0_linux_amd64.tar.gz` | `0534407ac90449ad8630c198471bbe8203097da799d224a74004ac19960019e8` |
| `envbank_0.2.0_linux_arm64.tar.gz` | `97d99a09be207b2c98907691c5b8685b3a5eb94694298d3d352e499b5707fa35` |
| `envbank_0.2.0_sbom.spdx.json` | `e7eef8ef6d8706b5185f34f181d8e68811ec6cd79d514e244387d20d3f8982a4` |

Every archive checksum passed. Archive safety, SBOM structure, and local
Sigstore bundle policy checks passed. The Darwin/ARM64 archive reported:

```text
envbank v0.2.0 (commit ddff78f9c70b3424ebea82c89fc02a6ecdce1ac3, built 2026-08-10T10:03:01-04:00)
```

The host binary also linked
`/System/Library/Frameworks/Security.framework`, proving that this release uses
the native Keychain implementation required for stored Railway credentials.

## Repository and container

Anonymous canonical and legacy-name clones both resolved `origin/main` to the
peeled tag commit, and the legacy browser URL redirected once to the canonical
repository. The public `ghcr.io/georgeqle/envbank:v0.2.0` OCI index resolved to
`sha256:f84d134e59c70b295008eb025afd70d0bc62b00f67b86082ac6658aeee8d8e7a`
with exactly these runnable platforms:

| Platform | Manifest digest |
| --- | --- |
| `linux/amd64` | `sha256:670856c3b07dbd014738fb2557458c003e42e1116e6c3a64afcaa74aa2565b72` |
| `linux/arm64` | `sha256:ed8cc457981ab79fd89888b2e1783b5a8fc2babe53636f4967f82833b4983b27` |

The image provenance policy passed. The verifier pulled the immutable digest,
started an isolated container and volume, and required `/healthz` to return
HTTP 200, `{"status":"ok"}`, and `Cache-Control: no-store`.

## Decisive output

```text
$ ./scripts/verify-release-anonymous.sh
Checking anonymous repository access and redirect...
Downloading and validating the exact release asset set...
envbank_0.2.0_darwin_amd64.tar.gz: OK
envbank_0.2.0_darwin_arm64.tar.gz: OK
envbank_0.2.0_linux_amd64.tar.gz: OK
envbank_0.2.0_linux_arm64.tar.gz: OK
Verifying Sigstore bundles and release provenance...
Verifying the public multi-platform image by immutable digest...
Anonymous verification passed.
tag object: 969398edd4f39d567f53493a68c9c3f2ec460fed
tag commit: ddff78f9c70b3424ebea82c89fc02a6ecdce1ac3
main head: ddff78f9c70b3424ebea82c89fc02a6ecdce1ac3
image digest: sha256:f84d134e59c70b295008eb025afd70d0bc62b00f67b86082ac6658aeee8d8e7a
```

No v0.1.x tag, release, asset, provenance bundle, or image was modified.
