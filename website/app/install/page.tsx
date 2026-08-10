import type { Metadata } from "next";
import { CodeBlock } from "../../components/code-block";
import { PlatformInstall } from "../../components/platform-install";

export const metadata: Metadata = {
  title: "Install v0.2.0",
  description: "Download and verify EnvBank v0.2.0 for macOS, Linux, or GHCR.",
  alternates: { canonical: "/install" },
};

const verifyArtifact = `grep 'envbank_0.2.0_darwin_arm64.tar.gz' SHA256SUMS | shasum -a 256 -c -
gh attestation verify envbank_0.2.0_darwin_arm64.tar.gz \\
  --bundle envbank_0.2.0_artifacts.provenance.json \\
  --repo GeorgeQLe/envbank \\
  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml \\
  --source-ref refs/tags/v0.2.0`;

export default function Install() {
  return (
    <>
      <section className="page-hero shell"><p className="eyebrow">Immutable release</p><h1>Install v0.2.0.<br />Verify every byte.</h1><p>Native archives for macOS and Linux on ARM64 and AMD64, plus a multi-architecture, non-root container image.</p><div className="page-meta"><span>Prerelease</span><span>Apache-2.0</span><span>Published Aug 10, 2026</span></div></section>
      <div className="shell install-layout">
        <PlatformInstall />
        <section className="verify-section" aria-labelledby="verify-download"><div className="section-heading compact"><p className="eyebrow">Supply-chain verification</p><h2 id="verify-download">Check the archive before extracting.</h2><p>The example below is for Apple Silicon. Substitute the exact archive name selected above. On Linux, use <code>sha256sum --ignore-missing --check SHA256SUMS</code>.</p></div><CodeBlock label="Verify checksum and Sigstore provenance">{verifyArtifact}</CodeBlock><div className="verify-grid"><article><span>01</span><h3>Checksum</h3><p>Compare the archive against the release&apos;s exact SHA-256 manifest.</p></article><article><span>02</span><h3>Provenance</h3><p>Require the EnvBank release workflow, v0.2.0 tag, and published Sigstore bundle.</p></article><article><span>03</span><h3>Version</h3><p>Run <code>./envbank version</code> and confirm v0.2.0 plus the protected-main commit.</p></article></div></section>
        <section className="release-proof" aria-labelledby="published-proof"><div><p className="eyebrow">Published proof</p><h2 id="published-proof">Evidence, not a trust badge.</h2><p>The anonymous verification report records exact archive hashes, provenance identity, container platforms, immutable image digest, binary metadata, and health response.</p></div><div className="proof-links"><a href="https://github.com/GeorgeQLe/envbank/releases/tag/v0.2.0">Release assets <span aria-hidden="true">↗</span></a><a href="https://github.com/GeorgeQLe/envbank/blob/main/docs/release-evidence-v0.2.0.md">Verification evidence <span aria-hidden="true">↗</span></a><a href="https://github.com/GeorgeQLe/envbank/blob/main/scripts/verify-release-anonymous.sh">Verification script <span aria-hidden="true">↗</span></a><a href="https://github.com/GeorgeQLe/envbank/blob/main/SECURITY.md">Security policy <span aria-hidden="true">↗</span></a></div></section>
      </div>
    </>
  );
}
