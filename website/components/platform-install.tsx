"use client";

import { useState } from "react";
import { CopyButton } from "./copy-button";

type Choice = "darwin-arm64" | "darwin-amd64" | "linux-arm64" | "linux-amd64" | "ghcr";

const choices: Record<Choice, { platform: string; arch: string; file?: string }> = {
  "darwin-arm64": { platform: "macOS", arch: "Apple Silicon", file: "envbank_0.2.0_darwin_arm64.tar.gz" },
  "darwin-amd64": { platform: "macOS", arch: "Intel", file: "envbank_0.2.0_darwin_amd64.tar.gz" },
  "linux-arm64": { platform: "Linux", arch: "ARM64", file: "envbank_0.2.0_linux_arm64.tar.gz" },
  "linux-amd64": { platform: "Linux", arch: "AMD64", file: "envbank_0.2.0_linux_amd64.tar.gz" },
  ghcr: { platform: "Container", arch: "AMD64 + ARM64" },
};

const digest = "sha256:f84d134e59c70b295008eb025afd70d0bc62b00f67b86082ac6658aeee8d8e7a";
const continued = (lines: string[]) => lines.join(` ${String.fromCharCode(92)}\n`);

export function PlatformInstall() {
  const [choice, setChoice] = useState<Choice>("darwin-arm64");
  const selected = choices[choice];
  const isContainer = choice === "ghcr";
  const archiveRoot = selected.file?.replace(".tar.gz", "");
  const checksumCommand = selected.platform === "macOS"
    ? `grep '${selected.file}' SHA256SUMS | shasum -a 256 -c -`
    : `grep '${selected.file}' SHA256SUMS | sha256sum -c -`;
  const command = isContainer
    ? `docker pull ghcr.io/georgeqle/envbank@${digest}\n${continued(["gh attestation verify oci://ghcr.io/georgeqle/envbank@" + digest, "  --repo GeorgeQLe/envbank", "  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml", "  --source-ref refs/tags/v0.2.0"])}\n${continued(["docker run --rm -p 127.0.0.1:7337:7337", "  -v envbank-data:/data ghcr.io/georgeqle/envbank@" + digest])}`
    : `${continued(["gh release download v0.2.0 --repo GeorgeQLe/envbank", `  --pattern '${selected.file}' --pattern SHA256SUMS`, "  --pattern 'envbank_0.2.0_artifacts.provenance.json'"])}\n${checksumCommand}\n${continued(["gh attestation verify " + selected.file, "  --bundle envbank_0.2.0_artifacts.provenance.json", "  --repo GeorgeQLe/envbank", "  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml", "  --source-ref refs/tags/v0.2.0"])}\ntar -xzf ${selected.file}\n./${archiveRoot}/envbank version`;

  return (
    <section className="installer" aria-labelledby="choose-build">
      <div className="section-heading compact">
        <p className="eyebrow">Release selector</p>
        <h2 id="choose-build">Choose your build</h2>
      </div>
      <div className="platform-tabs" role="group" aria-label="Platform and architecture">
        {(Object.keys(choices) as Choice[]).map((key) => (
          <button key={key} className={choice === key ? "active" : ""} type="button" aria-pressed={choice === key} onClick={() => setChoice(key)}>
            <span>{choices[key].platform}</span><small>{choices[key].arch}</small>
          </button>
        ))}
      </div>
      <div className="install-output">
        <div className="code-bar"><span>{isContainer ? "immutable image" : selected.file}</span><CopyButton value={command} /></div>
        <pre tabIndex={0}><code>{command}</code></pre>
      </div>
      {!isContainer && selected.platform === "macOS" ? (
        <p className="warning"><strong>Unsigned macOS build.</strong> v0.2.0 is not Apple-signed or notarized. Verify the checksum and provenance before bypassing Gatekeeper.</p>
      ) : null}
    </section>
  );
}
