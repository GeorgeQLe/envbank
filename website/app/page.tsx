import Link from "next/link";

const github = "https://github.com/GeorgeQLe/envbank";

const capabilities = [
  ["Encrypt before sync", "Names and values are encrypted on your device with AES-256-GCM. The service stores ciphertext, not usable credentials."],
  ["Run without .env files", "Inject decrypted values directly into a child process and its descendants, without writing a plaintext environment file."],
  ["Approve each device", "Enroll devices with public-key identities, wrapped vault keys, and an out-of-band fingerprint check."],
  ["Recover offline", "Export a separately passphrase-encrypted artifact that can verify, list, retrieve, run, or restore without the original service."],
  ["Fill in the browser", "On macOS, an optional Chrome bridge allows only exact approved origins and retrieves a value after deliberate field selection."],
  ["Prepare trusted bundles", "Validate checked-in manifests against a trusted JSON stdin object, then commit encrypted bundle snapshots without persisting plaintext."],
  ["Stage Railway rollouts", "Bind exact project, environment, and service IDs; plan names-only changes; and apply confirmed writes with deployment triggers disabled."],
  ["Verify the release", "Checksums, SPDX SBOMs, Sigstore provenance bundles, immutable tags, and credential-isolated verification evidence are public."],
];

export default function Home() {
  return (
    <>
      <section className="hero shell">
        <div className="hero-copy">
          <p className="eyebrow"><span className="status-dot" /> Open-source · v0.2.0 alpha</p>
          <h1>Your secrets should<br /><em>never reach the server.</em></h1>
          <p className="lede">EnvBank encrypts environment variables on your device, syncs only ciphertext, and puts plaintext directly into the process that needs it.</p>
          <div className="hero-actions">
            <Link className="button primary" href="/getting-started">Create your first vault <span aria-hidden="true">→</span></Link>
            <Link className="button secondary" href="/install">Install v0.2.0</Link>
          </div>
          <p className="hero-note">No account · No telemetry · No runtime dependency</p>
        </div>
        <div className="terminal-card" aria-label="Illustration of EnvBank encrypting a secret before sync">
          <div className="terminal-top"><span /><span /><span /><b>~/project</b></div>
          <div className="terminal-body">
            <p><span className="prompt">$</span> envbank run -- npm start</p>
            <p className="muted">unlocking encrypted device config</p>
            <p><span className="success">✓</span> 4 variables injected in memory</p>
            <p><span className="success">✓</span> child process started</p>
            <div className="cipher-row"><span>SYNC</span><code>9f6a···c201</code><i>ciphertext only</i></div>
          </div>
        </div>
      </section>

      <section className="proof-strip" aria-label="Security boundaries">
        <div className="shell proof-grid">
          <span>CLIENT</span><b>encrypt</b><i aria-hidden="true">→</i><span>NETWORK</span><b>ciphertext</b><i aria-hidden="true">→</i><span>SERVER</span><b>cannot decrypt</b>
        </div>
      </section>

      <section className="section shell" aria-labelledby="built-for-boundary">
        <div className="section-heading">
          <p className="eyebrow">A narrow, reviewable surface</p>
          <h2 id="built-for-boundary">Built around the security boundary.</h2>
          <p>The sync service is useful without being trusted with your plaintext. Everything else follows from that decision.</p>
        </div>
        <div className="capability-grid">
          {capabilities.map(([title, body], index) => (
            <article key={title} className="capability-card">
              <span className="card-index">0{index + 1}</span><h3>{title}</h3><p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section shell architecture" aria-labelledby="plaintext-path">
        <div className="section-heading compact"><p className="eyebrow">Plaintext path</p><h2 id="plaintext-path">Decrypt only where work happens.</h2></div>
        <div className="flow-diagram">
          <div className="flow-node trusted"><span>01</span><h3>Your device</h3><p>Vault key + plaintext</p></div>
          <div className="flow-edge"><b>encrypt</b><i aria-hidden="true">→</i></div>
          <div className="flow-node"><span>02</span><h3>Sync service</h3><p>Ciphertext + metadata</p></div>
          <div className="flow-edge"><b>inject</b><i aria-hidden="true">→</i></div>
          <div className="flow-node trusted"><span>03</span><h3>Child process</h3><p>Plaintext at use time</p></div>
        </div>
        <p className="diagram-note">The service can observe record count, timing, device count, and ciphertext sizes. It can delete, replay, or withhold data; v0.2.0 does not detect server rollback.</p>
      </section>

      <section className="alpha-section">
        <div className="shell alpha-grid">
          <div><p className="eyebrow danger">Read before evaluating</p><h2>Alpha means the limits are part of the product.</h2><p>EnvBank is prerelease software, not a KMS, HSM, enterprise secrets manager, or substitute for provider-side controls.</p></div>
          <ul>
            <li>No vault rekeying or server rollback detection</li>
            <li>No service rate limiting or hardware key custody</li>
            <li>No Windows release or Apple signing/notarization</li>
            <li>Compromised endpoints, child processes, or approved browser pages can expose plaintext at use time</li>
            <li>Losing every approved device and recovery copy means losing the vault</li>
          </ul>
          <div className="alpha-links">
            <a href={`${github}/blob/main/docs/architecture.md`}>Read the threat model <span aria-hidden="true">↗</span></a>
            <a href={`${github}/blob/main/docs/cryptographic-review-report.md`}>Read the crypto review <span aria-hidden="true">↗</span></a>
          </div>
        </div>
      </section>

      <section className="section shell evidence" aria-labelledby="verify-claims">
        <div><p className="eyebrow">Trust, but verify</p><h2 id="verify-claims">The evidence is public.</h2><p>The v0.2.0 release is tied to protected main, exact asset hashes, an immutable container digest, SBOM, provenance bundles, and a reproducible anonymous verification report.</p></div>
        <div className="evidence-actions"><a className="button primary" href={`${github}/blob/main/docs/release-evidence-v0.2.0.md`}>Inspect release evidence</a><a className="text-link" href={`${github}/releases/tag/v0.2.0`}>Open immutable release <span aria-hidden="true">↗</span></a></div>
      </section>
    </>
  );
}
