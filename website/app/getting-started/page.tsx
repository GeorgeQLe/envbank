import type { Metadata } from "next";
import Link from "next/link";
import { CodeBlock } from "../../components/code-block";

export const metadata: Metadata = {
  title: "Getting started",
  description: "Create your first EnvBank vault and run a process with encrypted environment variables.",
  alternates: { canonical: "/getting-started" },
};

const command = (lines: string[]) => lines.join(` ${String.fromCharCode(92)}\n`);

const steps = [
  { title: "Start the local service", body: "Bind to loopback and keep the SQLite database in EnvBank's local working directory.", code: "./envbank serve --listen 127.0.0.1:7337 --database .envbank/server.db", label: "Start service" },
  { title: "Create a protected passphrase file", body: "Keep this file outside the repository, make it readable only by your account, and write a strong passphrase using a trusted local editor.", code: "install -m 600 /dev/null /secure/path/envbank-passphrase", label: "Create passphrase file" },
  { title: "Initialize your vault", body: "This creates an encrypted local device identity and the first vault on your local service.", code: command(["./envbank init", "  --server http://127.0.0.1:7337", "  --vault personal", "  --device laptop", "  --config .envbank/laptop.json", "  --passphrase-file /secure/path/envbank-passphrase"]), label: "Initialize vault" },
  { title: "Store a value through standard input", body: "Read the value from a trusted source and pipe it through standard input so it is not placed directly in shell history or command arguments.", code: command(["printf '%s' \"$VALUE_FROM_A_TRUSTED_SOURCE\" |", "  ./envbank set --rotate-days 30", "    --config .envbank/laptop.json", "    --passphrase-file /secure/path/envbank-passphrase", "    API_TOKEN"]), label: "Store value" },
  { title: "Run your development command", body: "EnvBank decrypts your records and injects them into the child process without creating a plaintext .env file.", code: command(["./envbank run", "  --config .envbank/laptop.json", "  --passphrase-file /secure/path/envbank-passphrase", "  -- your-development-command"]), label: "Run child process" },
  { title: "Create a separate recovery copy", body: "Use a different recovery passphrase, store both files away from the device, and periodically verify the artifact.", code: `${command(["./envbank recovery-export", "  --output /secure/path/personal.recovery", "  --recovery-passphrase-file /secure/path/recovery-passphrase", "  --config .envbank/laptop.json", "  --passphrase-file /secure/path/envbank-passphrase"])}\n\n${command(["./envbank recovery-verify", "  --artifact /secure/path/personal.recovery", "  --recovery-passphrase-file /secure/path/recovery-passphrase"])}`, label: "Export and verify recovery" },
];

export default function GettingStarted() {
  return (
    <>
      <section className="page-hero shell"><p className="eyebrow">First vault tutorial</p><h1>From zero to an injected process.</h1><p>Six deliberate steps. Plaintext stays out of command arguments and environment files.</p><div className="page-meta"><span>~10 minutes</span><span>Local service</span><span>v0.2.0</span></div></section>
      <div className="tutorial shell">
        <aside className="tutorial-aside"><p>Before you begin</p><ul><li><Link href="/install">Install the v0.2.0 binary</Link></li><li>Open two terminal windows</li><li>Choose secure paths outside your repository</li></ul><p className="aside-warning">Never commit device configs, passphrase files, recovery artifacts, or plaintext values.</p></aside>
        <div className="steps">
          {steps.map((step, index) => <section className="step" key={step.title} aria-labelledby={`step-${index + 1}`}><div className="step-number">{String(index + 1).padStart(2, "0")}</div><div><p className="step-label">Step {index + 1} of {steps.length}</p><h2 id={`step-${index + 1}`}>{step.title}</h2><p>{step.body}</p><CodeBlock label={step.label}>{step.code}</CodeBlock></div></section>)}
        </div>
      </div>
      <section className="next-panel shell"><div><p className="eyebrow">Next boundary</p><h2>Add another device safely.</h2><p>Copy only the vault ID and service URL. Compare the enrollment fingerprint over a separate trusted channel—never copy the first device config.</p></div><a className="button secondary" href="https://github.com/GeorgeQLe/envbank/blob/main/docs/device-pairing.md">Read device enrollment <span aria-hidden="true">↗</span></a></section>
    </>
  );
}
