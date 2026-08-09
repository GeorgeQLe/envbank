import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

const siteUrl = "https://envbank.vercel.app";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "EnvBank — Secrets stay yours",
    template: "%s — EnvBank",
  },
  description:
    "A small, zero-knowledge environment-variable store for developers and self-hosted teams.",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    url: siteUrl,
    siteName: "EnvBank",
    title: "EnvBank — Secrets stay yours",
    description:
      "Encrypt environment variables on your device, sync only ciphertext, and inject values directly into child processes.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "EnvBank — secrets stay yours" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "EnvBank — Secrets stay yours",
    description: "Client-side encryption for environment variables, with public evidence.",
    images: ["/og.png"],
  },
};

const github = "https://github.com/GeorgeQLe/envbank";

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">Skip to content</a>
        <header className="site-header">
          <nav className="nav shell" aria-label="Primary navigation">
            <Link className="brand" href="/" aria-label="EnvBank home">
              <span className="brand-mark" aria-hidden="true"><span /></span>
              <span>ENVBANK</span>
            </Link>
            <div className="nav-links">
              <Link href="/getting-started">Getting started</Link>
              <Link href="/install">Install</Link>
              <a href={github}>GitHub <span aria-hidden="true">↗</span></a>
            </div>
          </nav>
        </header>
        <main id="main">{children}</main>
        <footer className="footer">
          <div className="shell footer-grid">
            <div>
              <Link className="brand" href="/"><span className="brand-mark" aria-hidden="true"><span /></span><span>ENVBANK</span></Link>
              <p>Small surface. Public evidence. Candid limits.</p>
              <p className="version">v0.1.1 alpha · Apache-2.0</p>
            </div>
            <div className="footer-links" aria-label="Project resources">
              <a href={`${github}/blob/main/SECURITY.md`}>Security policy</a>
              <a href={`${github}/blob/main/docs/architecture.md`}>Architecture</a>
              <a href={`${github}/releases/tag/v0.1.1`}>Release v0.1.1</a>
              <a href={`${github}/blob/main/docs/release-evidence-v0.1.1.md`}>Release evidence</a>
              <a href={`${github}/blob/main/docs/roadmap.md`}>Roadmap</a>
              <a href={`${github}/blob/main/CONTRIBUTING.md`}>Contribute</a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
