import assert from "node:assert/strict";

const base = (process.argv[2] ?? "http://localhost:3000").replace(/\/$/, "");
const canonicalBase = "https://envbank.vercel.app";
const routes = [
  { path: "/", title: "EnvBank — Secrets stay yours", canonical: "" },
  { path: "/getting-started", title: "Getting started — EnvBank", canonical: "/getting-started" },
  { path: "/install", title: "Install v0.2.0 — EnvBank", canonical: "/install" },
];

for (const route of routes) {
  const response = await fetch(`${base}${route.path}`);
  assert.equal(response.status, 200, `${route.path} should return 200`);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html/, `${route.path} should be HTML`);
  const html = await response.text();
  assert.ok(html.includes(`<title>${route.title}</title>`), `${route.path} title mismatch`);
  assert.ok(html.includes(`rel="canonical" href="${canonicalBase}${route.canonical}"`), `${route.path} canonical mismatch`);
  assert.equal((html.match(/<h1(?:\s|>)/g) ?? []).length, 1, `${route.path} should contain one h1`);
  assert.ok(!/Clerk-specific adapter|capture.*Clerk dashboard/i.test(html), `${route.path} overclaims Clerk support`);
  assert.ok(html.includes("href=\"/getting-started\"") && html.includes("href=\"/install\""), `${route.path} should expose internal navigation`);
}

const home = await (await fetch(`${base}/`)).text();
assert.ok(home.includes('property="og:image" content="https://envbank.vercel.app/og.png"'), "Open Graph image missing");

const tutorial = await (await fetch(`${base}/getting-started`)).text();
assert.ok((tutorial.match(/>Copy<\/button>/g) ?? []).length >= 6, "tutorial copy buttons missing");
assert.ok(!/sk_live|Sup3r\$ecret|password=/i.test(tutorial), "tutorial contains a plaintext-looking secret");
assert.ok(!tutorial.includes("\n+"), "tutorial contains a malformed continuation line");

const install = await (await fetch(`${base}/install`)).text();
assert.ok(install.includes('aria-pressed="true"'), "install platform selection missing");
assert.ok(install.includes("Unsigned macOS build"), "unsigned macOS warning missing");
assert.ok(install.includes("envbank_0.2.0_darwin_arm64.tar.gz"), "default Apple Silicon artifact missing");
assert.ok(!install.includes("\n+"), "installer contains a malformed continuation line");

for (const asset of ["/og.png", "/icon", "/robots.txt", "/sitemap.xml"]) {
  const response = await fetch(`${base}${asset}`);
  assert.equal(response.status, 200, `${asset} should return 200`);
}

console.log(`Smoke checks passed for ${base}`);
