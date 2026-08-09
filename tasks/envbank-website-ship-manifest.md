# EnvBank public website ship manifest

## User goal

Publish a public, static EnvBank website for developers and small teams with
marketing, first-vault tutorial, and verified v0.1.1 installation routes,
without including unreleased SiftCut or provider functionality.

## Changed files

- `website/**`: self-contained TypeScript Next.js application, dependency
  lockfile, routes, components, styling, metadata, favicon, and social image.
- `.github/workflows/ci.yml`: Node 24 website lint, typecheck, and build job.
- `README.md`: public site, tutorial, and installation links.
- `tasks/todo.md`: completed website implementation milestone.
- `tasks/history.md`: dated implementation record.
- `tasks/envbank-website-ship-manifest.md`: this shipping boundary and evidence.

## Per-file purpose

The website package owns all public UI and build configuration. Shared layout
and components provide navigation, footer provenance links, copy actions, and
platform selection; route files own accurate page-specific copy and metadata;
global CSS owns the responsive and accessible visual system. Repository files
connect the new surface to CI, discovery, and project history.

## User-goal mapping

- `/` explains client-side encryption, ciphertext-only sync, direct process
  injection, enrollment, recovery, browser boundaries, provenance, and alpha
  limitations.
- `/getting-started` walks through service startup, passphrase-file creation,
  initialization, stdin storage, process execution, and recovery setup without
  literal secret values.
- `/install` provides macOS, Linux, and GHCR choices plus checksums, Sigstore
  verification, unsigned-macOS guidance, immutable release links, and evidence.
- Metadata routes, generated graphics, responsive CSS, keyboard controls, and
  CI cover publication, usability, and maintainability requirements.

## Tests run

- Node 24 `npm ci` from `website/package-lock.json`, ESLint, TypeScript, and the
  production Next.js build; all eight static routes/assets generated.
- Local HTTP smoke checks for every public route, one semantic `h1` per page,
  canonical titles and URLs, internal navigation, copy buttons, platform
  defaults, warnings, redacted examples, OG asset, favicon, robots, and sitemap.
- HTTP 200 checks for every external GitHub project, policy, architecture,
  release, evidence, roadmap, contribution, pairing, and verifier link.
- `gofmt`, module verification/tidy diff, vet, ordinary and race Go tests,
  extension tests, recovery drill, four-target cross-build, pinned
  `govulncheck`, and the synthetic Gitleaks policy test.
- Manual WCAG contrast calculations for primary, muted, code-bar, supporting,
  and microcopy color pairs after raising low-contrast supporting labels.

## Skipped tests

- In-app visual and interaction inspection was unavailable because the required
  browser surface reported no available browser. Responsive structure, focus
  rules, code overflow, reduced-motion behavior, and control semantics received
  source review; the production route smoke still runs after deployment.
- CodeQL and full-history Gitleaks require their GitHub Actions environments and
  remain required protected PR checks rather than weaker local substitutes.

## Adversarial review

The review checked unreleased feature claims, plaintext credential examples,
misleading security absolutes, incorrect release artifacts, inaccessible
controls, mobile overflow, unsafe external links, and metadata drift. It found
and fixed malformed continuation prefixes in copyable commands, expanded each
selected install command to include checksum/provenance/version verification,
raised low-contrast microcopy, and rejected the first generated social card
because it invented plaintext-looking credentials.

## Residual risk

The public URL depends on Vercel project configuration outside the repository.
The unavailable in-app browser leaves a residual visual-regression gap, bounded
by static responsive review, semantic checks, and production smoke coverage.
The site intentionally pins displayed product content to v0.1.1, so a future
release requires a deliberate content and evidence update.

## Rollback note

Revert the website feature commit and restore the prior Vercel production
deployment. The site has no database, user data, runtime secrets, or migration.

## Next command

`cd website && npm ci && npm run lint && npm run typecheck && npm run build`
