# Vercel integration: current boundary and remaining work

This gap belongs to EnvBank, not the hosted application's Vercel backend.
Vercel can store project environment variables and deploy applications. EnvBank
currently lacks a connected production workflow for doing that privately.

## What exists

- The lifecycle interfaces model staging, activation, verification and rollback.
- The test lab uses loopback provider emulators to exercise those interfaces,
  including Vercel deployment and health scenarios. This is simulation evidence.
- Production MCP commands expose workflow-shaped, secret-free requests. The
  production bootstrap constructs a server without a Backend, so it refuses
  workflow execution. It now also reports capabilities unavailable instead of
  advertising automatic operations. A configured backend must supply its own
  capability response; the test backend explicitly reports simulations.
- Stripe, Railway and Cloudflare provider code is not a Vercel adapter. No
  production Vercel adapter or complete provider-to-Vercel backend is connected.

## What a real workflow must implement

1. Bind owner-approved access to immutable Vercel team/project IDs, the exact
   variable name, Preview/Production/custom environment and optional Git branch.
   Default to a disposable project/Preview branch for acceptance. Never infer
   Production from a display name or a successful browser save.
2. Accept the provider value through an authenticated private path into the
   existing encrypted vault/source abstraction. Do not send plaintext through
   MCP arguments/results, shell arguments, clipboard, screenshots or log traces.
3. Add a real Vercel adapter using existing provider/lifecycle interfaces. It
   must write the approved variable as a secret, discard value-bearing API
   response bodies, reject redirects that could forward credentials, sanitize
   errors, and return only bounded non-secret evidence.
4. Implement reconciliation for uncertain writes and exact scope checks. A
   successful request or variable presence is not proof of the exact secret
   value. Do not repeatedly overwrite an ambiguous result or silently restore
   unavailable prior plaintext. Existing encrypted revisions can support an
   explicitly approved rollback design.
5. Activate a new deployment in the approved scope, then verify the consuming
   application's health and provider function with non-secret evidence. Updating
   a project variable does not update an already-running deployment.
6. Wire the production MCP Backend only once the private credential source,
   target bindings, policy, journaling, adapter and acceptance are ready. Report
   only implemented/qualified capabilities. Keep real transfer unavailable until
   installed-controller sentinel tests and disposable target tests pass.

Vercel's environment scoping and deployment behavior are documented in
[environment variables](https://vercel.com/docs/environment-variables).
Do not use environment-variable pull commands for this integration: they can
write credential values into local files. Owner-only real credential handling
and the prohibition on accessing `.env.local` remain in force.

## External controller dependency

API deployment avoids fragile dashboard selectors, but a show-once provider
credential still needs an approved private capture flow. For browser capture,
EnvBank must be embedded by a trusted host that owns every agent observation
and input route. The current CUA tool API does not expose a documented global
barrier/Driver registration hook. The SDK and fake reference-controller tests
cannot establish control over that external host. Until an approved integration
exists, ordinary human filling stays separate and no real protected transfer
is qualified.
