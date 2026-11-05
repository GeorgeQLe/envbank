# Vercel integration: implemented path and remaining qualification

This gap belongs to EnvBank, not the hosted application's backend. The REST
adapter and vault-to-deployment workflow are now implemented on the Vercel
feature branch. See [the operator contract](vercel.md).

## Implemented

- Exact immutable team/project/environment/optional Preview branch binding;
  Secret-only writes, names-only metadata, no decrypted-value requests.
- Existing encrypted record intake, bundle snapshots, rollout engine, CAS
  journals and leases; no duplicate vault or provider credential store.
- Configured CLI/MCP backend, trusted-device signed plan approvals, expiry-only
  renewal, per-send authorization, conservative uncertain-write recovery.
- Pinned source/commit redeploy, status-only health checks, staged Production
  promotion and prior deployment rollback with explicit variable-state receipts.
- Synthetic HTTP and workflow tests, including private-response canaries and
  recovery regressions. These do not qualify Vercel's real account behavior.

- Opt-in disposable Preview acceptance runner (`envbank vercel accept`,
  `scripts/e2e-live.sh vercel`) with a status-only fixture and freshness
  proof; refuses without owner setup. Synthetic/loopback tests only.
- Secure Enclave P-256 owner approval with fresh user presence, owner-only
  enrollment, encrypted pin, canonical low-S signatures and no fallback.
  Cryptographic and cgo compile checks use synthetic software-signers only; no
  real key enrolled or physical prompt observed.

## Still unqualified

1. Real API acceptance on an owner-selected disposable project and exact Preview
   branch. The runner exists ([acceptance](vercel-acceptance.md)) but has not
   been run. A separate `vercel accept-production` runner checks staged
   promotion, consumption and rollback, with a provider-side default-domain
   guard. It likewise needs a separate disposable target and has not run live. No
   existing app or shared database is an acceptance fixture.
2. Real credential import remains owner-controlled. Agents must not read real
   credentials, `.env.local`, `.release-config`, or pull environment variables.
   Owner uses private stdin/Keychain setup; no real import was performed here.
3. Hardware owner approval is implemented but physically unaccepted: it needs a
   code-signed build with a data-protection Keychain entitlement, owner
   enrollment and an owner-observed Touch ID/password prompt. The pin is
   passphrase-protected, not hardware-attested.
4. Browser capture of show-once provider keys remains blocked on a trusted host
   controlling every observation/input route. Documented Codex lifecycle hooks
   exist and EnvBank's `codex-hook` adapter uses them for extra admission
   denial, but they can fail open and do not cover every route, so they are not
   a global barrier or Driver registration. See the
   [host checklist](computer-use-host-acceptance.md). Reference-controller and
   fake-site tests do not qualify the installed external computer-use host.

## Provider limits that implementation cannot remove

Vercel offers no cross-operation CAS or EnvBank idempotency key. Presence does
not prove a write-only value. Production variables affect future builds before
promotion, and deployment rollback does not restore prior project-variable
values. Coordinate external writers and use a separately reviewed encrypted
restore plan when variables must be changed back. Prebuilt redeploy sources,
development secrets and custom deployment hostname suffixes are refused.

No blanket “fully qualified” capability is advertised. An unconfigured MCP
backend continues to report workflows unavailable; configured capabilities
explicitly say live acceptance is pending.
