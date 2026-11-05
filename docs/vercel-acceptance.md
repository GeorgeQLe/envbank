# Vercel disposable acceptance and hardware owner approval

Status (November 4, 2026): implemented and covered by synthetic tests only.
**No live Vercel acceptance was run, no credential was imported, no Secure
Enclave key was enrolled and no physical user-presence test was performed.**

## Two different acceptance levels

| Level | What it proves | Status |
| --- | --- | --- |
| Provider Preview acceptance (`envbank vercel accept`) | Real metadata/upsert shapes, scoped Secret write, operation lookup, redeploy of the approved commit, protected-preview health, and that the new deployment consumed the exact approved fixture revision (status-only proof) | Runnable by the owner; not yet run |
| Provider Production API acceptance (`envbank vercel accept-production`) | Exact disposable Production/default-domain admission, healthy baseline, staged build, health-gated promotion, fresh-value consumption, signed rollback and restored-baseline consumption | Runnable after owner setup; not yet run |
| Physical approval and browser-controller acceptance | Owner observes real authentication/denial/repeated prompts; host vendor qualifies every observation route for browser capture | Separate, unqualified boundaries |

Preview receipts say `"acceptance_level":"provider-preview"`. Production receipts
say `"acceptance_level":"provider-production"` and report
`"api_promotion_rollback":"pass"` only after promotion and rollback checks.
Both keep `"full_workflow":"not-qualified"` for the broader combined pipeline.
Browser capture is independent: it is not required for the owner-imported API
path, and a provider API PASS does not qualify browser capture or physical
owner-presence behavior.

## Hardware owner approval (required for every Vercel mutation)

- `envbank owner-approval enroll` (owner only, interactive TTY, typed phrase)
  creates one non-exportable Secure Enclave P-256 key
  (`kSecAttrTokenIDSecureEnclave`, `kSecAccessControlPrivateKeyUsage |
  kSecAccessControlUserPresence`, `WhenUnlockedThisDeviceOnly`, data-protection
  Keychain, tag `com.envbank.owner-approval.p256.v1`). It refuses if any key
  (hardware or software) already carries the tag, and refuses to replace an
  existing pin.
- The public key is pinned inside the passphrase-encrypted, AAD-bound config
  payload, not a plain config field, flag, manifest or tool argument.
- `envbank vercel approve` asks for the existing terminal confirmation and then
  a **fresh** Secure Enclave signature. Each signature uses a new `LAContext`
  with `touchIDAuthenticationAllowableReuseDuration = 0`, invalidated afterwards;
  no authenticated context is cached. Before signing, the signer requires exactly
  one tagged key, re-checks the Secure Enclave token, EC/256 attributes and that
  its public key equals the pin.
- The owner signature covers a domain-separated canonical statement: every
  policy field (plan, source deployment, scope fingerprint, health path,
  operations, expiry, approving device **public key**) plus owner key ID,
  algorithm, presence attribute and signing time. Signatures are stored as
  strict DER, low-S. Expiry may be at most 24h after the owner signing time.
- The device Ed25519 key still authenticates the vault and signs the stored
  policy over the owner proof. Device-only, TTY-only or unpinned-key
  approvals are refused by the Vercel backend (`VERCEL_APPROVAL_REQUIRED`);
  without a pin, start/resume/policy-status/rollback return
  `OWNER_APPROVAL_KEY_NOT_PINNED`. The MCP backend holds the device key but no
  path to the Secure Enclave key, so it cannot mint approval.
- Renewal may change only expiry, with a fresh owner signature from the same
  pinned key. A legacy device-only approval already pinned by an operation
  journal cannot be silently upgraded; create and approve a new plan.

Limits: macOS gives no remote attestation for these keys, so the verifier
trusts the owner pin. The pin is protected by the local passphrase, not by
hardware; same-user code that has the passphrase can substitute it. Access
control flags cannot be read back through public API after creation.
Unsigned `go build` binaries normally lack a data-protection Keychain
entitlement and fail closed with `ErrEntitlement`; physical use needs a
code-signed EnvBank build with a `keychain-access-groups` entitlement.
Non-macOS or non-cgo builds always refuse. No software fallback is added when
signing/access entitlements are unavailable. If key creation succeeds but the
encrypted config cannot be saved, stop and have the owner inspect/recover that
specific key before retrying. Enrollment deliberately refuses to overwrite or
automatically delete an existing key. Never delete unrelated Keychain items.

## Fixture

`e2e/fixtures/vercel-acceptance` is a dependency-free Node project with two
status-only functions and no database, logging or outbound requests:

- `GET /api/health`: 200 if `ENVBANK_ACCEPTANCE_FIXTURE_SECRET` is configured
  (≥32 bytes), else 503.
- `GET /api/envbank-acceptance`: given a fresh random
  `x-envbank-acceptance-challenge` and
  `x-envbank-acceptance-proof = base64url(HMAC-SHA256(key=value,
  "envbank.vercel.acceptance.v1" NUL challenge))`, returns 204 (match), 409
  (present, mismatch), 424 (absent) or 400. No body.

The harness accepts only a generated fixture record with matching prepared
snapshot provenance. Imported upstream credentials are refused. It re-checks
current owner approval at the private read boundary, reads the exact approved
record revision once, computes two proofs
for fresh challenges, wipes the value and sends proofs only to proven owned
`*.vercel.app` deployments. Receipts contain status integers, fixed codes and
opaque IDs; no value, hash, proof or challenge. Use a dedicated generated fixture
value, never a real credential. The 32-byte minimum is a length check, not an
entropy measurement.

The runner PASSes only if (1) the approved **source** deployment answers 409 or
424, proving it does not already hold the value; (2) the configured workflow
completes; (3) the new deployment answers 204; and (4) a random negative-control
proof answers 409.

## Owner checklist and commands

The owner performs private credential setup, key enrollment and approval. An
agent may prepare public files and run the already-approved acceptance against
the selected disposable target. Do not paste credentials into chat or agent tools.
Commands omit `--config CONFIG --passphrase-file PASSFILE`.
Keep `TMPDIR`, `GOCACHE` and `GOMODCACHE` under `/Users/georgele/Developer`.

1. Create a **new** Vercel project named `envbank-acceptance-<suffix>` in a
   team you control. Connect the reviewed fixture from this repository with
   Root Directory `e2e/fixtures/vercel-acceptance`, or use a dedicated repository
   containing just that fixture. Never use an existing application or a
   shared database.
2. Push branch `envbank-acceptance-<run>` and let Vercel build it **before**
   the fixture variable exists. Record the READY Git deployment ID `dpl_…`
   (`/api/envbank-acceptance` must return 424 or 409 there).
3. Record the immutable `team_…` and `prj_…` IDs. Write the fixture manifest:

   ```yaml
   version: 1
   bundle: acceptance/vercel-<run>
   policies:
     fixture: {type: password, length: 64, lowercase: true, uppercase: true, digits: true}
   records:
     ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: generate, policy: fixture}
   targets:
     vercel:
       team_id: team_REPLACE
       project: envbank-acceptance-REPLACE
       project_id: prj_REPLACE
       environment: preview
       git_branch: envbank-acceptance-REPLACE
       services:
         environment:
           order: 1
           variables:
             ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: record, record: ENVBANK_ACCEPTANCE_FIXTURE_SECRET}
   ```

   Use a new bundle name per run; reusing a value already deployed makes the
   freshness check stop with `ACCEPTANCE_FIXTURE_NOT_FRESH`.
4. `envbank bundle prepare --manifest M` (generates the random fixture value in
   the vault; nothing is printed).
5. Create a dedicated Vercel token with the least provider permissions available
   for the selected team/project. EnvBank enforces exact project scope locally;
   this does not prove the token itself is project-restricted. Bind it from a
   private source on stdin (optionally JSON with `health_bypass` for a
   protected preview): `envbank vercel bind --manifest M < PRIVATE_INPUT`.
6. One time, with a signed build: `envbank owner-approval enroll`; check with
   `envbank owner-approval status`.
7. `envbank vercel plan --manifest M` → `PLAN_ID`.
8. `envbank vercel approve --manifest M --plan PLAN_ID --source-deployment dpl_SOURCE --health-path /api/health`
   (terminal confirmation, then Touch ID/password).
9. Run the harness from an interactive terminal:

   ```sh
   ENVBANK_LIVE_ACCEPTANCE=1 \
   ENVBANK_VERCEL_ACCEPTANCE_TARGET='disposable:team_REPLACE/prj_REPLACE/envbank-acceptance-REPLACE@envbank-acceptance-REPLACE' \
   VERCEL_ACCEPTANCE_MANIFEST=M VERCEL_ACCEPTANCE_CONFIG=CONFIG \
   VERCEL_ACCEPTANCE_PASSPHRASE_FILE=PASSFILE VERCEL_ACCEPTANCE_PLAN=PLAN_ID \
   VERCEL_ACCEPTANCE_CLI=/absolute/path/to/trusted/signed/envbank \
   scripts/e2e-live.sh vercel
   ```

   The target string is a separate restatement and must match the manifest and
   the provider-reported project name exactly. Vercel credentials in the
   environment are refused. The wrapper requires the explicitly selected helper
   and never rebuilds it. Use the same trusted signed identity for enrollment,
   binding, approval and acceptance; file/executable checks do not themselves
   verify code-signing authority.
10. Cleanup, using only IDs from the receipt `cleanup` list: delete the new
    Preview deployment, delete the branch-scoped fixture variable (or the whole
    disposable project), and revoke the acceptance token and any dedicated
    bypass secret. EnvBank never deletes provider resources automatically.

Precise refusals: `EXPLICIT_AUTHORIZATION_REQUIRED`,
`CREDENTIAL_ENVIRONMENT_FORBIDDEN`, `DISPOSABLE_TARGET_REQUIRED`,
`ACCEPTANCE_MANIFEST_NOT_DISPOSABLE`, `ACCEPTANCE_TARGET_MISMATCH`,
`ACCEPTANCE_PREVIEW_ONLY`, `ACCEPTANCE_PROJECT_NOT_MARKED`,
`OWNER_APPROVAL_KEY_NOT_PINNED`, `OWNER_APPROVAL_REQUIRED`,
`ACCEPTANCE_HEALTH_PATH_MISMATCH`, `ACCEPTANCE_FIXTURE_TOO_SHORT`,
`ACCEPTANCE_FIXTURE_NOT_FRESH`, `ACCEPTANCE_FIXTURE_UNREACHABLE`,
`ACCEPTANCE_FRESH_VALUE_NOT_CONSUMED`, `ACCEPTANCE_FIXTURE_CONTROL_FAILED`,
plus any workflow blocker code.

## Production promotion/rollback acceptance

Use a **second** owner-selected project named `envbank-acceptance-<suffix>`.
It must have exactly its verified default `PROJECT_NAME.vercel.app` domain:
no custom/customer domains, redirects, branch domains or custom environments.
Pause automatic/outside deployments during the run. The provider guard checks
the complete domain list before any record read and again at mutation time;
Vercel has no CAS, so outside writers must still be excluded.

1. Deploy the same no-database fixture to this project's Production environment.
   Establish a healthy baseline containing a different, older generated fixture
   value. One way is a separate bootstrap bundle/manifest and an explicitly
   owner-approved ordinary `vercel apply`/`resume` run on this disposable project.
   The bootstrap is setup, not an acceptance PASS. Keep its READY/current
   deployment ID. Both health and fixture endpoints must work; an absent value
   (424) or unhealthy baseline is refused because rollback must restore a
   healthy fixture. Never use a real credential as either fixture value.
2. Prepare a new bundle/manifest with another generated fixture revision. Use
   the same one-variable shape above, but `environment: production`, omit
   `git_branch`, and use the second project's immutable IDs/name. Bind its
   dedicated credential privately. `vercel plan`, then owner `vercel approve`
   with the healthy current baseline as `--source-deployment` and `/api/health`.
   The approval must include stage, verify, activate and rollback authority.
3. Run with the same trusted helper identity:

   ```sh
   ENVBANK_LIVE_ACCEPTANCE=1 \
   ENVBANK_VERCEL_ACCEPTANCE_TARGET='disposable-production:team_REPLACE/prj_REPLACE/envbank-acceptance-REPLACE' \
   VERCEL_ACCEPTANCE_MANIFEST=M VERCEL_ACCEPTANCE_CONFIG=CONFIG \
   VERCEL_ACCEPTANCE_PASSPHRASE_FILE=PASSFILE VERCEL_ACCEPTANCE_PLAN=PLAN_ID \
   VERCEL_ACCEPTANCE_CLI=/absolute/path/to/trusted/signed/envbank \
   scripts/e2e-live.sh vercel-production
   ```

   Direct equivalent: `envbank vercel accept-production --manifest M --plan PLAN_ID`
   with the same authorization/target environment and owner-controlled auth.
   The Preview command refuses this target, and Production refuses Preview.
4. The runner verifies baseline mismatch/health, drives the normal staged
   workflow, proves the new deployment is current and consumes the new value,
   rejects a negative control, then uses the normal signed rollback path. PASS
   requires the original deployment current again, healthy and serving its old
   value. Lost promotion/rollback responses are reconciled read-only, not resent.
5. A blocked receipt preserves operation/stage/current-target evidence and
   scoped recovery instructions. Inspect it before continuing. Do not delete a
   created deployment until the prior Production target is confirmed restored.
   Deployment rollback does **not** restore project variables: the new fixture
   variable remains applied or possibly partially applied. Cleanup is explicit
   and limited to the disposable resources/credentials listed in the receipt.

No real run has been performed. Remaining external steps are selecting both
disposable targets, private credential import, a trusted signed build with the
required Keychain access entitlements, owner enrollment, and physical prompt
acceptance (approve, cancel, approve again). Keep the long-lived owner signing
key; it is not a throwaway provider token. Automatic browser key capture still
requires the separate [host checklist](computer-use-host-acceptance.md).
