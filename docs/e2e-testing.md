# End-to-end acceptance runbook

EnvBank's required merge gate is local, hermetic, disposable, and free:

```sh
npm ci --prefix website
make e2e
```

Install dependencies before disconnecting from the network. `make e2e` itself
does not download dependencies or contact provider APIs. It runs the complete Go
suite, the binary-level `envbank-testlab` lifecycle across a process restart,
the recovery drill, extension tests, website lint/typecheck/build, and a live
loopback production-server smoke. Loopback ports are selected automatically.

All state is created beneath a mode-`0700` temporary directory. Set
`KEEP_ARTIFACTS=1` only while debugging; retained output has already passed the
synthetic-credential scan. Never attach a retained directory without reviewing
it. A success ends with `e2e: RESULT=PASS` and removes its state. On failure,
rerun the named surface directly, then rerun the complete gate. No account,
credential, paid service, Docker daemon, browser, or macOS Keychain is required.

## Local release artifacts

```sh
make e2e-release-local VERSION=v0.2.0
```

This cross-builds four targets, creates and extracts release-shaped archives,
checks embedded version metadata where executable on the host, verifies local
SHA-256 calculations, and builds the production website. If Docker is running,
it additionally builds the image and checks `/healthz`; otherwise that field is
reported as `SKIP ... DOCKER_UNAVAILABLE`. This target is a release check, not a
merge-gate replacement.

## Disposable browser acceptance

Prerequisites are a graphical macOS or Linux session and the pinned Playwright
browser:

```sh
npm ci --prefix e2e/browser
npx --prefix e2e/browser playwright install chromium
make e2e-browser
```

The harness launches headed Chromium with a new profile and temporary `HOME`,
loads an isolated copy of the unpacked development extension, installs a test-only native messaging
manifest beneath that temporary home, and serves the form fixture on an
automatically assigned loopback port. The native host reuses production framing
and holds one synthetic value only in memory. The copied manifest adds only
loopback host access to stand in for the `activeTab` grant that a real toolbar
click provides; the checked-in manifest is unchanged. It exercises text, password, and
textarea fills; hidden/file/iframe refusal; exact-origin navigation rejection;
bounded native-host requests; generation/replacement metadata; and checks
console, browser storage, clipboard, screenshots, stdout, and stderr for the
marker. Normal Chrome profiles and manifests are never opened or modified.

`KEEP_ARTIFACTS=1` retains only artifacts that passed the marker scan. A normal
run deletes the temporary profile, manifest, host, screenshot, and logs.

## Interactive macOS and Touch ID acceptance

Run from an interactive terminal on the release Mac:

```sh
make e2e-keychain
```

The first randomized Keychain test must be approved with **Allow Once**; select
**Deny** on the second prompt. Both entries have cleanup handlers, and the
automated test also checks a wrong account and post-deletion absence. The
command then creates a loopback-only disposable vault, installs the production
native host for the pinned headed Chrome for Testing build, and launches it
with a temporary profile and the unpacked extension. Follow the terminal steps
to perform one exact-origin fill, click **Lock**, deny the next user-presence
request, and confirm the second field remains empty. Do not automate or
screen-capture Touch ID.

The native-host manifest is installed beneath the disposable Chrome user-data
directory with `--profile-dir`; the host binary and configuration locator use a
production support directory derived from that manifest path. Each browser or
profile installation therefore owns separate support artifacts. The manifest,
host, locator, temporary profile, randomized Keychain entry, service database,
and fixture are removed on success, failure, or a handled signal. The installer
refuses to overwrite an existing profile manifest or its support artifacts. It
scans the disposable profile, logs, database, and serialized state for the
randomized browser value before cleanup. If the runner cannot use an isolated
profile, do not continue; record the release exception instead.

`envbank browser-install` also enforces this rule: it exits before installation
when the Chrome native-host manifest already exists, and uses an exclusive
create for the manifest to prevent a check/write race from overwriting it. Its
matching uninstall validates the browser/profile target before any optional
Keychain deletion.

The release check targets the pinned headed browser with
`--browser chrome-for-testing --profile-dir <disposable-profile>`; cleanup
passes the same browser target and profile. Chrome launches with its mock
browser Keychain so Chrome Safe Storage cannot obscure the real EnvBank
Keychain prompt.

Unsigned command-line builds cannot use the entitlement-bound data-protection
Keychain on every macOS configuration. EnvBank prefers that modern path and,
only when macOS returns `errSecMissingEntitlement`, uses the macOS file-Keychain
ACL with no trusted applications. That fallback requires confirmation on every
read. Select the one-time **Allow** action; never select **Always Allow**, which
would add the caller as a persistent trusted application. Signed future app
bundles should use only the modern user-presence path.

## Opt-in free-provider probes

Live acceptance is local-only and must never run in CI:

```sh
ENVBANK_LIVE_ACCEPTANCE=1 make e2e-live PROVIDER=stripe
ENVBANK_LIVE_ACCEPTANCE=1 make e2e-live PROVIDER=clerk
ENVBANK_LIVE_ACCEPTANCE=1 make e2e-live PROVIDER=railway
```

The runners require an interactive TTY. Credentials are loaded from the macOS
Keychain service `com.envbank.acceptance` (account `stripe` or `railway`) or a
hidden prompt. Credential flags, piped stdin, and ordinary provider credential
environment variables are rejected. Non-secret target metadata uses the
provider-prefixed variables below. Every target name must contain the exact
case-sensitive marker `ENVBANK_ACCEPTANCE`.

Stripe requires `STRIPE_ACCEPTANCE_TARGET` and an HTTPS
`STRIPE_ACCEPTANCE_WEBHOOK_URL`. It identifies the sandbox account, creates one
webhook endpoint, captures the one-time signing secret through `SecretSink`,
validates the resource, deletes it, and requires a provider `404` afterward.
Only its resource ID is held in private mode-`0600` recovery state under the
user cache directory. A later run resumes that cleanup before creating another
endpoint; signals and ordinary errors also trigger a bounded delete.

Clerk requires `CLERK_ACCEPTANCE_TARGET`, `CLERK_ACCEPTANCE_MANIFEST`,
`CLERK_ACCEPTANCE_CONFIG`, `CLERK_ACCEPTANCE_PASSPHRASE_FILE`,
`CLERK_ACCEPTANCE_CLI`, `CLERK_ACCEPTANCE_APP`, and
`CLERK_ACCEPTANCE_AUTHORIZED_PARTY`. The official CLI must already be logged in
to a dedicated Development application. The runner uses the terminal-safe
helper only through `bundle prepare-exec` and accepts exactly five names/revision
records. The passphrase file is an existing private local input; the runner
never creates or copies it.

Railway requires the marked `RAILWAY_ACCEPTANCE_PROJECT` plus exact
`RAILWAY_ACCEPTANCE_ENVIRONMENT`, `RAILWAY_ACCEPTANCE_SERVICE`, and their
`_PROJECT_ID`, `_ENVIRONMENT_ID`, and `_SERVICE_ID` bindings. Use one dormant,
dedicated free project. The only mutation is an idempotent upsert of
`ENVBANK_ACCEPTANCE_SENTINEL`; the adapter hard-codes `skipDeploys: true` and
never queries values, deploys, or blindly deletes a variable. Verification is
truthfully printed as `LIMITED_NAMES_ONLY`.

There is no production Vercel lifecycle adapter. `PROVIDER=vercel` fails with
`PRODUCTION_ADAPTER_UNAVAILABLE`; hermetic emulator coverage remains required.
The public Vercel website is independently validated by its HTTP smoke tests.
If any provider removes its free allowance, record a release exception and skip
that local probe—never weaken the offline gate or incur a charge.

## Evidence

Record only fixed status fields, provider resource IDs, and the commit tested.
Do not record values, digests of values, terminal transcripts containing prompt
input, screenshots of secret-bearing pages, Keychain metadata, or recovery
state. The milestone ship manifest is
[`tasks/zero-dollar-e2e-ship-manifest.md`](../tasks/zero-dollar-e2e-ship-manifest.md).
