# EnvBank

[![CI](https://github.com/GeorgeQLe/envbank/actions/workflows/ci.yml/badge.svg)](https://github.com/GeorgeQLe/envbank/actions/workflows/ci.yml)
[![Security](https://github.com/GeorgeQLe/envbank/actions/workflows/security.yml/badge.svg)](https://github.com/GeorgeQLe/envbank/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **v0.1.1-alpha:** EnvBank is prerelease software for evaluation. It has not
> reached a stable compatibility or operations baseline. Do not treat it as a
> KMS, HSM, enterprise secrets manager, or a substitute for provider-side
> access controls, rotation, auditing, and recovery.

EnvBank is a small, zero-knowledge environment-variable store for development
and self-hosted production. Secret names and values are encrypted on the client;
the sync service stores only ciphertext. Devices are enrolled with public keys
and an out-of-band fingerprint check.

This initial, reviewable implementation has important production limitations:
no vault rekeying, server rollback detection, service rate limiting, hardware
key custody, Windows support, or Apple signing/notarization. Endpoint,
child-process, and authorized browser-page compromise can expose plaintext at
use time. Read the
[architecture and threat model](docs/architecture.md) and
[cryptographic review brief](docs/cryptographic-review.md) and
[completed review report](docs/cryptographic-review-report.md) before
evaluation. The confirmed findings are remediated; the report's limitations,
deferred crypto-v2 hardening, and the operational production checklist still
constrain production claims.

For the server-enforced QR-first invitation design and its disposable developer lab, see
[device pairing](docs/device-pairing.md).

## Roadmap

See the [product roadmap](docs/roadmap.md) for the ordered path from today's
zero-knowledge foundation to safe recovery and provider-backed API-key
rotation.

Operators should also read the
[backup and restore runbook](docs/backup-and-restore.md), periodically run its
disposable recovery drill, and maintain a separate
[encrypted recovery artifact](docs/recovery.md).

## What works

- AES-256-GCM encrypted records with hidden, keyed record identifiers
- Ed25519-authenticated client/server requests and persisted replay protection
- X25519 vault-key wrapping for explicitly approved devices
- Ten-minute, single-use pairing invitations with cancellation, rejection, and
  attempt exhaustion
- Soft device revocation with an atomic last-active-device safeguard
- Privacy-preserving device-access history with bounded retention
- Passphrase-encrypted `0600` local device identity
- Passphrase-encrypted offline recovery exports and new-vault restoration
- Optimistic revisions to prevent silent concurrent overwrites
- Rotation policy reporting, local macOS notifications, and generated rotation
  values
- Cryptographically secure random-character password generation without
  plaintext output
- Direct child-process environment injection without writing a `.env` file
- Exact-origin browser authorization stored inside each encrypted record
- A macOS Keychain-gated Chrome native host and dependency-free MV3 extension
- A transactional SQLite sync service that supports multiple service processes

## Install v0.1.1

Release archives support macOS and Linux on AMD64 and ARM64. The macOS binaries
are unsigned and not notarized. Browser filling, Chrome native-host
installation, Keychain storage, and local rotation notifications are macOS-only;
the core CLI and sync service remain available on every released platform.

Download the archive for your platform from the
[v0.1.1 prerelease](https://github.com/GeorgeQLe/envbank/releases/tag/v0.1.1),
then verify it before extracting:

```sh
gh release download v0.1.1 \
  --repo GeorgeQLe/envbank \
  --pattern 'envbank_0.1.1_linux_amd64.tar.gz' \
  --pattern SHA256SUMS \
  --pattern 'envbank_0.1.1_sbom.spdx.json' \
  --pattern 'envbank_0.1.1_artifacts.provenance.json'
sha256sum --ignore-missing --check SHA256SUMS
gh attestation verify envbank_0.1.1_linux_amd64.tar.gz \
  --bundle envbank_0.1.1_artifacts.provenance.json \
  --repo GeorgeQLe/envbank \
  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.1
tar -xzf envbank_0.1.1_linux_amd64.tar.gz
./envbank_0.1.1_linux_amd64/envbank version
```

On macOS, verify a single downloaded archive with
`grep 'envbank_0.1.1_darwin_arm64.tar.gz' SHA256SUMS | shasum -a 256 -c -`
(substitute the archive name for your architecture). Inspect
`envbank_0.1.1_sbom.spdx.json` with an SPDX-compatible tool and verify its
provenance the same way:

```sh
gh attestation verify envbank_0.1.1_sbom.spdx.json \
  --bundle envbank_0.1.1_artifacts.provenance.json \
  --repo GeorgeQLe/envbank \
  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.1
```

For the complete credential-isolated public verification, including locally
stored Sigstore bundles and trusted roots, run:

```sh
./scripts/verify-release-anonymous.sh
```

The earlier v0.1.0 prerelease remains immutable and available, but its
provenance was not published as downloadable bundle assets. Use v0.1.1 for
anonymous verification.

Run the multi-architecture container by immutable digest in deployments:

```sh
docker pull ghcr.io/georgeqle/envbank:v0.1.1
docker image inspect ghcr.io/georgeqle/envbank:v0.1.1 \
  --format '{{index .RepoDigests 0}}'
gh attestation verify oci://ghcr.io/georgeqle/envbank:v0.1.1 \
  --repo GeorgeQLe/envbank \
  --signer-workflow GeorgeQLe/envbank/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.1
docker run --rm -p 127.0.0.1:7337:7337 \
  -v envbank-data:/data ghcr.io/georgeqle/envbank:v0.1.1
```

The image is shell-free, runs as UID/GID `65532`, and exposes `/healthz`.

## Build and test

Go 1.25.12 or later is required. Install `govulncheck` separately with
`go install golang.org/x/vuln/cmd/govulncheck@v1.6.0`; it is a review tool, not
an application dependency.

```sh
go version
go mod verify
go test ./...
go vet ./...
govulncheck ./...
go build -o envbank ./cmd/envbank
./envbank version
go run ./cmd/pairing-mvp
node --test extension/test/*.test.js
make recovery-drill
```

## Quick start

Start the service locally:

```sh
./envbank serve --listen 127.0.0.1:7337 --database .envbank/server.db
```

Create a passphrase file. Keep it outside the repository, back it up securely,
and ensure only your account can read it:

```sh
install -m 600 /dev/null /secure/path/envbank-passphrase
```

Write a strong passphrase into that file using a trusted local editor. Then
initialize a vault:

```sh
./envbank init \
  --server http://127.0.0.1:7337 \
  --vault personal \
  --device laptop \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase
```

Values are read from standard input so they do not appear in shell history:

```sh
printf '%s' "$VALUE_FROM_A_TRUSTED_SOURCE" |
  ./envbank set --rotate-days 30 \
    --config .envbank/laptop.json \
    --passphrase-file /secure/path/envbank-passphrase \
    API_TOKEN
```

Use the variables without creating a plaintext file:

```sh
./envbank run \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase \
  -- your-development-command
```

The child process and its descendants can read the injected values. On some
operating systems, privileged local users may also inspect process
environments.

## Recovery export

Create a recovery passphrase that is separate from the device passphrase, save
it in a private `0600` file, and export the current decrypted record snapshot
into a new encrypted artifact:

```sh
./envbank recovery-export \
  --output /secure/path/personal.recovery \
  --recovery-passphrase-file /secure/path/recovery-passphrase \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase
```

The artifact supports `recovery-verify`, `recovery-list`, `recovery-get`, and
`recovery-run` without the original service or any device config. Restoring
synchronized access requires a replacement EnvBank service:

```sh
./envbank recovery-restore \
  --artifact /secure/path/personal.recovery \
  --recovery-passphrase-file /secure/path/recovery-passphrase \
  --server https://replacement-envbank.example.com \
  --vault personal-recovered \
  --device replacement-laptop \
  --config /secure/path/replacement.json \
  --passphrase-file /secure/path/replacement-passphrase
```

See the [recovery guide](docs/recovery.md) for offline commands, interrupted
restore resumption, format guarantees, and recovery boundaries.

## Add a second device

Copy only the vault ID and server URL to the second device—never copy the first
device's config.

On the second device:

```sh
./envbank enroll-request \
  --server https://envbank.example.com \
  --vault-id VAULT_ID \
  --device workstation \
  --config /secure/path/workstation.json \
  --passphrase-file /secure/path/workstation-passphrase
```

Compare the printed fingerprint over a separate trusted channel. On an approved
device, list requests and approve the exact fingerprint:

```sh
./envbank enroll-list --config /secure/path/laptop.json \
  --passphrase-file /secure/path/laptop-passphrase

./envbank enroll-approve \
  --fingerprint VERIFIED_FINGERPRINT \
  --config /secure/path/laptop.json \
  --passphrase-file /secure/path/laptop-passphrase \
  DEVICE_ID
```

Back on the second device:

```sh
./envbank enroll-accept \
  --config /secure/path/workstation.json \
  --passphrase-file /secure/path/workstation-passphrase
```

## Revoke a device

List every active and revoked device from an active device:

```sh
./envbank device-list \
  --config /secure/path/laptop.json \
  --passphrase-file /secure/path/laptop-passphrase
```

Verify the target fingerprint over a trusted channel, then revoke it:

```sh
./envbank device-revoke \
  --fingerprint VERIFIED_FINGERPRINT \
  --config /secure/path/laptop.json \
  --passphrase-file /secure/path/laptop-passphrase \
  DEVICE_ID
```

Revoking the currently configured device also requires `--allow-self`. EnvBank
preserves that device's local config and Keychain entry, but the server rejects
all of its future authenticated requests. The server will not revoke the final
active device.

Revocation blocks future synchronization and approved enrollment-status
access. It cannot recall a vault key or ciphertext that the device already
downloaded. Re-enrollment therefore requires a new device identity; rotating
the vault key and re-encrypting existing records is a separate recovery
operation that EnvBank does not yet provide.

## Review access history

Authenticated devices can inspect the newest access events:

```sh
./envbank event-list --limit 100 \
  --config /secure/path/laptop.json \
  --passphrase-file /secure/path/laptop-passphrase
```

The tab-separated output contains the timestamp, acting identity (or `-`),
whether its signature was verified, operation, outcome, bounded reason (or
`-`), and target device identity (or `-`). When more history exists, the CLI
prints an opaque `--before` cursor hint to standard error.

The server records recognized enrollment, device-management, record, and event
listing operations, including verified policy rejections and authentication
failures. It never puts request bodies, ciphertext, record identifiers, secret
names or values, signatures, nonces, network addresses, forwarded headers, or
User-Agent strings into events. History is operational telemetry for review and
future risk scoring, not a signed, append-only, or rollback-resistant audit
log.

## Rotation

Show overdue entries:

```sh
./envbank due --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase
```

`due` exits with status 2 when rotation is needed, making it suitable for a
scheduled job. `--notify` sends a local macOS notification containing only the
count.

Generate and store a new random value:

```sh
./envbank rotate --bytes 32 \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase \
  API_TOKEN
```

This does not update the upstream provider. A safe provider/computer-use
adapter must create the provider credential, commit it to EnvBank, validate the
new credential, then revoke the old one. It must not expose values through model
prompts, screenshots, logs, shell arguments, or clipboard history.

For a human-compatible random-character password instead of a URL-safe token,
use `generate`. It defaults to 24 lowercase, uppercase, digit, and symbol
characters, guarantees every enabled class, and prints only the name and new
revision:

```sh
./envbank generate --length 32 --rotate-days 90 \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase \
  LOGIN_PASSWORD
```

Lengths from 8 through 256 are accepted. Disable classes with flags such as
`--symbols=false`; at least one class must remain enabled. Existing names are
refused unless `--replace` is present. Replacement preserves creation time,
origin permissions, and the current rotation policy unless `--rotate-days` is
also supplied. `rotate --bytes` remains the URL-safe token generator.

## Browser filling on macOS

Browser access is denied for existing and new variables until an exact origin
is allowed. HTTPS is required except for loopback development origins:

```sh
./envbank browser-allow \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase \
  API_TOKEN https://developer.example.com

./envbank browser-origins \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase \
  API_TOKEN
```

Prepare the native host after building the binary:

```sh
./envbank keychain-store \
  --config .envbank/laptop.json \
  --passphrase-file /secure/path/envbank-passphrase

./envbank browser-install --config .envbank/laptop.json
```

Then open `chrome://extensions`, enable developer mode, choose **Load
unpacked**, and select the repository's `extension` directory. The checked-in
development public key fixes the extension ID to
`pgbpmecaapiknpejgdkpaifpjcnckcnk`, matching the installed native manifest.

Open the popup on an HTTPS or loopback HTTP page. A blocked variable requires
an exact-origin confirmation. For an allowed variable, choose it and then click
one text/password input or textarea within 30 seconds. The value is fetched
only after that click. The page and its scripts can read a value after it has
been inserted.

`browser-uninstall` removes the copied host, locator, and Chrome manifest while
preserving the vault and Keychain item. Pass `--delete-keychain` only when that
credential should also be removed.

## Production deployment

The supported baseline is one hardened non-root container, one local Docker
volume, a loopback-only published port, and a TLS reverse proxy reachable only
through an authenticated private network. Follow the copy-ready
[production deployment runbook](docs/production-deployment.md) for preflight,
container limits, proxy policy, backup/recovery, upgrades, monitoring, incident
isolation, and the readiness checklist.

Deployment guidance is prepared, and the independent cryptographic review and
clean-clone remediation re-review are complete. Read the
[review report](docs/cryptographic-review-report.md), then complete every
environment-specific item in the production runbook before a deployment. See
the [product roadmap](docs/roadmap.md) for deferred architecture.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and pull-request
expectations. Report vulnerabilities only through the private process in
[SECURITY.md](SECURITY.md), never in a public issue.

EnvBank is licensed under the [Apache License 2.0](LICENSE). Changes are listed
in [CHANGELOG.md](CHANGELOG.md).
