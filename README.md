# EnvBank

EnvBank is a small, zero-knowledge environment-variable store for development
and self-hosted production. Secret names and values are encrypted on the client;
the sync service stores only ciphertext. Devices are enrolled with public keys
and an out-of-band fingerprint check.

This is an initial, reviewable implementation—not yet a replacement for a
managed KMS or enterprise secrets manager. Read the
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
- Direct child-process environment injection without writing a `.env` file
- Exact-origin browser authorization stored inside each encrypted record
- A macOS Keychain-gated Chrome native host and dependency-free MV3 extension
- A transactional SQLite sync service that supports multiple service processes

## Build and test

Go 1.25.12 or later is required. Install `govulncheck` separately with
`go install golang.org/x/vuln/cmd/govulncheck@latest`; it is a review tool, not
an application dependency.

```sh
go version
go mod verify
go test ./...
go vet ./...
govulncheck ./...
go build -o envbank ./cmd/envbank
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
