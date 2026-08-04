# EnvBank

EnvBank is a small, zero-knowledge environment-variable store for development
and self-hosted production. Secret names and values are encrypted on the client;
the sync service stores only ciphertext. Devices are enrolled with public keys
and an out-of-band fingerprint check.

This is an initial, reviewable implementation—not yet a replacement for a
managed KMS or enterprise secrets manager. Read the
[architecture and threat model](docs/architecture.md) before using real
production credentials.

## What works

- AES-256-GCM encrypted records with hidden, keyed record identifiers
- Ed25519-authenticated client/server requests and persisted replay protection
- X25519 vault-key wrapping for explicitly approved devices
- Passphrase-encrypted `0600` local device identity
- Optimistic revisions to prevent silent concurrent overwrites
- Rotation policy reporting, local macOS notifications, and generated rotation
  values
- Direct child-process environment injection without writing a `.env` file
- Exact-origin browser authorization stored inside each encrypted record
- A macOS Keychain-gated Chrome native host and dependency-free MV3 extension
- A dependency-free Go binary and single-process self-hosted sync service

## Build and test

Go 1.25 or later is required.

```sh
go test ./...
go build -o envbank ./cmd/envbank
node --test extension/test/*.test.js
```

## Quick start

Start the service locally:

```sh
./envbank serve --listen 127.0.0.1:7337 --state .envbank/server.json
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

Build the container:

```sh
docker build -t envbank .
docker run --read-only --init \
  -p 127.0.0.1:7337:7337 \
  -v envbank-data:/data \
  envbank
```

Put the service behind an authenticated private network and a TLS reverse
proxy. Back up `/data/server.json`; it contains encrypted records and device
metadata, not plaintext values. Run only one service instance against a state
file. Set up a separate encrypted recovery copy or keep two approved devices,
because the service cannot recover a lost vault key.

Before broader production use, add a transactional database backend,
device revocation, signed audit checkpoints/rollback detection, rate limiting,
platform keychain support, and an external cryptographic review.
