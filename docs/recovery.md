# Encrypted recovery

An EnvBank recovery artifact is an independent, encrypted snapshot of every
secret record that an approved device can currently read. It is the recovery
path when the original sync service, device configs, or device identities are
unavailable.

The artifact contains record names, values, creation and rotation timestamps,
rotation policies, browser-origin allowlists, and source revisions inside its
encrypted payload. It does not contain the original vault key, device signing
or wrapping keys, device authorization, revocation state, replay nonces, or
access history.

## Create and protect an artifact

Use a strong recovery passphrase that is different from every device
passphrase. Store the artifact and passphrase separately, with independent
backups and access controls. The passphrase file must have mode `0600`.

```sh
./envbank recovery-export \
  --output /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase \
  --config /secure/envbank/laptop.json \
  --passphrase-file /secure/envbank/laptop-passphrase
```

The output path must not already exist. EnvBank writes the artifact atomically
with mode `0600` and will not overwrite an earlier snapshot. Create each new
snapshot at a new path, verify it, then apply the desired retention policy:

```sh
./envbank recovery-verify \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase
```

If `--recovery-passphrase-file` is omitted,
`ENVBANK_RECOVERY_PASSPHRASE` is used. Avoid exporting passphrases into a
long-lived shell environment. Recovery passphrases and secret values are never
accepted as command-line arguments.

Format version 1 uses AES-256-GCM with a random nonce. Its key is derived with
PBKDF2-HMAC-SHA-256, a random 16-byte salt, and 600,000 iterations. The format
version and KDF parameters are authenticated. Readers reject files larger than
256 MiB, unsupported versions or algorithms, altered or truncated ciphertext,
unsafe KDF parameters, malformed payloads, and duplicate or invalid records.

## Offline access

These operations need only the artifact, its passphrase, and the EnvBank
binary. They do not contact the original or a replacement service and do not
use a device identity:

```sh
./envbank recovery-list \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase

./envbank recovery-get \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase \
  API_TOKEN

./envbank recovery-run \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase \
  -- command-that-needs-the-environment
```

`recovery-list` prints names, policies, and source revisions, but no values.
`recovery-get` deliberately writes the selected value to standard output.
`recovery-run` exposes values only through the child environment; the normal
process-environment caveats still apply.

## Restore synchronized access

Start a fresh EnvBank service, choose a new local device passphrase, and use:

```sh
./envbank recovery-restore \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase \
  --server https://replacement-envbank.example.com \
  --vault personal-recovered \
  --device replacement-laptop \
  --config /secure/envbank/replacement.json \
  --passphrase-file /secure/envbank/replacement-passphrase
```

Restoration creates a new vault with a random vault key and a new signing and
wrapping identity. It saves the encrypted `0600` device config before uploading
records. Each recovered record is encrypted under the new vault ID and starts
at optimistic revision 1. Names, values, timestamps, rotation policies, and
browser-origin allowlists remain unchanged.

If an upload or network request fails after the config is saved, keep that
config and resume:

```sh
./envbank recovery-restore --resume \
  --artifact /secure/backups/personal.recovery \
  --recovery-passphrase-file /secure/offline/recovery-passphrase \
  --config /secure/envbank/replacement.json \
  --passphrase-file /secure/envbank/replacement-passphrase
```

Resume binds the config to the exact artifact, authenticates to the server
recorded in the config, verifies the new vault key against any uploaded
records, skips identical recovered records, and uploads missing records. It
stops if the target contains a changed recovered record or any unrelated
record. Do not use the replacement vault for normal writes until restoration
reports completion.

After a successful restore, verify `list`, `get`, browser origins, and a benign
post-restore write through the new config. Enroll additional devices normally.

## Recovery boundary

Offline access does not require any EnvBank service. Synchronized restoration
does require a reachable replacement service, but never contacts or trusts the
original one.

The artifact cannot recreate old device authorization, revocation state,
access history, or original record revision counters. Those belong to the old
service and identities. A restore is a deliberate cryptographic reset into a
new vault, not a continuation of the old authorization domain.
