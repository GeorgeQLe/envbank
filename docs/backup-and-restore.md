# Backup and restore

This runbook covers the EnvBank sync-service database. It assumes a single
SQLite database on a host where the EnvBank binary and `/usr/bin/sqlite3` are
available.

The procedure protects server-side ciphertext, enrollment state, revocation
state, replay protection, and access history. It does not replace device-config
backups or the planned encrypted recovery export.

## Practice the procedure

Run the disposable drill from the repository root:

```sh
make recovery-drill
```

The drill builds a temporary EnvBank binary unless `ENVBANK_BIN` names an
existing executable. It binds only to `127.0.0.1:17337`, uses dummy values,
creates its fixture under the operating system's temporary directory, stops
every fixture service, and removes the fixture on exit.

Use a different loopback port or retain the fixture for local inspection:

```sh
ENVBANK_PORT=17437 KEEP_ARTIFACTS=1 make recovery-drill
```

The equivalent command-line options are `--port PORT` and
`--keep-artifacts`. Retained artifacts contain only drill data, but still
include private device keys encrypted with public dummy passphrases and should
be deleted after inspection.

A passing run verifies:

- The online backup and restored database both have mode `0600`.
- `PRAGMA quick_check` returns `ok` and `PRAGMA user_version` returns `3`.
- A deliberately truncated backup and a future schema are rejected before
  restore startup.
- A pre-backup sentinel decrypts, while a post-backup commit is absent.
- Active and revoked device states survive, and the revoked device remains
  denied.
- Access history remains readable and records new events.
- A post-restore write decrypts and survives another service restart.

The output is sanitized pass/fail evidence. It includes a SHA-256 digest and
the measured recovery-point window and recovery time, but no decrypted value,
vault ID, device ID, fingerprint, private key, signature, or passphrase.

## Create an online backup

Do not copy the live database file with Finder, `cp`, a filesystem snapshot
that is unaware of SQLite, or a backup agent that reads only the main file.
EnvBank uses SQLite write-ahead logging (WAL). A committed transaction may
exist in `server.db-wal` but not yet in `server.db`, so copying only the main
file can produce a stale or inconsistent recovery point.

Use SQLite's online backup API while EnvBank is running:

```sh
umask 077
/usr/bin/sqlite3 /secure/envbank/server.db \
  ".timeout 5000" \
  ".backup '/secure/backups/envbank-YYYYMMDDTHHMMSSZ.db'"
chmod 600 /secure/backups/envbank-YYYYMMDDTHHMMSSZ.db
```

The `.backup` operation obtains the SQLite locks needed to copy a consistent
database image while normal service traffic continues. The timeout lets it
wait briefly for a concurrent writer instead of failing immediately.

Validate the result before declaring the backup successful:

```sh
/usr/bin/sqlite3 /secure/backups/envbank-YYYYMMDDTHHMMSSZ.db \
  'PRAGMA quick_check; PRAGMA user_version;'
shasum -a 256 /secure/backups/envbank-YYYYMMDDTHHMMSSZ.db
stat -f '%Lp' /secure/backups/envbank-YYYYMMDDTHHMMSSZ.db
```

Require `ok`, schema version `3`, a recorded SHA-256 digest, and mode `600`.
Keep the digest in access-controlled operational records so transfer or storage
damage can be detected before a restore.

EnvBank record names and values are encrypted by device-held vault keys, so the
server database and its backup contain ciphertext for those fields. The backup
is not itself an encrypted container: it also contains service metadata,
device public keys, revocation state, timestamps, and access history. Store it
on an encrypted volume or in a backup system with encryption at rest, strict
access control, retention limits, and tested deletion.

Do not restore a database with a schema version newer than the running EnvBank
binary supports. Upgrade EnvBank first or select a compatible backup. Never
edit `PRAGMA user_version` to bypass the compatibility check.

## Restore

Schedule an outage and isolate the target host from clients. Record:

- Incident or drill identifier
- Backup timestamp and digest
- Time of the last known-good commit
- Restore start and service-ready times
- Expected recovery point objective (RPO) and recovery time objective (RTO)

Then:

1. Stop EnvBank and wait for the process to exit.
2. Verify the selected backup's digest, `quick_check`, schema version, and
   permissions.
3. Create a quarantine directory on the same protected filesystem.
4. Move the current database and every existing `-wal` and `-shm` sidecar into
   quarantine. Do not leave old sidecars beside the restored database.
5. Copy the verified backup to the configured database path and set mode
   `0600`.
6. Start EnvBank at the same URL used by existing device configs.
7. Perform application-level checks through an approved device.

Example database operations, with EnvBank stopped:

```sh
mkdir -m 700 /secure/envbank/restore-quarantine-YYYYMMDDTHHMMSSZ
mv /secure/envbank/server.db \
  /secure/envbank/restore-quarantine-YYYYMMDDTHHMMSSZ/

test ! -e /secure/envbank/server.db-wal ||
  mv /secure/envbank/server.db-wal \
    /secure/envbank/restore-quarantine-YYYYMMDDTHHMMSSZ/
test ! -e /secure/envbank/server.db-shm ||
  mv /secure/envbank/server.db-shm \
    /secure/envbank/restore-quarantine-YYYYMMDDTHHMMSSZ/

cp /secure/backups/envbank-YYYYMMDDTHHMMSSZ.db \
  /secure/envbank/server.db
chmod 600 /secure/envbank/server.db
```

Application verification is mandatory. SQLite integrity alone cannot show that
the intended vault key decrypts records or that authorization state matches the
chosen recovery point. Verify all of the following:

- A known pre-backup sentinel decrypts through an original approved device
  config.
- A known post-backup marker is absent, establishing the actual recovery
  point.
- Expected approved and revoked devices have the correct status.
- A revoked device is still rejected.
- Access history can be read and records a new benign operation.
- A new post-restore record can be written and decrypted.
- That record survives one more clean service restart.
- Final `PRAGMA quick_check`, schema version, and database permissions pass.

Record the observed data-loss window as the RPO result and the interval from
service stop to verified service readiness as the RTO result. Compare both with
the service objectives rather than reporting only that the process started.

## Failure and rollback

If backup validation fails, do not start EnvBank with that candidate. Preserve
the failure logs and select another known-good backup.

If startup or any application check fails:

1. Stop the restored service.
2. Move the failed restored database and any new WAL/SHM files to a separate
   evidence directory.
3. Move the quarantined original database and its matching sidecars back to
   their exact original paths.
4. Confirm mode `0600`, restart, and repeat the application checks.
5. Keep the service isolated if rollback verification also fails, and escalate
   with the digest, schema, timestamps, logs, and observed check—not decrypted
   secret material.

Never mix a main database from one recovery point with WAL or SHM files from
another. Keep quarantine until the restore has passed, the RPO/RTO record is
complete, and the operator has explicitly ended the rollback window.

## Recovery boundary

A server backup cannot recover a vault when every approved device's private
keys and decrypted vault key are lost. The sync service is deliberately
zero-knowledge: its database contains encrypted records and device public keys,
not the vault key needed to decrypt them.

Preserve at least one approved, passphrase-protected device config in a
separate secure backup until EnvBank provides the planned encrypted recovery
export. Restoring only `server.db` cannot cross this cryptographic boundary.
