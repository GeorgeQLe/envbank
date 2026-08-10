# Local bundle preparation

EnvBank can validate, prepare, and inspect a version-1 bundle manifest without
contacting Railway, Clerk, or any other provider:

```sh
envbank bundle check --manifest siftcut-staging.envbank.yaml
envbank bundle status --manifest siftcut-staging.envbank.yaml \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase
envbank bundle prepare --manifest siftcut-staging.envbank.yaml \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase
```

`bundle status` reports `missing`, `stale`, or `prepared` for the bundle and
each logical record. It never displays the deterministic physical record name,
record value, expanded template, value length, or internal object identifier.

## Trusted stdin imports

When imported records are missing, `bundle prepare` reads exactly one bounded
JSON object from standard input. Keys must exactly match the missing imported
logical records and values must be strings. Values are never accepted as flags
or positional arguments. Generate the JSON in a trusted local process and pipe
it directly to EnvBank:

```sh
trusted-intake-command | envbank bundle prepare \
  --manifest siftcut-staging.envbank.yaml \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase
```

Avoid shell history, temporary files, clipboard contents, and commands that
place a value directly in their arguments. A retry does not require stdin when
all imported records are already durable.

## Durability and conflicts

Preparation uses a deterministic bundle-scoped physical name for every
logical record. Missing generated passwords are created once with their named
policy. Imported and generated sources are stored before dependents are
derived. Derived values are assembled in topological order with a one-MiB
limit, and every durable record is followed by an encrypted, names-and-
revisions-only checkpoint. The encrypted bundle snapshot is published only
after a final revision check confirms that no input changed concurrently.

All record, checkpoint, and snapshot writes use expected revisions. A conflict
fails closed and asks the operator to refetch and begin a new prepare
operation. A matching snapshot and matching record revisions make preparation
a no-op. Changing an input makes the snapshot and every affected derivation
stale; the next preparation creates new derived revisions before publishing a
replacement snapshot.

When a record advances, the new encrypted snapshot retains its prior revision
numbers as non-secret recovery evidence. It never stores prior values or value
fingerprints in the snapshot or prepare journal.

These commands mutate only the encrypted EnvBank vault. Provider planning,
variable writes, service deployment, verification, and revocation are outside
this workflow.

## Railway names-only planning

On a cgo-enabled macOS build, bind a Railway project token from trusted stdin.
The token must be scoped to the manifest's exact project and environment. It is
verified before being stored in macOS Keychain and is never accepted as a flag,
environment variable, manifest field, or plan field:

```sh
trusted-token-command | envbank railway bind \
  --manifest siftcut-staging.envbank.yaml \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase

envbank railway plan \
  --manifest siftcut-staging.envbank.yaml \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase

envbank railway apply --plan PLAN_ID \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase

envbank railway resume --operation OPERATION_ID \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase

envbank railway verify --bundle example/siftcut/railway-staging \
  --config /secure/path/device.json \
  --passphrase-file /secure/path/passphrase
```

Binding verifies Railway's immutable project/environment identity and resolves
exactly `postgres`, `migrator`, `api`, and `web` to immutable service IDs. The
plan binds those IDs, the manifest digest, the encrypted snapshot revision, and
each referenced local record revision. Output includes provider identifiers
and variable names, but no values, physical record names, or credential
fingerprints. Encrypted plans may retain manifest-declared public constants;
secret values remain referenced only by logical record and exact revision.

Railway's documented variable query returns values, so EnvBank does not call it
in this workflow. Required-present and intended-absent names are therefore
reported honestly as `unverifiable`; absence is not inferred and no deletion is
planned. Locally available record-backed values and public constants become
ordered upserts. Apply requires an interactive terminal confirmation and uses
only Railway's single-variable upsert with `skipDeploys: true`.

Every action is durably marked in flight before its request and committed after
a successful response. Resume skips committed actions and may repeat an
ambiguous Railway upsert because setting the same name to the same value is
idempotent. Verification rechecks the exact immutable target and reports local
write evidence, but provider presence remains `unknown`; it never calls the
value-returning variable query. Staged-write evidence is kept separate from
deployed state, and EnvBank stops at readiness for a separately authorized
deployment. There is no deployment or deletion command.

## Memory limitation

EnvBank overwrites temporary byte buffers where practical, but Go strings and
garbage collection prevent a guarantee that every plaintext copy is erased
from process memory immediately. A compromised endpoint or authorized process
inspection at use time can expose plaintext. Run preparation only on a trusted
host and keep crash dumps, tracing, request dumps, and swap controls within the
same threat boundary as the vault client.
