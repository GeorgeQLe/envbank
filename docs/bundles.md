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

## Memory limitation

EnvBank overwrites temporary byte buffers where practical, but Go strings and
garbage collection prevent a guarantee that every plaintext copy is erased
from process memory immediately. A compromised endpoint or authorized process
inspection at use time can expose plaintext. Run preparation only on a trusted
host and keep crash dumps, tracing, request dumps, and swap controls within the
same threat boundary as the vault client.
