# Cloudflare migration and rollout

EnvBank's production target is the Worker in
[`cloudflare/envbank-worker`](../cloudflare/envbank-worker): one named,
SQLite-backed Durable Object per vault, with Cloudflare Access in front of the
hostname and EnvBank signatures still required by the application.

Cloudflare Paid and North American placement are operational preferences, not
a strict US-residency claim. Edge and control-plane processing may be global.

## Client configuration

New device configs use encrypted format v2. The Access client ID and secret
are encrypted in the same local payload as device private material. Unlocking
a v1 config migrates it to v2; CLI unlock paths save the migrated file
atomically.

Credentials are accepted only as a single JSON object on trusted stdin:

```sh
credential-source | envbank access bind --config DEVICE.json
credential-source | envbank access rotate --config DEVICE.json
envbank access remove --config DEVICE.json
```

For a brand-new vault or enrollment behind an already-enforced Access policy,
pass `--access-credentials-stdin` to `init`, `enroll-request`, or a new-vault
`recovery-restore` and pipe the same JSON object. The credentials are used for
that first request and saved only inside encrypted config v2.

The client sends `CF-Access-Client-Id` and `CF-Access-Client-Secret` outside
the EnvBank signature message. It refuses authenticated redirects so neither
Access nor EnvBank authentication headers can be forwarded.

## Worker deployment

Install, check, and build without deploying:

```sh
cd cloudflare/envbank-worker
npm ci
npm run check
npx wrangler deploy --dry-run
```

Cloudflare Access must be enforced on the production route. `wrangler.toml`
contains no secret values. Keep the Worker script name exact and immutable for
each environment.

## Secret rollout

The manifest has one `cloudflare` target. `project_id` is the immutable account
ID, `environment_id` is the immutable zone/environment ID, and the sole service
key and `id` are both the exact Worker script name. D1, R2, Queues, Workers AI,
and other Cloudflare resources are bindings, not EnvBank records.

```sh
token-source | envbank cloudflare bind --manifest siftcut-staging.yaml
envbank cloudflare plan --manifest siftcut-staging.yaml
envbank cloudflare apply --plan PLAN_ID --worker-module dist/worker.js
envbank cloudflare resume --operation OPERATION_ID --worker-module dist/worker.js
envbank cloudflare verify --operation OPERATION_ID
envbank cloudflare promote --operation OPERATION_ID --manifest siftcut-staging.yaml
envbank cloudflare rollback --operation OPERATION_ID
```

`apply` decrypts the complete target set in memory and performs one multipart
version upload with strict binding inheritance. It does not deploy. Encrypted
operation evidence records the prior deployed version and the one staged
version; provider verification reads binding names from that exact version,
never values.

`promote` revalidates the plan, prepared snapshot, manifest digest, account,
zone, script, prior deployed version, and staged version. It requires a fresh
interactive confirmation, deploys the staged version at 100%, then runs every
manifest health check. Health policy must provide at least three successes over
at least 30 seconds. Failure force-deploys the recorded prior version and saves
encrypted rollback evidence.

## Cutover gates

Do not remove the Go/SQLite server, Docker image, Railway evidence readers, or
old infrastructure until all gates pass:

1. Deploy isolated, clearly marked Cloudflare staging resources and enable
   Access without production data.
2. Freeze source writes; create and validate a SQLite backup; import each vault
   transactionally while preserving ciphertext, identities, invitations,
   nonces, revisions, timestamps, objects, and audit sequence.
3. Compare canonical source/destination counts and digests without printing
   identifiers or ciphertext.
4. Complete pairing, read/write, recovery, replay, invitation, pagination,
   concurrency, rollback, deletion, and restore journeys.
5. Promote during a maintenance window and retain the old service read-only
   for seven clean days.
6. Run a restore drill. Only then remove Railway code and credentials, the Go
   production runtime, Docker/GHCR publication, and obsolete live probes.

The SiftCut application lives in a separate repository. Its D1/R2/Queues/AI/
Containers implementation and PostgreSQL-to-D1 importer must be qualified in
that repository; this repository owns EnvBank and its Cloudflare rollout
adapter only.
