# SiftCut staging implementation plan

## Status and scope

This plan turns the requirements in
[SiftCut staging use-case gaps](siftcut-use-case-gaps.md) into an implementable
sequence for EnvBank. It covers bundle contracts, trusted derivation, Railway
variable synchronization, Clerk intake, resumability, reconciliation,
readiness, recovery, and rotation.

The first release target is a disposable SiftCut-shaped staging environment.
It is not authorization to modify the real SiftCut Railway or Clerk resources.
Real-provider testing remains manual, credential-gated, and separate from the
default automated test suite.

The implementation must preserve the architecture's existing zero-knowledge
boundary: the sync service stores ciphertext, while only a trusted local
EnvBank process decrypts records or constructs provider request bodies.

## Decisions and capability gates

### 1. Treat the contract as public and runtime state as encrypted

The checked-in manifest is a strict, versioned, non-secret declaration of
intent. It contains logical variable names, source types, policies,
destinations, public constants, derivation templates, intentionally absent
names, and deployment ordering metadata.

The following are runtime state and must not be written into the manifest or a
plaintext plan file:

- local secret-record revisions and provider credentials;
- generated, imported, or derived values;
- provider request bodies and provider responses that may contain values;
- resumability checkpoints that include internal object identifiers; and
- evidence that would provide a reversible value fingerprint.

Store bundle snapshots, plans, and operation journals as new encrypted vault
objects rather than overloading environment-variable records. This avoids
showing bookkeeping objects in `envbank list`, permits schema evolution, and
allows recovery artifacts to carry the state required to resume safely.

### 2. Keep secret records backward-compatible

Do not change the record-ID or record-AAD formulas for existing
`SecretRecord` values. Bundle records should use a deterministic, valid
physical record name derived from the bundle ID and logical variable name,
for example:

```text
ENVBANK_B1_<base32(sha256(bundle-id))>_<LOGICAL_NAME>
```

The manifest and encrypted bundle snapshot map that physical name back to the
logical destination name. Existing unbundled records continue to work. The
CLI must display logical names in bundle commands and never expose physical
record names in plans or normal bundle output.

Before committing this encoding, add test vectors and set length limits so
every valid logical name maps to a valid EnvBank record name without
truncation collisions.

### 3. Use a strict data-only manifest parser

Version 1 should support YAML as shown in the use-case document, using a
maintained parser configured for known fields and scalar/collection data only.
Reject aliases, custom tags, merge keys, duplicate keys, multiple documents,
unknown fields, and input above fixed size/depth/item limits. Decode into typed
Go structures, then canonicalize to deterministic JSON before hashing.

The parser belongs in the contract layer, not the cryptographic core. Pin and
review the parser dependency and include it in vulnerability and SBOM checks.
If the project decides to preserve a standard-library-only parser boundary,
ship JSON manifests in v1 and defer YAML rather than implementing an ad hoc
YAML parser.

### 4. Railway metadata-only reconciliation is a release gate

Railway's documented GraphQL `variables` query returns a map of names to
values. The adapter must not call that query merely to discard values. Railway
also documents sealed variables, whose values cannot be retrieved through the
API, and `skipDeploys: true` for variable upserts. Before implementing the
production adapter, run a disposable capability spike against the current
introspected schema to answer:

1. Is there an API query that returns variable names and sealed/presence state
   without requesting values?
2. Can new variables be created sealed, or must sealing be a separate mutation?
3. Does `skipDeploys: true` stage changes without committing or deploying them?
4. What stable mutation result or staged-change identifier can be persisted
   for idempotent resume?
5. Can a project token prove its exact project and environment, enumerate the
   four allowed services, and perform only the required mutations?

If no metadata-only query exists, names-only provider reconciliation is not
fully implementable. The adapter may still support explicit writes, but plan
and verify must report provider presence as `unverifiable`; the SiftCut MVP
acceptance gate remains open. It must not weaken the invariant by fetching
plaintext values.

### 5. Clerk intake is a separate capability gate

Clerk's Backend API itself authenticates with an instance secret key. Confirm
in a disposable Clerk instance whether the current official API can create or
return the instance secret and webhook signing secret directly to the local
process. In particular, do not assume that the Backend API's generic “API
Keys” resource is the instance `CLERK_SECRET_KEY`.

If either value is dashboard-only, implement a provider-specific human intake
path whose secret-bearing UI is never inspected by a model, screenshot, or
accessibility automation. General browser capture is out of scope. A manual
trusted-stdin intake is acceptable for the first SiftCut evaluation if it
commits before returning redacted success.

## Target architecture

```text
checked-in manifest
        |
        v
contract parser/validator -----> canonical manifest digest
        |                                  |
        v                                  v
bundle preparer <---- decrypted records ---- encrypted bundle snapshot
        |                                  |
        v                                  v
provider-neutral planner ----------> encrypted plan + operation journal
        |                                  |
        v                                  v
Railway / Clerk adapters <---------- resumable state machine
        |
        v
names-only or explicitly limited verification evidence
```

Only the local CLI process crosses the plaintext boundary. Provider adapters
receive secret values as in-memory byte buffers and write request bodies
directly to an in-process HTTP client. They must not invoke a shell, pass
values as arguments or environment variables, or serialize request bodies to
disk.

### New packages

| Package | Responsibility |
| --- | --- |
| `internal/contract` | Parse, normalize, validate, and digest manifests. |
| `internal/bundle` | Resolve logical records, prepare sources, evaluate derivations, and create snapshots. |
| `internal/vaultobject` | Encrypt/decrypt typed non-record vault objects with domain-separated IDs and AAD. |
| `internal/rollout` | Provider-neutral plan, apply, verify, resume, rotate, and revoke state machine. |
| `internal/provider` | Adapter interfaces, capability declarations, redacted errors, and common result types. |
| `internal/provider/railway` | Railway GraphQL transport and SiftCut-safe variable operations. |
| `internal/provider/clerk` | Clerk API operations and protected intake abstractions. |
| `internal/readiness` | Local protection, recovery, reachability, scope, and plaintext-artifact checks. |

Keep command parsing thin. Move reusable record load/store behavior currently
embedded in `cmd/envbank/main.go` into `internal/client` or `internal/bundle`
before adding the new commands.

### Encrypted vault objects

Add a versioned envelope independent of `SecretRecord`:

```go
type VaultObject struct {
    Kind       string
    Key        string
    Revision   int64
    ModifiedAt string
    Payload    json.RawMessage
}
```

Derive the opaque object ID with a domain-separated HMAC over kind and key;
encrypt with a distinct AAD label such as `envbank.object.v1`. The server needs
only opaque object CRUD with optimistic revisions. It must not learn object
kind, bundle name, manifest digest, provider, target, or operation status.

Required v1 object kinds:

- `bundle-snapshot`: manifest digest, physical-to-logical mapping, source
  status, and exact secret record revisions;
- `provider-plan`: target binding, actions, digest, creation/expiry, and
  expected revisions, with no secret values;
- `rollout-operation`: per-action state, attempt metadata, sanitized provider
  evidence, and terminal status; and
- `readiness-attestation`: timestamps and non-sensitive pass/fail evidence for
  operator prerequisites.

Plans should expire after a short fixed interval (initially 15 minutes). Their
digest binds the canonical manifest digest, bundle snapshot revision, provider
identity, exact target IDs, ordered action list, and expiry. Apply refetches
the plan and every referenced record, recomputes the digest, and fails closed
on any mismatch.

Recovery artifact v2 must include encrypted-object plaintext inside the
artifact's outer encryption, preserving source revisions as evidence while
resetting restored sync revisions in the same way record restore does today.
Version 1 artifacts remain readable.

### Manifest model

The final schema should represent the complete contract, not only the five
secret examples. At minimum:

```yaml
version: 1
bundle: short-editor/siftcut-staging/staging

policies:
  password-32:
    type: password
    length: 32
    lowercase: true
    uppercase: true
    digits: true
    symbols: true

records:
  POSTGRES_PASSWORD:
    source: generate
    policy: password-32
  MIGRATOR_PASSWORD:
    source: generate
    policy: password-32
  API_PASSWORD:
    source: generate
    policy: password-32
  MIGRATOR_DATABASE_URL:
    source: derive
    template: postgresql://siftcut_migrator:${secret:MIGRATOR_PASSWORD}@postgres.railway.internal:5432/siftcut
  DATABASE_URL:
    source: derive
    template: postgresql://siftcut_api:${secret:API_PASSWORD}@postgres.railway.internal:5432/siftcut

targets:
  railway:
    project: siftcut-staging
    environment: staging
    services:
      postgres:
        order: 1
        variables:
          POSTGRES_DB: {source: constant, value: siftcut}
          POSTGRES_USER: {source: constant, value: siftcut_admin}
          POSTGRES_PASSWORD: {source: record, record: POSTGRES_PASSWORD}
          MIGRATOR_PASSWORD: {source: record, record: MIGRATOR_PASSWORD}
          API_PASSWORD: {source: record, record: API_PASSWORD}
      migrator:
        order: 2
        variables:
          MIGRATOR_DATABASE_URL: {source: record, record: MIGRATOR_DATABASE_URL}
      api:
        order: 3
        variables:
          NODE_ENV: {source: constant, value: staging}
          PORT: {source: constant, value: "3000"}
          DATABASE_URL: {source: record, record: DATABASE_URL}
          CLERK_ISSUER: {source: import, sensitivity: public}
          CLERK_AUDIENCE: {source: import, sensitivity: public}
          CLERK_AUTHORIZED_PARTIES: {source: import, sensitivity: public}
          CLERK_SECRET_KEY: {source: record, record: CLERK_SECRET_KEY}
          CLERK_WEBHOOK_SIGNING_SECRET: {source: record, record: CLERK_WEBHOOK_SIGNING_SECRET}
      web:
        order: 4
        variables:
          API_UPSTREAM: {source: constant, value: "http://api.railway.internal:3000"}
          VITE_CLERK_PUBLISHABLE_KEY: {source: import, sensitivity: public}
        absent:
          - VITE_API_URL
```

The example constants must be checked against the actual SiftCut repository
before its manifest is committed; they are schema illustrations, not an
authoritative SiftCut configuration.

Validation rules:

- allow only manifest version 1 and a bounded bundle identifier;
- require exactly one source for every record and destination;
- distinguish `constant`, `import`, `generate`, `derive`, and `record`;
- forbid secret material in fields declared public and reject suspicious
  secret-shaped constant names by policy;
- validate environment variable names and prevent duplicate destinations;
- require every record reference and policy to exist;
- parse derivation placeholders into an AST; do not perform string replacement
  with regular expressions;
- topologically sort derivations and reject self-references and cycles;
- cap manifest size, records, targets, services, template length, dependency
  count, and expanded value size;
- require absent names not to appear in the same service's variables;
- require provider, project, environment, and service names plus immutable IDs
  after target binding; and
- treat `order` as report-only metadata. No bundle command deploys services.

## Delivery phases

### Phase 0: provider capability spikes and threat review

Deliverables:

1. A fake Railway GraphQL server and a small experimental client that proves
   request/response redaction and `skipDeploys` behavior locally.
2. A disposable real-Railway capability report answering the five Railway
   gate questions above without using SiftCut credentials.
3. A disposable Clerk capability report identifying which secret values can
   enter an in-process adapter and which require trusted human intake.
4. A written data-flow/threat review for manifest parsing, derivation memory,
   provider credentials, GraphQL errors, HTTP tracing, crash dumps, and
   resumability state.

Exit criteria:

- exact adapter capabilities and limitations are recorded;
- the Railway operation that writes variables is proven not to deploy or
  commit staged changes;
- metadata-only reconciliation is either proven or explicitly marked blocked;
- provider credentials have a supported platform-protected storage path; and
- no implementation relies on browser scraping or shelling out to provider
  CLIs.

### Phase 1: manifest and encrypted object foundation

Implement:

1. Typed manifest structures, strict YAML decoding, canonical JSON, and SHA-256
   manifest digests in `internal/contract`.
2. Semantic validation, derivation dependency graph, deterministic ordering,
   and useful errors that contain paths/names but never values.
3. Opaque encrypted vault-object CRUD in protocol, client, and server layers,
   including optimistic revisions and privacy-preserving access events.
4. Bundle snapshot and plan schemas with explicit format versions.
5. CLI dispatch for:

   ```text
   envbank bundle check --manifest PATH
   envbank bundle status --manifest PATH [auth flags]
   ```

Tests:

- table and fuzz tests for duplicate keys, aliases, tags, cycles, missing
  references, unknown fields, oversized documents, expansion limits, and
  canonical digest stability;
- server integration tests proving the service sees only opaque IDs and
  ciphertext;
- revision-conflict and cross-kind/AAD substitution tests; and
- golden output tests showing only bundle, logical names, sources, targets,
  status, and digests.

Exit criteria:

- a SiftCut-shaped manifest validates deterministically;
- malformed or ambiguous manifests fail before vault or provider mutation;
- bundle metadata survives sync without becoming visible to the service; and
- all existing record/recovery/browser tests remain green.

### Phase 2: trusted bundle preparation and derivation

Implement `envbank bundle prepare --manifest PATH [auth flags]` as a local,
resumable operation:

1. Validate and canonicalize the manifest before unlocking records.
2. Load the current encrypted bundle snapshot and referenced records.
3. Generate each missing `source: generate` record once using the existing
   unbiased password generator and its named policy.
4. Accept `source: import` values only through trusted stdin or a provider
   intake interface. Never accept secret values as arguments.
5. Evaluate derivations in topological order using parsed literal/reference
   nodes. Append directly into bounded in-memory buffers.
6. Store every generated/imported source before deriving dependents, and store
   every derived result before advancing its journal state.
7. Use expected revisions on all writes. On conflict, stop, refetch, and require
   a new prepare operation; never overwrite a concurrent change.
8. Persist an encrypted snapshot only after all required records are durable.

Idempotency rules:

- a matching snapshot plus matching source revisions is a no-op;
- retry never regenerates an already stored password;
- derivation is recomputed only when the manifest digest or an input revision
  changes;
- changed inputs create new derived revisions but retain previous revisions in
  the recovery artifact until rollout validation is complete; and
- prepare never contacts Railway or deploys anything.

Memory and output rules:

- use byte buffers where practical and zero temporary buffers on completion;
- disable request dumps and ensure errors identify only logical record names;
- never print values, templates after expansion, lengths that act as unexpected
  fingerprints, or physical record keys; and
- document that Go strings and garbage collection prevent a guarantee of
  immediate memory erasure.

Tests:

- three generated fixture passwords are independent and policy-compliant;
- the two database URLs have exact expected fixture values when inspected only
  inside the test process;
- stdout, stderr, structured logs, operation objects, and temp directories do
  not contain any plaintext fixture or component substring;
- injected failures after each write resume without new generation; and
- concurrent source replacement produces a stale-revision failure.

Exit criteria:

- the complete local SiftCut bundle can be prepared without plaintext output;
- the snapshot binds every required logical record to an exact revision; and
- `bundle status` reports missing/prepared/stale using names only.

### Phase 3: provider-neutral rollout engine

Define a narrow adapter interface before adding Railway behavior:

```go
type Capabilities struct {
    Create, ReadMetadata, Update, Validate, Revoke bool
    SupportsIdempotencyKey, SupportsMaskedPresence bool
}

type Adapter interface {
    Identity(context.Context) (Identity, error)
    Inspect(context.Context, Target) (MetadataState, error)
    Write(context.Context, WriteRequest) (WriteEvidence, error)
    Verify(context.Context, VerifyRequest) (VerifyEvidence, error)
}
```

Secret fields in `WriteRequest` must be an unexported or specially marshaled
type that cannot be formatted with `%v`, JSON-marshaled outside the adapter, or
included in wrapped errors. Provider errors pass through a sanitizer that
returns operation, HTTP/GraphQL status, bounded provider code, and retry class,
never response bodies.

State machine:

```text
draft -> prepared -> planned -> confirmed -> writing -> written
                                              |           |
                                              v           v
                                          retryable    verifying
                                                          |
                                            verified <----+----> limited
                                                |
                                         ready-to-deploy
```

Each variable action separately moves through `pending`, `in_flight`,
`committed`, and `verified`/`limited`. Persist `in_flight` before a call and
persist provider evidence immediately after success. If a crash occurs while
in flight and the provider lacks an idempotency key, resume with inspection;
if inspection cannot prove outcome, stop for explicit reconciliation rather
than issuing a blind duplicate irreversible operation.

`plan` is read-only. `apply` requires:

- an unexpired plan ID;
- exact manifest, snapshot, target, adapter-identity, and record-revision
  matches;
- an interactive TTY confirmation immediately before the first provider write;
- a second confirmation for any deletion or future revocation; and
- refusal of non-interactive confirmation flags in v1.

### Phase 4: Railway plan, apply, resume, and verify

Implement the Railway adapter in-process with `net/http` and GraphQL request
constants. Provider tokens must come from a project-scoped credential protected
by macOS Keychain for the initial supported path. Use the project-token identity
query to bind immutable project and environment IDs. Bind service names to
immutable IDs during plan and fail on missing, duplicate, or unexpected target
resolution.

Commands:

```text
envbank railway bind --bundle BUNDLE [auth flags]
envbank railway plan --bundle BUNDLE [auth flags]
envbank railway apply --plan PLAN_ID [auth flags]
envbank railway resume --operation OPERATION_ID [auth flags]
envbank railway verify --bundle BUNDLE [auth flags]
```

Planning behavior:

- inspect only documented metadata-only endpoints proven in Phase 0;
- include exactly `postgres`, `migrator`, `api`, and `web` for SiftCut;
- classify actions as add, update, unchanged, intentionally absent, or
  unverifiable only when evidence supports that label;
- never claim equality from masked presence;
- plan removal of `VITE_API_URL` only if the provider can prove it is present;
  deletion requires explicit apply-time confirmation; and
- if names cannot be inspected safely, mark all provider state unverifiable
  and leave the names-only acceptance criterion blocked.

Apply behavior:

- send one service-scoped collection upsert at a time with `replace: false`
  and `skipDeploys: true`, or single upserts if they offer safer resumability;
- never call environment staged-change commit, deploy, redeploy, restart,
  domain, service-create, or service-delete mutations;
- order writes by service order only for deterministic reporting and resume;
- record completed actions after each successful response;
- honor provider rate limits and bounded retry-after values; and
- make cancellation before confirmation a guaranteed no-write path.

Verification behavior:

- re-resolve the exact project/environment/service identity;
- report required-name presence only from metadata-only evidence;
- report local snapshot revision and completed operation evidence;
- classify sealed or non-readable variables honestly;
- report staged changes separately from deployed state; and
- stop at `ready for separately authorized deployment`. Do not add a deploy
  command as part of this use case.

Integration tests use an `httptest` GraphQL server that records operation names
and sanitizes bodies before assertion. Cover timeout before response, timeout
after server commit, partial service failure, rate limiting, stale plans,
expired plans, target renames, wrong project token, unexpected service IDs,
presence limitations, and forbidden mutation detection.

Exit criteria:

- a names-only plan binds the exact four services and local revisions;
- apply uses only allowed variable mutations with no deployment mutation;
- partial failure resumes without regenerating or redoing proven writes; and
- verification states presence and limitations without value reads.

### Phase 5: Clerk protected intake

Implement public metadata and secret intake as separate paths:

- public values (`CLERK_ISSUER`, `CLERK_AUDIENCE`, authorized parties, and
  publishable key) may be validated and stored as public contract imports;
- `CLERK_SECRET_KEY` and `CLERK_WEBHOOK_SIGNING_SECRET` use an official API
  adapter only if Phase 0 proves the API returns them directly to the local
  process under appropriate scope;
- otherwise accept each through a trusted, no-echo stdin/terminal flow and
  immediately store it with optimistic revision checks; and
- return only logical name, stored revision, provider identity match, and a
  redacted status.

If creating a webhook is supported, split it into create, store, validate, and
eventual revoke operations under the same rollout state machine. Never delete
the previous endpoint or signing secret until the new endpoint is validated
and the operator explicitly authorizes revocation.

Tests use fake Clerk responses containing sentinel secrets and assert the
sentinels are absent from output, logs, errors, journal objects, screenshots,
and filesystem scans. Browser fallback requires its own threat review and is
not part of the first adapter milestone.

### Phase 6: reconciliation, readiness, recovery, and rotation

Add:

```text
envbank bundle reconcile --manifest PATH [auth flags]
envbank readiness check --bundle BUNDLE [auth flags]
envbank bundle rotate --manifest PATH RECORD... [auth flags]
```

Reconciliation compares three independently labeled states:

1. contract intent from the canonical manifest;
2. local encrypted snapshot and current record revisions; and
3. provider names/presence and prior write evidence.

It never collapses `present`, `written by operation X`, and `equal` into one
state. Example output:

```text
api/DATABASE_URL: present; local bundle revision 17; value equality unavailable
api/CLERK_SECRET_KEY: present; provider value not requested
web/VITE_API_URL: intentionally absent
provider synchronization: incomplete (2 names missing)
```

Readiness checks should return pass/fail/unknown for:

- device config permissions and supported local protection;
- current Keychain credential availability without exposing account IDs;
- recent encrypted recovery artifact and recorded recovery drill;
- approved private-network reachability to the EnvBank service;
- Railway/Clerk adapter identity and required scope;
- manifest digest and snapshot compatibility; and
- known EnvBank-created plaintext export paths (the check cannot prove that no
  other program created a plaintext copy).

Rotation reuses prepare, plan, apply, verify, and revoke states. It creates new
record revisions, retains last-known-good revisions in a new encrypted recovery
artifact before rollout, validates the new provider state, observes any grace
period, and requires explicit confirmation before revoking old credentials.
Database-role password rotation also needs a separate PostgreSQL-side adapter
or operational step; updating only Railway variables would break authentication
and must not be labeled a complete rotation.

Recovery tests must prove that artifact v2 restores secret records, bundle
snapshots, and sufficient non-secret operation evidence to reproduce a fresh
plan. Provider tokens and provider authorization are deliberately excluded and
must be re-established on the replacement device.

## Test and security matrix

| Layer | Required tests |
| --- | --- |
| Contract | unit, fuzz, canonicalization goldens, schema compatibility, malicious YAML corpus |
| Derivation | DAG/cycle tests, size bounds, exact fixture results, redaction scans, failure injection |
| Vault objects | crypto round trips, domain separation, optimistic conflicts, server opacity, migrations |
| Rollout | state transition table, crash at every boundary, idempotency, stale/expired plan rejection |
| Railway | fake GraphQL server, allowed-operation allowlist, target binding, rate limits, partial writes |
| Clerk | fake secret responses, commit-before-success, intake cancellation, lifecycle rollback |
| CLI | stdout/stderr goldens, TTY confirmation, exit codes, no secret-bearing arguments |
| Recovery | v1 compatibility, v2 round trip, interrupted restore resume, bundle-plan reproduction |
| End to end | disposable providers only, four services, intentional absence, no deployment, recovery drill |

Every secret-bearing test should use unique high-entropy sentinel fixtures and
scan:

- captured stdout and stderr;
- structured and HTTP logs;
- serialized plan and journal objects after decryption inside the test;
- shell history fixture files;
- temporary directories and crash artifacts; and
- fake-provider request recordings after the adapter-specific assertion has
  completed.

The fake provider necessarily receives fixture plaintext to emulate the trust
boundary; its recorder must be test-only and never used by production logging.

Run at least:

```text
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
node --test extension/test/*.test.js
make recovery-drill
gitleaks detect --no-banner
```

Add fuzz targets to the normal corpus and a failure-injection end-to-end job to
CI. Keep live-provider tests opt-in, excluded from pull requests, and guarded
against real SiftCut identifiers.

## Work breakdown and dependencies

| ID | Work item | Depends on | Parallelizable after dependency | MVP gate |
| --- | --- | --- | --- | --- |
| P0 | Railway capability spike | none | Clerk spike, threat review | yes |
| P1 | Clerk capability spike | none | Railway spike, threat review | Clerk only |
| A1 | Manifest schema/parser/digest | threat review | object foundation | yes |
| A2 | Encrypted vault objects/server migration | threat review | manifest work | yes |
| A3 | Recovery artifact v2 | A2 | CLI manifest work | yes |
| B1 | Bundle snapshots and physical-name mapping | A1, A2 | derivation engine | yes |
| B2 | Trusted derivation engine | A1 | snapshot CLI | yes |
| B3 | Prepare/status commands | B1, B2 | provider engine | yes |
| R1 | Provider interface and redaction types | threat review | A1, A2 | yes |
| R2 | Rollout state machine and plans | A2, B1, R1 | Railway transport | yes |
| R3 | Railway transport and identity binding | P0, R1 | R2 | yes |
| R4 | Railway plan/apply/resume/verify | B3, R2, R3 | readiness | yes |
| C1 | Clerk intake/API adapter | P1, R1, B3 | Railway work | Clerk completion |
| O1 | Reconciliation/readiness | R4, A3 | Clerk work | final MVP |
| O2 | Disposable end-to-end and recovery test | R4, C1, O1 | none | release |
| O3 | Rotation/revocation workflows | R2, R4, C1 | after MVP | post-MVP |

Recommended pull-request sequence:

1. Provider capability reports and threat model addendum.
2. Strict manifest parser, schema, fixtures, and `bundle check`.
3. Encrypted vault objects, server migration, and recovery v2.
4. Bundle prepare/status plus trusted derivation.
5. Provider interface, plan schema, and rollout state machine with a fake
   adapter.
6. Railway identity binding and names-only plan.
7. Railway apply/resume/verify with forbidden-operation tests.
8. Clerk protected intake.
9. Reconciliation, readiness, and disposable end-to-end recovery test.
10. Rotation, grace-period, PostgreSQL credential application, and revocation.

## Definition of done

The SiftCut staging MVP is done only when all original acceptance criteria are
demonstrated in disposable environments and the following additional
conditions hold:

- a capability report confirms the exact Railway API contract used by the
  adapter;
- provider-value read queries and deployment mutations are absent from the
  production Railway adapter;
- a checked-in SiftCut manifest has repository-owner approval for every public
  constant, intended absence, target, and ordering declaration;
- all mutations have stale-revision and crash-resume tests;
- recovery artifact v2 restores the bundle state needed to make a new plan;
- provider credentials are not part of manifests, plans, recovery artifacts,
  command arguments, or sync-service plaintext;
- documentation distinguishes provider presence, prior write evidence, and
  value equality; and
- security review signs off on any browser fallback before it is enabled.

If Railway cannot provide metadata-only variable presence, the implementation
may ship local preparation and explicitly confirmed write-only synchronization
as an experimental subset, but it must not declare the complete SiftCut use
case done.

## Provider references checked for this plan

- Railway Public API and token scopes:
  <https://docs.railway.com/integrations/api>
- Railway variable API operations and `skipDeploys` guidance:
  <https://docs.railway.com/integrations/api/manage-variables>
- Railway staged changes:
  <https://docs.railway.com/deployments/staged-changes>
- Railway sealed-variable behavior:
  <https://docs.railway.com/variables>
- Clerk Backend API reference:
  <https://clerk.com/docs/reference/backend-api>
- Clerk webhook overview:
  <https://clerk.com/docs/guides/development/webhooks/overview>

Provider APIs are time-sensitive. Re-run the capability spikes against the
current official schemas before implementation and before each release.
