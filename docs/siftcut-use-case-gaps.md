# SiftCut staging use-case gaps

## Purpose

This document evaluates EnvBank against one concrete workflow: preparing and
maintaining the secrets and environment variables for SiftCut's Railway staging
stack without exposing values through model prompts, screenshots, logs, shell
arguments, or clipboard history.

It is a product gap analysis, not a claim that EnvBank or the SiftCut staging
environment is production-ready. The current EnvBank alpha remains subject to
the [architecture and threat model](architecture.md), the
[production deployment checklist](production-deployment.md), and the deferred
work in the [product roadmap](roadmap.md).

## Target workflow

SiftCut uses a Railway project named `siftcut-staging`, a `staging` environment,
and four ordered services:

1. `postgres`
2. `migrator`
3. `api`
4. `web`

The desired operator journey is:

1. Load a versioned, non-secret variable contract from the SiftCut repository.
2. Generate independent PostgreSQL administrator, migrator, and API passwords.
3. Store those passwords in EnvBank without displaying them.
4. Derive the migrator and API connection URLs inside a trusted local process.
5. Capture Clerk secrets directly from a trusted provider response or explicit
   human-controlled input.
6. Show a names-only plan for the exact Railway project, environment, and
   services.
7. Commit variables to Railway without exposing their values to an agent,
   browser accessibility data, terminal output, or clipboard history.
8. Verify provider-side presence and deployment health using sanitized status
   evidence.
9. Resume safely after partial failure and later rotate credentials without
   losing the last known-good values.

Deployment remains a separate, explicitly authorized operation. Variable
synchronization must not implicitly apply Railway staged changes or deploy a
service.

## SiftCut variable contract

The repository contract currently requires these names:

| Service | Required variables |
| --- | --- |
| `postgres` | `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `MIGRATOR_PASSWORD`, `API_PASSWORD` |
| `migrator` | `MIGRATOR_DATABASE_URL` |
| `api` | `NODE_ENV`, `PORT`, `DATABASE_URL`, `CLERK_ISSUER`, `CLERK_AUDIENCE`, `CLERK_AUTHORIZED_PARTIES`, `CLERK_SECRET_KEY`, `CLERK_WEBHOOK_SIGNING_SECRET` |
| `web` | `API_UPSTREAM`, `VITE_CLERK_PUBLISHABLE_KEY` |

`VITE_API_URL` is intentionally absent in staging so the browser uses the
public web origin and the web service proxies API traffic over Railway private
networking.

The three database passwords must be independently generated. The migrator and
API connection URLs reuse the corresponding passwords and target
`postgres.railway.internal`; this dependency is the central derived-secret gap
in the current product.

## Current capability fit

EnvBank already supplies useful primitives for part of the workflow:

- password generation that stores the value without printing plaintext;
- encrypted records whose names and values remain hidden from the sync service;
- standard-input ingestion for values obtained through a trusted local path;
- optimistic revisions that can reject stale record replacement;
- exact-origin browser authorization and human-selected field filling on
  macOS;
- passphrase-protected device identity, Keychain integration, device
  revocation, encrypted recovery exports, and access-event history; and
- direct child-process environment injection without a plaintext `.env` file.

These primitives make EnvBank suitable for a controlled staging evaluation as
a secondary vault and secure-fill mechanism. They do not yet provide a safe
end-to-end SiftCut synchronization workflow.

## Product gaps

### 1. Namespaced bundles and contracts

Records are individually addressable, but EnvBank lacks a first-class bundle
such as `short-editor/siftcut-staging/staging` that binds variable names to
their intended services and provider targets.

EnvBank also cannot import a repository-owned, non-secret contract describing:

- required and intentionally absent names;
- generated, imported, constant, and derived values;
- destination project, environment, and service;
- validation rules and rotation policy; and
- deployment ordering metadata that is reported but not automatically acted
  upon.

Without that contract, an operator can store values but cannot safely prove
that the complete and correct set is destined for the correct services.

### 2. Derived values

EnvBank cannot currently construct a value from encrypted records without
revealing the source values to an external shell, model, or page. SiftCut needs
at least:

```text
MIGRATOR_DATABASE_URL =
  postgresql://siftcut_migrator:${MIGRATOR_PASSWORD}@postgres.railway.internal:5432/siftcut

DATABASE_URL =
  postgresql://siftcut_api:${API_PASSWORD}@postgres.railway.internal:5432/siftcut
```

Derivation must occur in a trusted local EnvBank process. Inputs and the result
must remain encrypted at rest and must never appear in diagnostics, command
arguments, process listings, or normal output.

### 3. Railway provider adapter

The browser extension can fill one selected field, but it cannot reconcile a
multi-service environment or prove that an entire contract is synchronized.
EnvBank needs a local Railway adapter that can:

- bind to one exact workspace, project, environment, and service set;
- read variable names and masked presence without requesting provider values;
- produce a names-only, values-redacted plan;
- upsert values directly from decrypted EnvBank memory;
- require confirmation immediately before provider writes;
- persist resumable operation state without secret material;
- verify names, targets, and provider-side presence after writes; and
- keep variable synchronization separate from staged-change application and
  service deployment.

The adapter should use the narrowest supported Railway authorization and keep
that credential behind local platform protection. A model must not receive the
credential or provider request body.

### 4. Clerk secret intake

Some Clerk values are discoverable non-secret metadata, while the secret key
and webhook signing secret require a protected intake path. EnvBank has no
Clerk adapter and its browser extension fills values but does not securely
capture a one-time provider value.

The preferred adapter should use an official provider API when possible and
commit returned secrets directly to EnvBank before producing only redacted
status. A browser fallback, if required, must be provider-specific and must
keep secret-bearing page state outside model and accessibility inspection.
General page scraping is out of scope.

### 5. Transactional rollout state

Optimistic record revisions protect individual writes, but the workflow spans
multiple records and two providers. EnvBank does not yet implement the durable
create, store, validate, rollout, and revoke state machine described in the
roadmap.

For SiftCut, an interrupted operation must distinguish:

- generated and durably stored;
- derived and durably stored;
- planned for a provider target;
- committed to that target;
- provider presence verified; and
- ready for a separately authorized deployment.

Retrying must not generate replacement passwords, repeat an irreversible
provider action, or discard the last known-good revision.

### 6. Sanitized reconciliation

The existing CLI can list local records and rotation status, but it cannot
compare a repository contract, an EnvBank bundle, and provider-side masked
state. The SiftCut workflow needs output limited to evidence such as:

```text
api/DATABASE_URL: present, bundle revision 17
api/CLERK_SECRET_KEY: present, value not read back
web/VITE_API_URL: intentionally absent
provider synchronization: incomplete (2 names missing)
```

Provider values must not be read back merely to compare them. When a provider
cannot attest to a committed revision, EnvBank must say that verification is
limited rather than implying equality.

### 7. Guided operational readiness

Before the workflow can be relied on, EnvBank needs a readiness check that
brings existing runbooks into the operator path. It should verify, without
printing sensitive identifiers or values:

- local device and Keychain protection;
- current encrypted recovery artifact;
- successful backup and recovery drill;
- approved private-network reachability to the EnvBank service;
- expected provider-adapter identity and scope;
- contract and bundle revision compatibility; and
- absence of plaintext export files created by EnvBank.

This check does not replace host hardening, provider-side audit controls, or
the production deployment checklist.

## Proposed minimum viable workflow

### Bundle manifest

Add a versioned, non-secret manifest format. A SiftCut manifest should express
intent without embedding secret values:

```yaml
version: 1
bundle: short-editor/siftcut-staging/staging

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
```

The final schema should use a parser that cannot execute code, should reject
unknown fields, cycles, missing references, duplicate destinations, and
unbounded expansion, and should explicitly separate public constants from
secret-derived records.

### Commands

A minimal operator interface could be:

```text
envbank bundle check --manifest siftcut-staging.envbank.yaml
envbank bundle prepare --manifest siftcut-staging.envbank.yaml
envbank railway plan --bundle short-editor/siftcut-staging/staging
envbank railway apply --plan PLAN_ID
envbank railway verify --bundle short-editor/siftcut-staging/staging
```

`check`, `plan`, and `verify` are read-only. `prepare` may generate and store
local records but does not contact a provider. `apply` is the only variable
synchronization command and requires an exact, unexpired plan plus action-time
confirmation.

### Safe plan contents

A plan may contain:

- provider and target identifiers;
- variable names;
- add, update, unchanged, intentionally absent, and unverifiable states;
- encrypted bundle revision references;
- creation and expiration times; and
- a digest binding the plan to the manifest, target, and expected local
  revisions.

It must not contain values, derivation results, provider credentials, decrypted
record identifiers, or reversible value fingerprints.

## Security invariants

Any implementation for this use case must preserve these invariants:

1. Secret plaintext never enters a model prompt or tool result.
2. Secret plaintext never appears in screenshots, accessibility trees, logs,
   shell arguments, clipboard history, plan files, or error messages.
3. Generated and derived values are durably stored before provider rollout.
4. A plan is bound to an exact provider account, project, environment, service,
   manifest digest, and local record revisions.
5. A stale or expired plan fails closed.
6. Provider writes require action-time confirmation and do not imply deploy,
   staged-change apply, domain creation, or credential revocation.
7. Retries are idempotent where the provider permits and otherwise stop for
   explicit reconciliation.
8. Verification reports presence and scope honestly; masked presence is not
   described as value equality.
9. The last known-good credential remains recoverable until replacement is
   validated and an explicitly authorized revocation completes.
10. Provider adapters remain outside the cryptographic core and declare their
    create, read-metadata, update, validate, and revoke capabilities.

## Acceptance criteria

The minimum SiftCut use case is complete when a disposable test environment can
prove all of the following:

- A checked-in manifest contains no credential values and Gitleaks reports no
  findings.
- EnvBank generates three independent database passwords without plaintext
  output.
- Both database URLs are derived and stored without exposing their component
  passwords or final values.
- A names-only Railway plan targets exactly four expected services in the
  expected project and environment.
- Cancelling before apply causes no provider changes.
- Applying after confirmation populates every required variable and leaves
  `VITE_API_URL` absent.
- No operation applies Railway staged changes or deploys a service.
- An injected failure after a subset of provider writes resumes without
  regenerating values or repeating completed writes.
- Verification reports required-name coverage and any provider limitations
  without reading back or printing values.
- Clerk secret intake commits the returned secret before showing sanitized
  success and never exposes it through browser automation evidence.
- Recovery from the encrypted artifact restores the bundle revisions needed to
  reproduce a plan in a fresh disposable EnvBank environment.
- Sanitized tests inspect command output, structured logs, plan state, shell
  history, and temporary files and find no plaintext fixtures.

Real SiftCut and provider credentials must not be used in automated tests.

## Non-goals

This use case does not require or justify:

- exposing EnvBank directly to the public Internet;
- treating EnvBank as a KMS, HSM, or provider-side access-control replacement;
- general-purpose browser scraping;
- unattended deployment or staged-change application;
- automatic credential revocation without confirmation;
- storing provider credentials in a repository manifest;
- enterprise organization roles or multi-tenant vault administration; or
- weakening the existing recovery, origin, device, or local-passphrase
  boundaries for convenience.

## Roadmap impact

The SiftCut workflow supplies a concrete first consumer for several existing
roadmap milestones. Recommended implementation order:

1. Versioned bundle manifest and strict contract validation.
2. Trusted derived-record evaluation.
3. Railway names-only planning, variable upsert, and sanitized verification.
4. Durable resumable rollout state.
5. Clerk secret intake and webhook lifecycle adapter.
6. Guided readiness and end-to-end disposable recovery tests.

The first four items make EnvBank materially useful for SiftCut staging. Clerk
integration completes the secret-intake path. Rotation and revocation should
then build on the same durable state machine instead of introducing a separate
automation path.
