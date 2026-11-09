# Vercel vault-to-deployment workflow

EnvBank's Vercel path uses the REST API, existing encrypted bundle snapshots,
provider rollout engine, signed automation policy and encrypted vault objects.
It does not read local environment files or automate secret-bearing dashboard
pages. Acquiring a show-once provider key through browser capture remains a
separate, unqualified controller integration.

## Scope and boundaries

A binding names one immutable team ID and project ID, one Preview, Production
or custom environment, and optionally an exact Preview Git branch. The full
scope fingerprint is included in every plan's target service ID and signed
approval. Development is refused because this workflow requires write-only
Secret variables. Client-exposed/runtime-reserved variable names are refused.

The API adapter proves ownership before mutation, inspects metadata without
requesting decrypted values, and writes only Secret variables. It rejects
ambiguous/overlapping existing variable entries rather than broadening scope.
A metadata presence check remains limited verification, not proof of the exact
stored value. No key-creation or upstream key-revocation capability is implied.

Real credentials stay owner-controlled. `vercel bind` accepts its token through
trusted stdin and stores it with the exact scope in the existing macOS Keychain
boundary. Never paste token values into a chat, put them on command arguments,
or pull project variables into local files. The ordinary browser fill feature
is not part of this API path.

## Public manifest

Use a public bundle manifest with vault-record references only:

```yaml
version: 1
bundle: arcade/acceptance
records:
  API_SECRET:
    source: import
    sensitivity: secret
targets:
  vercel:
    team_id: team_REPLACE
    project: disposable-project
    project_id: prj_REPLACE
    environment: preview
    git_branch: envbank-acceptance
    services:
      environment:
        order: 1
        variables:
          API_SECRET:
            source: record
            record: API_SECRET
```

Replace the immutable IDs and exact branch before use. Prepare/import records
through the existing owner-controlled bundle flow. There is no plaintext value
field in a Vercel workflow tool request.

## Owner setup and approval

Commands below omit the normal `--config` and owner-controlled auth flags:

1. Owner supplies the Vercel token on trusted stdin to
   `envbank vercel bind --manifest PATH`. Binding performs read-only identity
   verification before storing the credential; it does not deploy or write
   project variables.
2. `envbank vercel plan --manifest PATH` creates an encrypted plan with exact
   record revisions and scope. Planning makes no provider writes.
3. Owner reviews the plan and runs
   `envbank vercel approve --manifest PATH --plan PLAN_ID --source-deployment dpl_ID --health-path /api/health`.
   Approval requires an interactive local confirmation **and** a fresh Secure
   Enclave owner signature (Touch ID/password) over the exact plan, source
   deployment, scope, health path, device key and expiry; the enrolled device
   then signs the stored policy. The owner key is enrolled once with the
   owner-only `envbank owner-approval enroll` command. There is no TTY-only or
   software fallback: without a pinned key or on non-macOS builds, approval
   and all Vercel mutations refuse. The default approval duration is one
   hour; the maximum is 24 hours after the owner signature. See
   [acceptance and hardware approval](vercel-acceptance.md).
4. `envbank vercel apply --manifest PATH --plan PLAN_ID` starts the durable
   workflow. Continue it with
   `envbank vercel resume --manifest PATH --operation OPERATION_ID`.
   Inspect it with the corresponding `status` command.

### Standing rotation approval

A per-plan approval is right for an ad-hoc deployment and wrong for
rotation, where the owner's intent is "keep these credentials fresh in this
target". A **standing approval** is the same signed, owner-approved policy
with no `deployment_plan_id` and no `deployment_source_id`, and a `schedule`
other than `manual`. It still binds the exact manifest digest, scope
fingerprint, health path, credentials, operations and device, and it still
expires (at most 90 days). While it is valid, the backend configured with
that policy ID (`Backend.StandingPolicyID`) accepts every plan for that
manifest: the owner signs once, and each rotation runs without them.

The source deployment is resolved when a run starts. Production rebuilds the
currently promoted deployment, after the usual drift check. Preview and
custom scopes have no single current deployment, so the caller names one
through the identifier-only `source_deployment_id` field of
`envbank_workflow_start`; a run without it is blocked with
`SOURCE_DEPLOYMENT_REQUIRED`. Everything else (durable intent before each
mutation, lease, health, promotion gate, rollback) is unchanged.

`vercelworkflow.RotationDeployer` adapts this workflow to the rotation
engine's `Deployer`: `Stage` plans the current snapshot (refusing one that
does not carry exactly the record revisions the engine just stored) and
drives it to the promotion gate; `Activate` promotes and returns the health
evidence; `Rollback` restores the previous production deployment. See
[agent-driven rotation](agent-rotation.md).

For an agent, start `envbank mcp serve --manifest PATH` with the existing
owner-controlled auth configuration. This pins the backend to that manifest and
credential scope. `envbank_setup_plan`, `envbank_workflow_start`,
`envbank_workflow_resume`, `envbank_workflow_status`,
`envbank_operation_evidence`, `envbank_policy_status` and
`envbank_deployment_rollback` accept identifiers only. Without an approval
carrying a valid owner signature from the pinned Secure Enclave key, mutations
refuse; a device-only signature is not enough. Starting MCP without a manifest
retains the unconfigured backend and advertises workflows unavailable.

The configured backend retains the device signing credential for vault
authentication while running, but hardware owner approval is a separate key
it cannot use: re-signing a changed policy with the device key breaks the
owner signature. Physical user presence has not been exercised (no key was
enrolled during implementation). The owner pin lives in the
passphrase-encrypted config; same-user code that also holds the passphrase can
still substitute it, and macOS offers no remote attestation of the key.
Keep signing/auth material outside agent-visible tools. Unused unlock-key
references are dropped and close releases retained references.
Go string copies are not guaranteed to be physically wiped. Do not give
untrusted same-user code process inspection or arbitrary signing-key access.

## Staging, activation and rollback

The workflow journals intent before mutation and serializes EnvBank operations
for a project within the same vault with the existing encrypted optimistic lease. The rollout engine
reads each approved record only when writing. Approval is checked again before
each write, and record/snapshot revisions are revalidated by the existing engine.

Only Git/server-built sources with an inspectable commit SHA are supported.
Prebuilt sources are rejected because a redeploy may reuse output without
consuming updated variables. Redeploy uses the approved source commit, applies the approved environment,
disables automatic custom-domain assignment and tags the deployment with the
operation/scope IDs. Production is staged as a Production build; a Preview is
never silently rebuilt/promoted into Production. Only the staged build that
passes three successful application-health checks over at least 30 seconds may
be promoted. The workflow checks for Production target drift before promotion
and verifies the current deployment afterward. Vercel has no cross-operation
compare-and-swap guarantee: coordinate external dashboard/deployment writers
during the approved window. Pause external Git/API/dashboard production deploys
and auto-promotion while production variables are changing; project variables
are live configuration for future builds, not an isolated draft. EnvBank's lease
serializes callers within one vault only. Separate vaults and outside writers
are not coordinated.

Preview/custom completion verifies the new deployment URL; it does not claim to
change Production or manage arbitrary branch/custom-domain aliases. Health uses
a status-only HTTPS GET on the owned `vercel.app` deployment URL with no redirects
or response-body reads. Evidence expires after two minutes and is checked again
at the promotion request boundary. Custom deployment hostname suffixes fail
closed. For protected previews, the owner may provide private stdin JSON
`{"token":"…","health_bypass":"…"}` when binding. The optional project automation
bypass is sent only as `x-vercel-protection-bypass` to the proven deployment,
never in a URL/cookie or as an API bearer. Its project-wide provider permission
is narrowed by EnvBank's scope checks. Without that owner-supplied credential,
401/403 fails health.

Production rollback is a separate approved action:
`envbank vercel rollback --manifest PATH --operation OPERATION_ID`.
It restores the approved prior immutable deployment and verifies the target.
It does **not** recover unknown old write-only project variable values. Those
project values remain changed for future builds and need a separately approved
restore from known encrypted vault material if required. Do not let another
writer redeploy them unknowingly after a rollback.

## Recovery and honest evidence

A dropped response after a variable write stops for reconciliation; presence
alone never proves the attempted value committed. An uncertain deployment create
is looked up by its operation/scope marker, never blindly recreated. Promotion
and rollback in-flight states reconcile the current deployment rather than
reissuing mutations. Conflicts and expired or changed approval stop the flow. A signed renewal may
change expiry only; every other initial approval field remains pinned.
Definite pre-send failures return to a pending stage. A crash without durable
send evidence stays uncertain even when a lookup finds nothing: absence is not
a provider idempotency guarantee. Lost variable-write/checkpoint acknowledgements
require reconciliation or a separately reviewed new plan, not a blind retry.

Receipts report the variable rollout ID and whether variables are applied or
possibly partially applied and not reverted. They contain fixed stages, blocker
codes, opaque IDs and health counts, not
credentials, value hashes, HTTP response bodies or remote error text. Provider
responses and Vercel itself remain trusted for authoritative resource IDs and
accepted-write semantics. Synthetic tests establish isolated behavior only;
real-account acceptance must use a disposable project/Preview branch and an
owner-imported token. No existing production project is an acceptance fixture.
The owner-run `envbank vercel accept` harness implements that Preview
acceptance (see [acceptance](vercel-acceptance.md)); it has not been run.

Official API sources:
[environment writes](https://vercel.com/docs/rest-api/projects/create-one-or-more-environment-variables),
[metadata reads](https://vercel.com/docs/rest-api/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name),
[deployment creation](https://vercel.com/docs/rest-api/deployments/create-a-new-deployment),
and the official CLI's
[promotion](https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/promote/request-promote.ts)
and [rollback](https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/rollback/request-rollback.ts).
