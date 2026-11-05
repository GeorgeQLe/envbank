# Provider actions (`envbank.provider-actions/v1`)

Status (November 5, 2026): **broker side implemented and unit-tested against
fake providers (`internal/provideraction`, `internal/authz`); no provider
adapters plugged in yet, so every `provider_action` answers
`PROVIDER_UNAVAILABLE`; not qualified.** See
[Implementation notes](#implementation-notes).

## Goal

An authorized agent (docs/authorized-agents.md) sets up and rotates provider
credentials for a Vercel project (Neon Postgres, Stripe webhooks, Vercel env
vars and deployments). The only human step is the owner's Touch ID approval.
The agent never receives a secret value.

The broker makes every provider call itself, with control credentials held in
the vault. New secrets flow from the provider response into the vault
(`lifecycle.SecretSink`) and from the vault into Vercel `sensitive` env vars.
Nothing passes through the agent, a terminal, a browser or a command's output.

Owner decisions (November 5, 2026):

- **Stripe API key.** Use Vercel Connect managed Stripe keys: Vercel mints a
  restricted key and the app fetches it at runtime over OIDC. The owner accepts
  the integration once in the browser. EnvBank automates webhook signing secrets.
  It does not mint Stripe API keys, because Stripe offers no public API for that
  on the owner's own account.
- **Live acceptance.** Use throwaway resources only: a new Vercel project, a new
  Neon project, and Stripe test mode or a sandbox. Each is approved with Touch ID
  and deleted afterwards.

## Control credentials

Control credentials are vault records with a reserved name prefix `CONTROL_`:

| Record | Holds | Used for |
| --- | --- | --- |
| `CONTROL_VERCEL_TOKEN` | Vercel access token with team scope | project create and delete, env writes, deployments |
| `CONTROL_NEON_API_KEY` | Neon organization (or personal) API key | project create and delete, role password reset, connection URIs |
| `CONTROL_STRIPE_KEY` | Stripe test-mode restricted key (`rk_test_`/`sk_test_`) with webhook-endpoint write | webhook endpoint create and delete |

- **Reserved.** `CONTROL_*` records (prefix matched ignoring case) are never
  listed by `names`, injected by `run`, or used as the source or destination
  of an action. They can be granted only under `request`, for owner-typed
  entry; `names` and `run` grants naming them get `RESERVED_NAME`.
- **Seeding.** The owner seeds them once with the existing `request` flow:
  Chromux secure entry, with Touch ID to replace.
- **Live-mode Stripe keys.** `sk_live_` and `rk_live_` are refused in v1.

## Agent operations

Two new operations travel through the host channel the same way as `run`:
`agent_request` → service → broker, then `authz.Gate`.

- `provider_action {action, params, reason}` validates and plans, asks for Touch
  ID, and starts the action. It returns `{operation_id, state:"started"}`, or a
  fixed refusal code.
- `provider_status {operation_id}` returns `{operation_id, action, state, step,
  result?, code?}`, value-free.

Actions run asynchronously in the broker, because deployments and health checks
outlast the 110 s request budget. `operation_id` is a random 128-bit ID. Only
the session that started an operation may read its status.

### Grants

`grant_request {scope:"provider", actions:[ACTION...], duration_s}` asks the
owner, with Touch ID, to allow those action IDs for the session. Every
`provider_action` call still needs its own Touch ID approval, which shows the
exact plan. There is no "always" for provider actions.

### Actions (v1)

| Action | Params (all non-secret) | Effect | Result (value-free) |
| --- | --- | --- | --- |
| `neon.project.create` | `name`, `region_id?`, `pg_version?`, `roles?` (default `[app_a, app_b]`), `records:{pooled, direct}` | Create a project, prepare the rotation roles as its owner role (no adopt), then reset `roles[0]` and store its pooled and direct URIs in the two new records. Owner URIs are discarded, never stored | `project_id`, `branch_id`, `role` (owner), `database`, `active_role`, `prepared_roles`, `records:{name: revision}` |
| `neon.roles.prepare` | `project_id`, `branch_id`, `database`, `owner_role`, `roles?` (default `[app_a, app_b]`), `adopt` | For an existing project: make the roles rotation-ready (see [Neon rotation roles](#neon-rotation-roles)). With `adopt`, existing public-schema objects change owner, and the approval text says so | `prepared_roles` |
| `neon.project.delete` | `project_id` | Delete the project (throwaway cleanup) | `deleted` |
| `neon.rotate` | `project_id`, `branch_id`, `roles:[A, B]` (A is the role the deployment uses now), `owner_role`, `database`, `records:{pooled, direct}`, `vercel:{team_id, project_id, target, deployment?}`, `health_path` | Check the roles are prepared (`NEON_ROLES_NOT_PREPARED` otherwise, with no side effects), then zero-downtime rotation: reset the inactive role's password, store its URIs, push them to Vercel, redeploy, check health, then reset the previously active role (invalidating its old password) | active role, record revisions, `deployment_id` |
| `vercel.project.create` | `team_id`, `name`, `git_repo?` (`owner/repo`), `framework?` | Create a project | `project_id` |
| `vercel.project.delete` | `team_id`, `project_id` | Delete a project (throwaway cleanup) | `deleted` |
| `vercel.env.push` | `team_id`, `project_id`, `target` (`preview`\|`production`), `git_branch?`, `variables:{ENV_NAME: record}` | Upsert each variable as a `sensitive` env var | names and states |
| `vercel.redeploy` | `team_id`, `project_id`, `target`, `deployment?` (source ID; default current), `health_path?` | Redeploy, wait until ready, check health (at least 3 checks over at least 30 s, as in `lifecycle.HealthEvidence`) | `deployment_id`, health |
| `stripe.webhook.create` | `url` (HTTPS), `events:[...]`, `record` | Create an endpoint and store `whsec_…` in the record | `endpoint_id`, record revision |
| `stripe.webhook.rotate` | `endpoint_id`, `record`, `previous_record`, `vercel:{…}`, `health_path` | Create a new endpoint with the same URL and events. Move the current secret to `previous_record`, store the new one in `record`, push both, redeploy, check health, then delete the old endpoint | new `endpoint_id`, revisions |
| `stripe.webhook.delete` | `endpoint_id` | Delete an endpoint (cleanup) | `deleted` |

All IDs are validated against strict patterns:

- Vercel: `team_…`, `prj_…`, `dpl_…`
- Neon: project IDs `[a-z0-9-]`, branch IDs `br-…`
- Stripe: `we_…`, `acct_…`

Names and URLs are bounded. `production` targets need the action to name the
target explicitly, and the approval text says **PRODUCTION**.

### Neon rotation roles

Roles created through Neon's API do not share table ownership, so after a
switch from `app_a` to `app_b` the new role could not use the old role's
tables. Rotation-ready roles fix that:

- a no-login group role `envbank_app_owner` owns the public schema and every
  app object;
- `app_a` and `app_b` are members, each with
  `ALTER ROLE … SET role = 'envbank_app_owner'`, so every app session acts as
  the group owner;
- setup runs as the project owner role, with a connection URI the adapter
  fetches on demand through the Neon API, holds in memory only and wipes; it
  is never stored.

`neon.project.create` prepares them on a new project; `neon.roles.prepare`
prepares an existing one (`adopt` reassigns its existing public-schema
objects). Preparation is idempotent. `neon.rotate` first checks it
read-only (`RotationRolesReady`).

### Approval text

The broker builds the Touch ID reason from the validated plan only. Example:

    EnvBank: agent "<label>" (claude, 3f2a9c1e) wants to ROTATE Neon role
    app_b → active in project <id>, push DATABASE_URL, DATABASE_URL_UNPOOLED to
    Vercel prj_… preview, redeploy, then invalidate app_a.

## Implementation notes

Where the broker side (`internal/provideraction`, `internal/authz/provider.go`)
details or deviates from the above:

- **Wire format.** `provider_action {action, params, reason?}` answers
  `{v, ok, operation_id, action, state:"started"}` or `{v, ok:false, code}`.
  `provider_status {operation_id}` answers `{v, ok:true, operation_id,
  action, state, step, steps?, result?, code?}`: `ok` is true whenever the
  operation was found; a failed operation has `state:"failed"`, the `step`
  it stopped in and a fixed `code`. `steps` lists completed steps. `result`
  is a JSON object of validated IDs, record names and revisions, env var
  names and health counts; a failed operation keeps its partial result (for
  example the `project_id` or new `endpoint_id` to clean up). An unknown
  operation and another session's both answer `UNKNOWN_OPERATION`.
  `grant_request {scope:"provider", actions, duration_s}` takes no
  `secrets`; grants list `actions`.
- **Order of checks.** Grant (`NOT_AUTHORIZED`), then service available
  (`PROVIDER_UNAVAILABLE`: no factory, or no vault in setup mode), then
  strict params (`INVALID_REQUEST`: unknown fields, patterns, bounds), then
  side-effect-free prechecks (`CONTROL_CREDENTIAL_MISSING`, `RECORD_EXISTS`,
  `UNKNOWN_SECRET`), then a run slot (`BROKER_BUSY`), and only then Touch
  ID. A plan whose text does not fit the 600-byte prompt is refused
  (`INVALID_REQUEST`), never clipped. Checks that need a provider call
  (roles prepared, Stripe test-mode key) run after approval as the first,
  read-only step and fail the operation.
- **Approval text.** `perform a provider action: <plan>, for <agent kind>
  agent session <fingerprint> in workspace <ws>; session label: <label>`.
  The label comes last, as for every other approval; the agent's `reason`
  is shown only in the broker terminal.
- **Params.** A `production` target needs `"production": true` beside it;
  `production: true` with `preview` is refused. `git_branch` is preview only.
  Health paths are `/[A-Za-z0-9._~/-]*` without `..` or `//`
  (`vercel.redeploy` defaults to `/`). Webhook URLs are `https`, a DNS host
  (no IP, port, user info or fragment), at most 256 bytes, plain URL
  characters. Up to 16 events and 16 variables.
- **Env var names.** Composite actions push each record under an env var of
  the same name (`DATABASE_URL`, `STRIPE_WEBHOOK_SECRET_PREVIOUS`, …).
- **Records.** Create actions refuse an existing record (`RECORD_EXISTS`).
  Rotations overwrite their named records; the approval text names them.
  Each push reads the exact revision this operation stored.
- **Stripe rotation.** The current secret is copied to `previous_record`
  before the new endpoint is created, so the vault never loses the secret in
  use. If the operation fails after creating the endpoint, the new endpoint
  stays (its ID is in the result) and the old one is not deleted.
- **Health.** At least 3 successful checks spanning at least 30 s, every 15 s;
  any failed check fails the step. Only the clock and interval are
  injectable; the minimums are fixed.
- **Executor.** At most 2 operations run at once (a slot is reserved before
  the prompt); the journal keeps 64 operations, evicting the oldest finished.
  An operation is bounded to 30 minutes. A grant revoked or expired
  (`NOT_AUTHORIZED`) or the broker locking (`BROKER_CLOSED`) cancels it; the
  grant is re-checked before every step.
- **Control credentials.** Read per operation inside a vault callback into
  a broker buffer, passed to the factory, wiped when the operation ends.
  `CONTROL_STRIPE_KEY` must start `sk_test_` or `rk_test_`
  (`CONTROL_CREDENTIAL_REFUSED`).
- **Adapters seam.** `cmd/envbank/agent.go` `providerActionFactory` returns
  nil in this build. The ports are `NeonPort`, `VercelPort` and `StripePort`
  in `internal/provideraction/ports.go`.
- **Routes.** The development socket refuses `provider_action` and
  `provider_status` (`NOT_AUTHORIZED`); MCP has no provider tools.

## Properties

1. **Values.** No value appears in a response, status, error, log, plan or
   approval text. Provider errors are mapped to fixed codes
   (`provider.SanitizeError`).
2. **Endpoints.** Provider calls go only to fixed HTTPS endpoints:
   `api.vercel.com`, `console.neon.tech`, `api.stripe.com`. The tests use
   loopback overrides, which are not reachable from agent input.
3. **Ordering.** New values are stored durably before any destination is
   written. Old credentials are revoked only after health checks pass. If
   anything fails, the old credential stays valid and the operation ends
   `failed` with a step code. Neon's old role is reset only after health passes.
4. **No retained authority.** Control credentials are read per action, in a
   callback, and wiped afterwards.
5. **No agent routes.** Provider actions are not reachable through
   `--legacy-socket` or MCP. They require the paired host channel and a
   `provider` grant.

## Not covered (v1)

- Minting or rotating Stripe API keys. That goes through Vercel Connect;
  automating its rotation trigger needs a documented API, which is not yet
  verified.
- Minting Vercel or Neon API keys (control credentials are owner-seeded).
- Resuming an operation after a broker restart. The operation journal is in
  memory. A restart mid-rotation leaves both credentials valid, with the vault
  holding the new value. The owner reruns the action.
