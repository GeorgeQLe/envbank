# Provider actions (`envbank.provider-actions/v1`)

Status (November 5, 2026): **broker side and live adapters implemented;
tested end to end against stateful loopback fakes of Neon, Vercel and
Stripe (`internal/provideraction/live`); not yet accepted against the live
providers; not qualified.** The broker uses the adapters only when started
with `--provider-actions`; otherwise every `provider_action` answers
`PROVIDER_UNAVAILABLE`. See [Implementation notes](#implementation-notes).

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
| `neon.project.create` | `name`, `region_id?`, `pg_version?`, `roles?` (default `[app_a, app_b]`), `records:{pooled, direct}` | Create a project and record its provenance (`provider-neon-project`), prepare the rotation roles as its owner role (no adopt), then reset `roles[0]` and store its pooled and direct URIs in the two new records, bound to the project with no destination, `roles` and `active_role: roles[0]`. Owner URIs are discarded, never stored | `project_id`, `branch_id`, `role` (owner), `database`, `active_role`, `prepared_roles`, `records:{name: revision}` |
| `neon.roles.prepare` | `project_id`, `branch_id`, `database`, `owner_role`, `roles?` (default `[app_a, app_b]`), `adopt`, `adopt_existing_roles?` | For an existing project: make the roles rotation-ready (see [Neon rotation roles](#neon-rotation-roles)). `owner_role` must own `database` (`NEON_OWNER_ROLE_MISMATCH`). A rotation role that already exists, and was not created by this broker, is refused (`NEON_ROLE_EXISTS`) unless `adopt_existing_roles: true`; the approval text then names each one (`EXISTING role X will act as the schema owner`). With `adopt`, existing public-schema objects change owner, and the approval text says so | `prepared_roles` |
| `neon.project.delete` | `project_id` | Delete a project this broker created (`NOT_CREATED_BY_BROKER` otherwise; the text names it and says `created by this broker`) and revoke its records' bindings. Refused (`RESOURCE_STILL_DEPLOYED`, before the prompt and again as the first step) while a live binding of its records still lists a `deployed_to` entry: `vercel.env.remove` those first | `deleted`, `revoked_bindings` |
| `neon.rotate` | `project_id`, `branch_id`, `roles?:[A, B]` (optional; derived from the binding, and a mismatch is refused), `owner_role`, `database`, `records:{pooled, direct}`, `vercel:[{team_id, project_id, target, production?, git_branch?, deployment?}, …]` (1 to 3 scopes, at most one production; a preview scope must name `git_branch`), `health_path` | Check the roles are prepared (`NEON_ROLES_NOT_PREPARED`) and the owner (`NEON_OWNER_ROLE_MISMATCH`), then zero-downtime rotation: reset the inactive role's password, store its URIs, push them to every scope (production last), redeploy and check each, then reset the previously active role (invalidating its old password). The production scope runs a [production release](#production-releases) | active role, `invalidated_role`, record revisions, `redeployed`, `resumed` (production: release fields) |
| `vercel.project.create` | `team_id`, `name`, `git_repo?` (`owner/repo`), `framework?` | Create a project and record its provenance (allows no record) | `team_id`, `project_id` |
| `vercel.project.delete` | `team_id`, `project_id` | Delete a project this broker created (`NOT_CREATED_BY_BROKER` otherwise; the text names it), then drop its `deployed_to` entries | `deleted`, `forgotten_deployments` |
| `vercel.env.push` | `team_id`, `project_id`, `target` (`preview`\|`production`), `git_branch?`, `variables:{ENV_NAME: record}`, `replace_existing?` | Record the scope in each binding's `deployed_to`, then upsert each variable as a `sensitive` env var; every record must be bound and allowed to the project. An env var another record's binding claims in that scope (a revoked binding's claim counts), or one Vercel already holds that no binding claims (set by hand; a names-only read before the prompt and again just before the write), is `ENV_NAME_TAKEN` unless `replace_existing: true`; the text then says `REPLACES record B's value in ENV` (`REPLACES records B, C' values in ENV` when several claim it) or `REPLACES a value NOT written by this broker in ENV`, and after the push every other claimant's entry is dropped (`vault.release_env_owner`). The claims and unclaimed names are re-checked after approval (`ENV_NAME_TAKEN` if they changed). A push is refused if a later rotation of its records could not run: more than 3 distinct scopes (`ROTATION_SCOPE_LIMIT`), an all-branches preview (`ROTATION_UNSCOPED_PREVIEW`), a Neon sibling mid-rotation (`ROTATION_INCOMPLETE`), or a shortest possible rotation plan that would not fit the prompt (`PLAN_TOO_LONG`) | names and states, `replaced_records?` (the records actually released, also on a failed release) |
| `vercel.env.remove` | `record`, `env`, `team_id`, `project_id`, `target`, `production?`, `git_branch?` | Delete env var `env` from exactly that scope and drop that `deployed_to` entry of `record`'s binding (`vault.forget_deployments`). Only for an entry this broker recorded (`RECORD_NOT_BOUND` without a binding, `NOT_DEPLOYED` without the entry; a revoked or stale binding is accepted, so cleanup works after a delete or an owner edit), and only by its sole claimant (`ENV_NAME_TAKEN` while another record, revoked or not, also claims it: an `env.push` with `replace_existing` resolves that). A plain or ambiguous Vercel entry under the name is not deleted (the step fails, the claim stays). Text: `REMOVE env var ENV (record REC's value) from Vercel prj_… (team_…) [PRODUCTION]; deployments built with it keep it until redeployed; the record stays in the vault`. Reads no value | `variables:{ENV: "removed"}`, `forgotten_deployments` |
| `vercel.redeploy` | `team_id`, `project_id`, `target`, `git_branch?` (preview only), `deployment?` (source ID; default current, of that branch if named), `health_path?` | Redeploy, wait until ready, check health (at least 3 checks over at least 30 s, as in `lifecycle.HealthEvidence`). Production: a [production release](#production-releases); an explicit `deployment` must be the one serving production now (`PRODUCTION_SOURCE_NOT_CURRENT`, checked after approval before any change; the text says `(must be dpl_…)`) | `deployment_id`, health (production: release fields) |
| `stripe.webhook.create` | `url` (HTTPS), `events:[...]`, `record` | Create an endpoint (the account's default API version), record its provenance (`provider-stripe-endpoint`, with the `api_version` read back, best effort) and store `whsec_…` in the record, bound to the endpoint with no destination | `endpoint_id`, record revision |
| `stripe.webhook.rotate` | `endpoint_id`, `record`, `previous_record`, `vercel:[…]` (as for `neon.rotate`), `health_path` | Create a new endpoint with the URL and events recorded in the endpoint's provenance; the live endpoint must still match them, be `enabled`, and have the recorded `api_version` if one was recorded (`STRIPE_ENDPOINT_DRIFT` before the prompt and again after approval; a missing endpoint, provenance without events, or a version changed after approval is drift). The copy is created with the live endpoint's `api_version`, which its provenance records. Move the current secret to `previous_record`, store the new one in `record`, push both to every scope, redeploy and check each, then delete the old endpoint. Refused (`STRIPE_ORPHAN_ENDPOINT`) while `previous_record` holds the secret of another endpoint that still exists. The production scope runs a [production release](#production-releases) | new `endpoint_id`, revisions, `redeployed` (production: release fields) |
| `stripe.webhook.delete` | `endpoint_id` | Delete an endpoint this broker created (`NOT_CREATED_BY_BROKER` otherwise; the text gives its URL and says `created by this broker`) and revoke its bindings (its whole lineage, if it is the current endpoint). Refused (`RESOURCE_STILL_DEPLOYED`) while a live `stripe.webhook_secret` binding of this endpoint lists a `deployed_to` entry. A previous secret still deployed does not block it (the orphan cleanup below deletes such endpoints) | `deleted`, `revoked_bindings` |
| `binding.allow` | `records:[record...]` (1 to 16), `team_id`, `project_id` | Allow bound records to be deployed to a Vercel project (every target). The only way a destination is added | `team_id`, `project_id`, `records:{name: revision}` |

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

Role escalation guards (all read-only, before the prompt):

- **Owner.** `owner_role` must be the database's actual owner (Neon API
  `databases/{db}.owner_name`), and may not be one of the rotation roles
  (`NEON_OWNER_ROLE_MISMATCH`). `neon.rotate` re-checks it after approval.
- **Existing roles.** Preparation makes each rotation role a member of the
  schema-owner group. A role that already exists could be granted that
  power without the owner noticing, so `neon.roles.prepare` refuses one
  (`NEON_ROLE_EXISTS`) unless it is one this broker created (recorded in the
  project's provenance) or the call sets `adopt_existing_roles: true`, in
  which case the approval text names each: `EXISTING role X will act as the
  schema owner`. The role state is checked again as the first step after
  approval. Roles prepared on a project this broker did not create are not
  recorded as broker-created, so a re-run needs `adopt_existing_roles`.
- **Active role.** The binding stores `roles` and `active_role`; the
  rotation order is derived from it, never taken from the agent. A `roles`
  param, if given, must match (`NEON_ACTIVE_ROLE_MISMATCH`), as must the
  pooled and direct bindings. A binding written before these fields existed
  has no roles and is refused the same way.
- **Retry.** Before the reset, the bindings record `pending_role: next`
  and `pending_host`, the SHA-256 of the current URI's host
  (`vault.mark_pending`). If the operation stops between the reset and the
  binding save (provider failure, vault failure, broker restart), the next
  `neon.rotate` sees the pending role and resets the same role again
  instead of refusing a mismatch: the old role is still the one in use. A
  pending binding is accepted with its record at the bound revision or one
  ahead (the pooled URI stored, the direct one not). The vault keeps no
  history, so one ahead must be the rotation's own store: its URI's user is
  the pending role and its host hashes to `pending_host`; anything else (an
  owner edit) fails `RECORD_NOT_BOUND` at `vault.mark_pending`, before any
  reset. The binding save clears both fields.
- **Resume.** The bindings switch to `active_role: next`, `retiring_role:
  old` as soon as the new URIs are stored. If the operation stops before
  the old role is invalidated, the next `neon.rotate` resumes it instead of
  resetting a role still in use: it resets nothing, pushes and redeploys the
  stored URIs, invalidates `retiring_role` and clears it
  (`vault.finish_rotation`; result `resumed: true`). The approval text says
  `COMPLETE Neon <project>/<branch>/<db> rotation to role X`.
- **Group members.** An existing `envbank_app_owner` group with a member
  other than the owner role and the two rotation roles is refused by the
  Neon adapter (`GROUP_ROLE_CONFLICT`; the action fails `PROVIDER_FAILED`
  at the preparation step, before any grant): that member would inherit
  the schema.

### Record bindings

Gaps closed: a push could send any non-`CONTROL_` record to any Vercel
project (whose code the agent may control), and a rotation could overwrite
any record it named.

- **Store.** When an action creates a record, the broker stores a binding as
  an encrypted vault object (kind `provider-binding`, keyed by record name;
  not a record, so `names`, `run` and `request` never reach it): `{v,
  record, provider, kind, resource, record_revision, allowed_destinations,
  deployed_to?, roles?, active_role?, retiring_role?, pending_role?,
  pending_host?, revoked}` (`pending_host` set exactly when `pending_role`
  is; Neon only). The schema
  stays `v: 1`; the new fields are optional. Kinds: `neon.pooled`, `neon.direct` (resource `project_id`,
  `branch_id`), `stripe.webhook_secret`, `stripe.webhook_secret_previous`
  (resource `endpoint_id`, `lineage` = the first endpoint of the rotation
  chain). Only the provider service writes bindings, inside an approved
  operation, with optimistic object revisions.
- **Live.** A binding counts only if it exists, is not revoked, and
  `record_revision` is the record's current revision. A value written by
  anything else (owner entry, import) under a bound name is not bound.
- **Pushes.** `vercel.env.push`, `neon.rotate` and `stripe.webhook.rotate`
  push a record only if it is bound and `(team_id, project_id)` is in its
  `allowed_destinations`; otherwise `RECORD_NOT_BOUND` or
  `DESTINATION_NOT_ALLOWED`, before any prompt. Each operation re-checks
  as its first step and pushes exactly the bound revision.
- **Destinations.** Only `binding.allow` adds one (at most 16 per binding,
  `BINDING_LIMIT`). Its Touch ID text: `ALLOW records A, B to be deployed to
  Vercel project prj_… (team_…), every target including PRODUCTION; code
  deployed there can read their values. Project created by this broker`
  (or `NOT created by this broker`). A push can never widen a binding.
- **Deployed to.** `deployed_to` (at most 32 entries, `BINDING_LIMIT`, over
  at most 3 distinct scopes, `ROTATION_SCOPE_LIMIT`, so one rotation can
  always cover them) lists every `{team_id, project_id, target, git_branch?,
  env}` this broker pushed the record to. `vercel.env.push` and the rotations record an entry
  (`vault.record_deployments`, or with the rotation's binding save) before
  the write, so after a failed push it can over-approximate, never
  under-approximate. Every entry must be an allowed destination.
  `vercel.project.delete` drops that project's entries and
  `vercel.env.remove` one entry (`vault.forget_deployments`).
- **One owner per env var.** One `(scope, env name)` should be listed by
  one binding, revoked or not: the record whose value the broker last wrote
  there. A push over another record's env var needs `replace_existing`
  (`ENV_NAME_TAKEN` otherwise) and drops every other claimant's entry after
  the write, so a replaced record's rotation never rewrites it. Because the
  entry is recorded before the write and released after it, a failed push
  or release can leave two claimants; then rotations and `vercel.env.remove`
  of that env var are refused `ENV_NAME_TAKEN` until an `env.push` with
  `replace_existing` takes it over. A rotation that would write there is
  refused `ENV_NAME_TAKEN`.
- **Unclaimed env vars.** An env var Vercel holds in a scope that no
  binding claims was set by someone else. A push or rotation that would
  newly write that name checks presence (names only, never values) before
  the prompt and again just before the write; a push needs
  `replace_existing` and says `REPLACES a value NOT written by this broker
  in ENV`, a rotation is refused `ENV_NAME_TAKEN`. An all-branches preview
  entry does not count for a branch scope: Vercel keeps it and prefers the
  branch entry.
- **Rotation scope.** A rotation invalidates the old credential at the end,
  so it must first rewrite every scope that uses it. Its `vercel` list must
  cover every `deployed_to` entry of the records it rotates
  (`ROTATION_SCOPE_INCOMPLETE` otherwise, before the prompt); it may name
  more (a first push). Each scope gets the env names the record was
  deployed under there (its own name where it was not deployed yet); two
  records under one env name is `BINDING_MISMATCH`. Scopes run in order,
  production last, and the approval text lists every one.
- **Unscoped previews.** A preview scope without `git_branch` (an
  all-branches env var) is used by every preview deployment, but a
  rotation redeploys and checks only one, so invalidating the old
  credential would break the others. A rotation naming one, or of a record
  whose `deployed_to` lists one, is refused `ROTATION_UNSCOPED_PREVIEW`,
  and so is a push of a rotatable record to one.
  Workaround: `vercel.env.remove` the all-branches entry, `vercel.env.push`
  to each branch that needs it, then rotate with those branch scopes.
- **Provenance.** `vercel.project.create`, `neon.project.create` and
  `stripe.webhook.create` store a `provider-vercel-project`,
  `provider-neon-project` (name, branch, database, owner role, created
  roles) or `provider-stripe-endpoint` (URL, lineage, events) object. It changes the
  `binding.allow` wording, lets the delete actions run, and tells
  `neon.roles.prepare` which roles the broker created. Rotated Stripe
  endpoints get one too.
- **Rotations.** `neon.rotate` needs both records bound to that exact
  project and branch with kinds `neon.pooled`/`neon.direct`;
  `stripe.webhook.rotate` needs `record` bound as `stripe.webhook_secret`
  to `endpoint_id`, and `previous_record` either absent (then created) or
  bound as `stripe.webhook_secret_previous` of the same lineage. Otherwise
  `RECORD_NOT_BOUND` or `BINDING_MISMATCH`, before any prompt. After a
  rotation the bindings pin the new revisions; Stripe's moves to the new
  endpoint (same lineage) and `previous_record` inherits the record's
  destinations. Create actions still refuse existing records.
- **Deletes.** All three deletes need provenance (`NOT_CREATED_BY_BROKER`
  before the prompt otherwise), and their text names the resource (project
  name, endpoint URL) and says `created by this broker`.
  `neon.project.delete` and `stripe.webhook.delete` mark the related
  bindings revoked after the provider delete succeeds, and refuse while the
  credentials are still deployed (`RESOURCE_STILL_DEPLOYED`). They never
  delete records. There is no record-delete route for agents or provider
  actions; the owner removes records in the EnvBank app.
- **Concurrent writes.** Every vault store names the revision it expects
  (`StoreSecretAt`): 0 for a create and a new `previous_record`, the bound
  revision for a rotation. A record changed meanwhile (owner edit, another
  broker) is not overwritten; the operation fails `RECORD_CHANGED` at that
  step (nothing pushed, old credential kept).
- **Stripe orphans.** If a Stripe rotation stopped after creating its new
  endpoint, the old endpoint still exists and `previous_record` holds its
  secret, which deployments may still verify with. A re-run would overwrite
  it, so it is refused (`STRIPE_ORPHAN_ENDPOINT`) after a read-only GET of
  that endpoint, and the refusal's `result.orphan_endpoint_id` names it.
  Cleanup: redeploy so nothing uses the old secret, `stripe.webhook.delete`
  the orphan (its `previous_record` binding is revoked), then rotate again;
  a revoked previous binding of the same lineage, whose revision is
  unchanged, may be overwritten.
- **Unbound records** (owner-entered secrets such as Clerk keys) cannot be
  pushed or rotated by provider actions in v1. That includes the URIs of a
  Neon project EnvBank did not create: `neon.roles.prepare` works on it,
  but `neon.rotate` needs bound records. Future path: an owner-only
  `binding.adopt` for an existing record, with stronger wording ("EnvBank
  did not create this value") and the owner's own Touch ID, never one the
  agent can request alone.

### Approval text

The broker builds the Touch ID reason from the validated plan and vault
state only. Example (realistic IDs):

    perform a provider action: ROTATE Neon polished-forest-12345678/
    br-polished-forest-12345678/neondb: reset role app_b into DATABASE_URL,
    DATABASE_URL_UNPOOLED; push, redeploy, health /api/health on Vercel
    team_…: prj_… preview@main+PRODUCTION; PRODUCTION last: STAGED, PROMOTE,
    auto ROLL BACK on failure; then INVALIDATE old role app_a, for claude
    agent session 3f2a9c1e in workspace /Users/…/myapp; [agent label: "…"]

Scopes are grouped by team, then project: `Vercel team_a: prj_x
preview@main+PRODUCTION, prj_y preview@feat and team_b: prj_z PRODUCTION`
(a scope with a named source deployment adds ` from dpl_…`). Other plans:

- Stripe rotation: `ROTATE Stripe webhook we_… (<url>, N events) to a copy:
  new secret into REC, old kept in PREV; push, … ; then DELETE the old one`.
- Production redeploy: `REDEPLOY Vercel prj_… (team_…) PRODUCTION from the
  deployment serving production now [(must be dpl_…)] as STAGED, check
  health at P; then PROMOTE, verify production serves it and recheck, auto
  ROLL BACK on failure`.

**Budget.** The prompt holds 600 bytes. The authoritative part,
`perform a provider action: <plan>, for <session>`, may use at most 570
(`authz.MaxProviderPlanBytes`): the rest is reserved for the label, which
gets whatever room is left (up to 80 characters) and is clipped with `...`,
never less than 8 characters. So the label never makes an approval fail. A
plan that does not fit alone is refused `PLAN_TOO_LONG` before the prompt,
never clipped. `TestRotationApprovalBudget` checks, with realistic IDs and
a 40-character workspace: Neon rotations of 1 to 3 scopes fit, in one
project, two projects or two teams; Stripe rotations (which also name the
URL) fit up to 3 scopes in one project and 2 scopes over two projects, and
the wider Stripe layouts are refused `PLAN_TOO_LONG`. Longer URLs, branch
names or workspaces shrink this; the remedy is fewer scopes
(`vercel.env.remove`).

### Production releases

Vercel creates a production redeploy STAGED (`autoAssignCustomDomains:
false`): production traffic stays on the old deployment, which keeps using
the old credential, until the new one is promoted. So `vercel.redeploy`,
`neon.rotate` and `stripe.webhook.rotate` with a production target run:

1. `vercel.current_deployment`: read the deployment serving production (the
   rollback target, `previous_deployment_id`), before anything changes. It
   must be alias-proven (every verified production domain aliased to one
   READY, PROMOTED deployment, no alias job running), or the operation fails
   with no side effects.
2. Rotations: the new credential is created and stored, then pushed to
   production env vars (`vercel.env_push`).
3. `vercel.redeploy` (staged), `vercel.wait_ready`, `health` on the staged
   deployment's URL.
4. `vercel.promote`: production must still be on `previous_deployment_id`
   (else `PRODUCTION_DEPLOYMENT_DRIFT`), then the promote request.
5. `vercel.verify_production`: production alias reads (every 5 s, at most 60)
   until it is proven to serve the new deployment (`PRODUCTION_NOT_SERVING`
   otherwise; a third deployment is `PRODUCTION_DEPLOYMENT_DRIFT`).
6. `health.production`: the full health policy again, on the promoted
   deployment's URL.
7. `vercel.confirm_production`: one more alias proof.
8. Only then is the old credential invalidated (`neon.invalidate_old_role`)
   or the old endpoint deleted (`stripe.delete_old_endpoint`).

A failure before step 4's request leaves production untouched. A failure in
steps 4 to 7 runs `vercel.rollback` (the operation still fails with the
original step and code): it reads production, asks Vercel to roll back to
`previous_deployment_id` if the new deployment serves it (up to 3 requests),
and reads until production is proven back. The old credential is never
invalidated, because the restored deployment still uses it. A failure of
step 8 itself does not roll back: production serves the new deployment with
the new credential.

Release result fields (value-free): `previous_deployment_id`, `promoted`
(the promote request was accepted), `production_verified`,
`production_health {checks, window_s}` (`health` is the staged checks),
`rolled_back` (a rollback was sent and production proven back), and
`rollback`, set only after a failure at or after the promote:
`rolled_back`, `not_needed` (production proven still on the previous
deployment), `failed` (not proven, for example the operation was cancelled
or the grant ended; both credentials stay valid) or `drift` (production
serves a deployment the operation neither read nor created; left alone).

Caveats:

- **Env vars stay updated.** Variables pushed to production before a failure
  (or a rollback) keep their new values: a Vercel rollback never restores
  variable values (docs/vercel-integration-gaps.md). They hold credentials
  that remain valid (the new Neon role, the new webhook secret), and the vault
  keeps the new values; the restored deployment runs with the old ones.
  Restoring the vault's previous values is not automated: the bindings
  already follow the new revisions, so the owner reruns the action (a Neon
  rotation can be repeated as is; a failed Stripe rotation leaves the new
  endpoint, whose ID is in the result, beside the old one).
- **Health host.** Health checks go only to the deployment's own
  `*.vercel.app` URL, before and after the promote; production custom domains
  are never contacted. Serving is proven through Vercel's alias records
  instead. Standard Deployment Protection covers that URL, so it fails the
  staged check with `HEALTH_PROTECTED` before the promote.
- **Asynchronous promote.** A promote that Vercel accepts after the rollback
  step proved production on the previous deployment could still land later;
  the old credential is still valid then too.

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
  side-effect-free vault prechecks (`CONTROL_CREDENTIAL_MISSING`,
  `RECORD_EXISTS`, `UNKNOWN_SECRET`, `RECORD_NOT_BOUND`,
  `DESTINATION_NOT_ALLOWED`, `BINDING_MISMATCH`, `BINDING_LIMIT`,
  `ROTATION_SCOPE_INCOMPLETE`, `ROTATION_SCOPE_LIMIT`,
  `ROTATION_UNSCOPED_PREVIEW`, `ROTATION_INCOMPLETE`, `ENV_NAME_TAKEN`,
  `NOT_DEPLOYED`,
  `RESOURCE_STILL_DEPLOYED`, `NEON_ACTIVE_ROLE_MISMATCH`,
  `NEON_OWNER_ROLE_MISMATCH`, `NOT_CREATED_BY_BROKER`), then a run slot
  (`BROKER_BUSY`), then live prechecks, and only then Touch ID. The
  resource lock (`RESOURCE_BUSY`) is taken just before the vault prechecks.
  A plan whose text does not fit the prompt with the label's minimum room
  is refused (`PLAN_TOO_LONG`), never clipped. A push also checks, through
  `provideraction.WithPlanFit` (set by authz for that session), that the
  shortest rotation of its records (health path `/`) would fit.
- **Live prechecks.** `neon.roles.prepare` (owner, existing roles:
  `NEON_OWNER_ROLE_MISMATCH`, `NEON_ROLE_EXISTS`), `neon.rotate` (owner) and
  `stripe.webhook.rotate` (endpoint drift: `STRIPE_ENDPOINT_DRIFT`, then
  orphan endpoint: `STRIPE_ORPHAN_ENDPOINT`) read
  the provider before the prompt; `vercel.env.push` and both rotations
  check that env names they newly write are unset in Vercel
  (`VercelPort.EnvPresent`; `ENV_NAME_TAKEN`). They open the ports with the control
  credentials but without operation authority, so every mutation is
  refused; they are bounded to 30 s, and the ports are closed and the
  credentials wiped before the prompt. A provider failure there is
  `PROVIDER_FAILED`. Other checks that need a provider call (roles
  prepared, Stripe test-mode key) run after approval as the first,
  read-only step and fail the operation; the role and owner checks are
  repeated there.
- **Refusal result.** A refusal may carry a value-free `result`; only
  `STRIPE_ORPHAN_ENDPOINT` does (`{orphan_endpoint_id}`).
- **Approval text.** `perform a provider action: <plan>, for <agent kind>
  agent session <fingerprint> in workspace <ws>; [agent label: "<label>"]`.
  The plan is built from validated params and vault state only. The label
  is agent-influenced, so it comes last, inside the delimiter, rendered
  ASCII-only: cleaned to one line, every non-printable-ASCII rune and `"`,
  `[`, `]` become `?`, and it is cut with `...` to 80 characters or the
  room the plan leaves (see the budget under
  [Approval text](#approval-text)); a label never causes a refusal. The
  agent's `reason` is shown only in the broker terminal.
- **Params.** A `production` target needs `"production": true` beside it;
  `production: true` with `preview` is refused. `git_branch` is preview only.
  Health paths are `/[A-Za-z0-9._~/-]*` without `..` or `//`
  (`vercel.redeploy` defaults to `/`). Webhook URLs are `https`, a DNS host
  (no IP, port, user info or fragment), at most 256 bytes, plain URL
  characters. Up to 16 events and 16 variables (per scope). Rotation
  `vercel` is a list of 1 to 3 distinct scopes with at most one
  production; each takes `production`, `git_branch` and `deployment` as
  a push or redeploy does, and a preview scope must name `git_branch`.
- **Env var names.** Composite actions push each record under the env
  names in its `deployed_to` for that scope, or under its own name
  (`DATABASE_URL`, `STRIPE_WEBHOOK_SECRET_PREVIOUS`, …) where it was not
  deployed yet.
- **Records.** Create actions refuse an existing record (`RECORD_EXISTS`).
  Rotations overwrite only bound records (see
  [Record bindings](#record-bindings)); the approval text names them. Each
  push reads the exact revision this operation stored or checked.
- **Binding steps.** `vault.check_bindings` (first step after `control`),
  `vault.save_bindings`, `vault.allow_destination`, `vault.revoke_bindings`,
  `vault.save_provenance`, `vault.record_deployments` (push),
  `vault.mark_pending` (Neon: before the reset), `vault.finish_rotation`
  (Neon: clears `retiring_role`, last), `vault.forget_deployments` (Vercel
  project delete, env remove), `vault.release_env_owner` (push with
  `replace_existing`). Vercel: `vercel.env_remove`. Neon role checks:
  `neon.check_role_state`. A failed binding save fails the operation before
  any push. A Neon rotation is then retried or resumed from its bindings
  (`pending_role`, `retiring_role`). A create whose binding save failed
  leaves an unbound record: `neon.project.delete` cleans up the project,
  and the create is repeated under new record names (or after the owner
  removes the records in the app). There is no record-delete route.
- **Stripe rotation.** The current secret is copied to `previous_record`
  before the new endpoint is created, so the vault never loses the secret in
  use. If the operation fails after creating the endpoint, the new endpoint
  stays (its ID is in the result) and the old one is not deleted; see
  [Stripe orphans](#record-bindings). If a create fails after Stripe made the
  endpoint, its provenance is still saved (best effort), so
  `stripe.webhook.delete` can remove it.
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
- **Resource locks.** Before its record prechecks, an action locks what it
  changes: the Neon project, the Vercel project (push, redeploy, delete,
  rotations), the Stripe lineage and endpoint, and every record it writes or
  re-binds (a push: each record it pushes and each record whose env var it
  replaces; an env remove: its record). A push and an env remove also lock
  each record's provider resource (its Neon project, or its Stripe endpoint
  and lineage), so neither interleaves with that resource's delete. A second action needing any of them
  is refused `RESOURCE_BUSY`
  before its prompt, while the first is waiting for approval or running. The
  lock ends with the operation (or a declined prompt).
- **Adapters seam.** `cmd/envbank/agent.go` `providerActionFactory` returns
  nil unless the broker runs with `--provider-actions` (and optional
  `--neon-org-id org-…`); then it is `internal/provideraction/live`. The
  ports are `NeonPort`, `VercelPort` and `StripePort` in
  `internal/provideraction/ports.go`; each is an `io.Closer`, closed when
  the operation ends (the adapters wipe their credential copies) before the
  broker wipes its buffer.
- **Live factory.** Fixed production endpoints; `live.New` takes no endpoint,
  client or transport. The loopback overrides the end-to-end test uses are an
  unexported field set only from `live`'s `_test.go` files (never compiled
  into the binary), and the Neon SQL connector hook refuses outside a test
  binary (`testing.Testing`). Mutations need the running operation's
  authority (`provideraction.OperationAuthority`): Vercel checks it through
  `WithMutationAuthorization` immediately before each mutating request, as
  the Vercel workflow does with its policy check; the Neon and Stripe ports
  check it before each mutation.
- **Vercel mapping.** Env pushes use the adapter's exact-scope sensitive
  `Write` (value read only inside `SecretSource.WithSecret`). `EnvPresent`
  uses the adapter's `Present`: a names-only listing (`decrypt=false`)
  where any entry in or overlapping the exact scope, including plain and
  ambiguous ones, counts as present. "Current
  deployment" is the production alias target for production, and the newest
  READY preview deployment of the project for preview, filtered to
  `git_branch` when the scope names one; the port also checks each
  returned deployment's branch itself and fails `vercel.current_deployment`
  if the list was not filtered. Redeploys are tagged with a random
  operation ID; `WaitReady` returns `https://<deployment>.vercel.app`.
- **Production mapping.** `Promote` and `Rollback` map to the adapter's
  `Promote`/`Rollback` in the exact production scope, under
  `WithMutationAuthorization` as above; the adapter re-checks project
  ownership, an idle alias job, and READY+STAGED (promote) or a prior
  PROMOTED deployment that is not current (rollback). The port promotes only
  a deployment it created and rolls back only to one its alias-proven
  `CurrentDeployment` returned. See [Production releases](#production-releases).
- **Health requests.** One HTTPS GET to `<deployment URL><health_path>`: only
  a URL this operation's `WaitReady` returned, on a single-label
  `*.vercel.app` host (production custom domains are never checked; serving
  is proven through the alias records); no redirects followed; no credentials, cookies or
  protection-bypass headers; at most 4 KiB of body read. 2xx is healthy. A
  `401` (Vercel deployment protection) fails the step with
  `HEALTH_PROTECTED` and is never bypassed: disable protection on the
  throwaway project, or use a path it serves unprotected.
- **Stripe mapping.** Webhook create uses the adapter's `Create` with
  `url`/`enabled_events`, an optional validated `api_version` and a random
  idempotency key; the endpoint is read back with `Endpoint` (ID, URL,
  events, `status` (`enabled`/`disabled`) and `api_version` (null is the
  account default); a 404 is "not found") and
  deleted with `Revoke`. Live-mode keys are refused by the service, the
  factory and the adapter. `stripe.New` accepts only
  `https://api.stripe.com` or an `http(s)` literal loopback IP (tests); any
  other base, including `localhost`, is refused.
- **Memory hygiene.** Prechecks and binding checks read record revisions
  only (`Vault.Revision`: the record is found by its keyed ID, nothing is
  decrypted), so they trust the sync service's revision metadata; the push
  that follows authenticates the value by decrypting exactly that revision.
  A value read (`Latest`, `ReadSecret`) decrypts that one record into a
  byte buffer that is wiped after the callback. Limits: storing a secret
  (`StoreSecret`) and the names/values paths still decrypt every record
  into Go strings, which cannot be wiped; values pass through Go's HTTP
  and JSON stacks, which copy them. Wiping narrows exposure; it does not
  guarantee a value leaves no copy in process memory.
- **Routes.** The development socket refuses `provider_action` and
  `provider_status` (`NOT_AUTHORIZED`); MCP has no provider tools.

## Properties

1. **Values.** No value appears in a response, status, error, log, plan or
   approval text. Provider errors are mapped to fixed codes
   (`provider.SanitizeError`).
2. **Endpoints.** Provider calls go only to fixed HTTPS endpoints:
   `api.vercel.com`, `console.neon.tech`, `api.stripe.com` (and health checks
   to the deployment's `*.vercel.app` URL). The Stripe adapter refuses any
   other base itself. The tests use loopback
   overrides, which are not reachable from agent input, flags or the
   production binary.
3. **Ordering.** New values are stored durably before any destination is
   written. Old credentials are revoked only after health checks pass (for
   production: after production is proven to serve the new deployment and
   it passed health there). If anything fails, the old credential stays valid
   and the operation ends `failed` with a step code; a production failure at
   or after the promote rolls production back. Neon's old role is reset only
   after every scope the records were deployed to was rewritten, redeployed
   and passed health.
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
  holding the new value. The owner reruns the action (a Neon rotation
  resumes from its binding; a Stripe one hits the orphan refusal first).
- Scopes the broker did not push to. `deployed_to` knows only this
  broker's pushes; a value copied elsewhere by hand is not tracked.
- Interrupted creates and Stripe rotations are not resumable the way a
  Neon rotation is. `pending_role` covers only `neon.rotate`; a
  `neon.project.create` or Stripe create/rotate that stops between the
  provider call and the vault write leaves a provider resource (its ID in
  the partial result, and for Stripe a best-effort provenance) to delete.
- `PRODUCTION_SOURCE_NOT_CURRENT` is checked after approval (at
  `vercel.current_deployment`, before any change), not before the prompt.
