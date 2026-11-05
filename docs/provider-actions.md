# Provider actions (`envbank.provider-actions/v1`)

Status (November 5, 2026): **specification; implementation in progress; not
qualified.**

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

- **Reserved.** `CONTROL_*` records are never listed by `names`, injected by
  `run`, or granted by any scope other than `provider`.
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
| `neon.project.create` | `name`, `region_id?`, `pg_version?`, `records:{pooled, direct}` | Create a project. Store the pooled and direct connection URIs in the two records | `project_id`, `branch_id`, `role`, `database`, `records:{name: revision}` |
| `neon.project.delete` | `project_id` | Delete the project (throwaway cleanup) | `deleted` |
| `neon.rotate` | `project_id`, `branch_id`, `roles:[A, B]`, `database`, `records:{pooled, direct}`, `vercel:{team_id, project_id, target, deployment?}`, `health_path` | Zero-downtime rotation: reset the inactive role's password, store its URIs, push them to Vercel, redeploy, check health, then reset the previously active role (invalidating its old password) | active role, record revisions, `deployment_id` |
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

### Approval text

The broker builds the Touch ID reason from the validated plan only. Example:

    EnvBank: agent "<label>" (claude, 3f2a9c1e) wants to ROTATE Neon role
    app_b → active in project <id>, push DATABASE_URL, DATABASE_URL_UNPOOLED to
    Vercel prj_… preview, redeploy, then invalidate app_a.

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
