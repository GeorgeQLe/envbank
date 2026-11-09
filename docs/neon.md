# Neon credential lifecycle

Status (November 8, 2026): **adapter implemented and unit-tested against a
synthetic HTTP transport; not run against a real Neon project.** The field
names below follow Neon's published API reference; live acceptance against a
disposable project is required before any real rotation.

`internal/provider/neon` implements `lifecycle.CredentialAdapter` for two
credential types, both declared **automatic** in the manifest contract.

| Type | Create | Validate | Revoke |
| --- | --- | --- | --- |
| `role-password` | `POST .../roles/{role}/reset_password`, then poll every returned operation to `finished` | `GET .../roles/{role}` (limited: presence of the role, not of a particular password) | another `reset_password`, result discarded |
| `api-key` | `POST /api_keys` or `POST /organizations/{org}/api_keys` (optionally project-scoped) | list keys and match the id | `DELETE` the key (404 counts as revoked) |

The control credential (a Neon API key) is held in memory only and wiped on
`Close`. Identity is `GET /auth` → `account_id`, which is defined for personal,
organization and project-scoped keys.

## Role passwords have no grace period at Neon

Neon invalidates the old password as soon as the reset operation finishes,
and every reset **drops the open connections on the compute endpoint**. A
single-role rotation therefore leaves the application with an invalid
password until the deployment target redeploys with the new value. Alternating
**two equally privileged roles** removes that invalid-password window: the
role the application is using keeps its password until the new deployment is
healthy. It does not remove the connection drop; the application must
reconnect and retry transient connection errors, as it already must for Neon
compute suspend/resume.

1. The application currently uses role A.
2. Rotation calls `Create` for role **B**: B gets a fresh password, EnvBank
   stores it (or a full connection URI), the deployment target is updated and
   health-checked.
3. After the grace period, `Revoke` on the previous credential
   (`role:<project>/<branch>/A`) resets A's password and discards the result,
   so the retired value stops working. This reset also drops connections on
   the endpoint; the application, now on B, reconnects with its still-valid
   password.
4. The next rotation mints for A and retires B.

Roles created through the Neon API are `neon_superuser` members, so two
API-created roles have equal privileges. Roles created in SQL must be granted
equivalently by the owner before rotation is enabled.

Parameters for `role-password`:

| Parameter | Required | Meaning |
| --- | --- | --- |
| `project_id`, `branch_id`, `role_name` | yes | immutable scope; also the credential ID `role:<project>/<branch>/<role>` |
| `database_name` | no | when set, the stored value is `postgresql://role:password@host/db?sslmode=require&channel_binding=require` using the branch's single `read_write` endpoint host |
| `pooled` | no (`true`/`false`) | with `database_name`, use the `-pooler` host |

The URI is composed locally from `GET .../branches/{branch}/endpoints`, so
EnvBank never calls `connection_uri` or `reveal_password` and does not depend
on Neon's optional server-side password storage. A branch with zero or more
than one read-write endpoint is refused.

## API keys

Parameters: `key_name` (required, ≤64 bytes), `org_id` (optional), and
`project_id` (optional, requires `org_id`; produces an Editor-level key limited
to that project). Credential IDs are `api-key:<id>` or
`api-key:org:<org>:<id>`. Organization and project-scoped keys are only
listed and revoked through the organization endpoints.

## Ambiguity and retries

Neon has no idempotency header. The lifecycle idempotency key is still
required and is sent as `X-Request-ID` for correlation, but a lost response to
a mutation **cannot be recovered by retrying**: a repeated `reset_password` or
key creation mints another secret. The adapter therefore classifies:

- transport failure or any 5xx other than 503 on a mutation: `ambiguous`;
- 423 (resource locked by a running operation), 429 and 503: `safe`;
- a reset whose operation ends `failed`, `error` or `cancelled`, or does not
  finish within the poll budget (default 90 s): `ambiguous`, because the old
  password may already be gone;
- all GETs: `safe` on 423/429/5xx.

The lifecycle engine routes ambiguous failures to reconciliation rather than
retrying them. For a role password, reconciliation is simply another
`Create` for the same role once the owner-approved policy allows it.

## Not done

- Live acceptance on a disposable Neon project (role reset, endpoint lookup,
  operation polling, API key create/list/revoke).
- Wiring into a CLI/MCP rotation command and the Vercel deployment workflow
  (see the rotation design once it lands).
- Role-password `Validate` cannot prove which password the role accepts; a
  connection-level health check at the deployment target is the real
  verification.
