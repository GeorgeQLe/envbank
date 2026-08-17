# Production deployment

> Migration status: Cloudflare Workers is the production target. The Docker
> runbook below is retained only for the read-only rollback window and must not
> be used for a new deployment. Remove it, the image publication, and `serve`
> only after the migration validation, seven clean days, and restore drill in
> [the Cloudflare migration runbook](cloudflare-migration.md).

The legacy baseline was one Docker host, one EnvBank container, one local
Docker volume, and one TLS reverse proxy on the same host.
The proxy must be reachable only through an authenticated private network such
as a device-authenticated VPN. EnvBank and its port must never be exposed
directly to the public Internet.

The independent cryptographic review and remediation re-review are complete.
That review is not proof of security and does not replace this runbook's
environment-specific controls. Multi-host storage, high availability,
application-level rate limiting, vault rekeying, and signed audit checkpoints
remain out of scope.

## Host and image preflight

Use a dedicated, patched host with full-disk encryption, Docker Engine 25 or
later, a host firewall, synchronized time, and a local filesystem for Docker's
data root. Do not put SQLite on NFS, SMB, a clustered volume, or a volume shared
by multiple hosts.

Choose an image by digest, not a mutable tag:

```sh
export ENVBANK_IMAGE='ghcr.io/georgeqle/envbank@sha256:REPLACE_WITH_DIGEST'
case "$ENVBANK_IMAGE" in
  *@sha256:*) ;;
  *) echo 'ENVBANK_IMAGE must be pinned by sha256 digest' >&2; exit 1 ;;
esac
printf '%s\n' "${ENVBANK_IMAGE##*@}" |
  grep -Eq '^sha256:[0-9a-f]{64}$' ||
  { echo 'ENVBANK_IMAGE digest must be 64 lowercase hex characters' >&2; exit 1; }
docker image pull "$ENVBANK_IMAGE"
docker image inspect "$ENVBANK_IMAGE" --format '{{index .RepoDigests 0}}'
```

Record the exact digest, source revision, operator, host, and deployment time.
Verify the digest against the release's trusted publication channel before
starting it. Confirm that TCP 7337 is not allowed by the host or cloud firewall
and that only authenticated private-network clients can reach the proxy.

Release builders must use Go 1.25.13 or later. The repository Dockerfile pins
the official `golang:1.25.13-alpine` multi-platform image by digest. Before
publishing an image, run `go mod verify`, the complete test suite, and
`govulncheck ./...` using a separately installed current `govulncheck`; do not
add the scanner to the application module dependencies.

## Start the service

The image runs as numeric UID/GID `65532`, contains no shell, and initializes
`/data` for that identity. Create one named local volume and one container:

```sh
docker volume create envbank-data
docker run -d \
  --name envbank \
  --user 65532:65532 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 100 \
  --cpus 1 \
  --memory 256m \
  --restart unless-stopped \
  --mount type=volume,source=envbank-data,target=/data \
  --publish 127.0.0.1:7337:7337 \
  "$ENVBANK_IMAGE"
```

Do not add environment variables containing secrets. The sync service has no
server-side vault key. Do not bind the published port to `0.0.0.0`, `::`, a
LAN address, or a public address. Do not add extra capabilities or mount the
Docker socket, host directories, device configs, passphrases, recovery
artifacts, or TLS private keys into this container.

Verify the effective settings and health:

```sh
docker inspect envbank --format \
  'user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{json .HostConfig.CapDrop}} security={{json .HostConfig.SecurityOpt}} pids={{.HostConfig.PidsLimit}} memory={{.HostConfig.Memory}} restart={{.HostConfig.RestartPolicy.Name}} ports={{json .HostConfig.PortBindings}}'
curl --fail --silent --show-error http://127.0.0.1:7337/healthz
docker logs --since 5m envbank
```

Require UID/GID `65532`, `readonly=true`, `["ALL"]`, no-new-privileges, the
configured limits, `unless-stopped`, and a `127.0.0.1` port binding. The health
response must be `{"status":"ok"}`. On the host, inspect Docker's volume data
as an administrator and require the database to be owned by the container
identity and have mode `0600`; do not loosen it to make backup tooling work.

## TLS and private-network proxy

Terminate TLS at a separately managed reverse proxy on the same host. The
private network must authenticate devices before they can reach the proxy;
enforce that with the VPN policy and host firewall, not a source header supplied
by the client. Use a private DNS name whose certificate is trusted by every
EnvBank client. The proxy must:

- allow TLS 1.2 and 1.3 only, with a currently maintained cipher policy;
- send traffic only to `127.0.0.1:7337`;
- allow at most 16 KiB of request headers and 1 MiB request bodies;
- use conservative connect, header, body, and idle timeouts;
- rate-limit `POST /v1/vaults`, public enrollment-request routes, and public
  invitation-creation routes more
  strictly than authenticated routes;
- disable request and response buffering to disk, response caching, and
  transformed error pages;
- preserve the method, path, and query exactly because they are signed;
- never log authorization or EnvBank authentication headers, request or
  response bodies, query strings, vault IDs, device IDs, record IDs, or
  vault-bearing paths.

This NGINX example belongs in the `http` context except for the `server` block.
Its access log deliberately contains no URI or query:

```nginx
log_format envbank_safe
  '$time_iso8601 status=$status bytes=$body_bytes_sent '
  'request_time=$request_time connection=$connection';
map $request_uri $envbank_public_key {
  default "";
  "~^/v1/vaults(?:\?.*)?$" $binary_remote_addr;
  "~^/v1/vaults/[^/?]+/enrollments(?:\?.*)?$" $binary_remote_addr;
  "~^/v1/vaults/[^/?]+/invitations(?:\?.*)?$" $binary_remote_addr;
}
limit_req_zone $envbank_public_key zone=envbank_public:10m rate=5r/m;

server {
  listen 443 ssl;
  server_name envbank.private.example;

  ssl_certificate /etc/nginx/tls/envbank.crt;
  ssl_certificate_key /etc/nginx/tls/envbank.key;
  ssl_protocols TLSv1.2 TLSv1.3;

  access_log /var/log/nginx/envbank-access.log envbank_safe;
  # NGINX error-log records can embed the request URI and cannot use log_format.
  error_log /dev/null crit;
  server_tokens off;

  client_max_body_size 1m;
  client_header_buffer_size 8k;
  large_client_header_buffers 2 8k;
  client_header_timeout 10s;
  client_body_timeout 15s;
  keepalive_timeout 60s;

  location / {
    limit_req zone=envbank_public burst=5 nodelay;
    proxy_pass http://127.0.0.1:7337;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_pass_request_headers on;
    proxy_connect_timeout 5s;
    proxy_send_timeout 15s;
    proxy_read_timeout 15s;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_cache off;
    proxy_intercept_errors off;
  }
}
```

An empty `envbank_public_key` is not accounted by NGINX, so only the three mapped
public route shapes consume this limit. Validate the actual configuration with `nginx -t`.
Test that private-network authentication is required, TLS 1.1 is rejected,
oversized bodies/headers are rejected, the three public routes are throttled,
signed requests still work with queries, and logs contain none of the excluded
fields. Treat proxy logs as sensitive operational data and apply access,
retention, and deletion controls.

## Backup and recovery

Follow the [backup and restore runbook](backup-and-restore.md), including its
online SQLite backup API, integrity checks, digest recording, disposable
recovery drill, quarantine, and application-level restore verification. Backup
the named volume through a SQLite-aware process; never copy only a live
`envbank.db` file or omit its WAL state.

Maintain a separately stored [encrypted recovery artifact](recovery.md) and a
separate strong recovery passphrase. Keep database backups, device configs,
passphrases, and recovery artifacts in distinct encrypted locations with
least-privilege access. Periodically verify recovery artifacts offline and
perform both database and new-vault restoration drills. A database backup alone
cannot recover a vault after every approved device and recovery artifact is
lost.

## Upgrade and rollback

1. Record the current image digest and take and validate an online backup.
2. Read release notes and verify that the target supports the current database
   schema. Never bypass the schema-version check.
3. Pull and verify the new digest.
4. Stop the container and require a clean exit; EnvBank allows ten seconds for
   graceful HTTP shutdown.
5. Remove only the stopped container, then repeat the hardened `docker run`
   command with the new digest and the existing `envbank-data` volume.
6. Verify health, approved-device reads and writes, revocation state, access
   events, database mode `0600`, and persistence across one clean restart.

Keep the old digest and validated backup through the rollback window. If
verification fails, isolate the proxy, stop the new container, preserve logs,
and follow the backup runbook's rollback procedure. A migration may make an old
binary incompatible with the database, so rollback may require restoring the
pre-upgrade backup and will lose writes made after it.

## Monitoring and incident isolation

Monitor container state/restarts, loopback health, proxy TLS expiry, 4xx/5xx
rates, rate-limit rejections, disk and inode capacity, backup age, recovery
drill age, host clock, and database integrity. Alerts and dashboards must not
include request paths, queries, headers, bodies, vault/device/record IDs,
ciphertext, fingerprints, or secret material.

On suspected host, proxy, database, or image compromise:

1. Remove private-network access to the proxy while preserving the host and
   volume; do not expose a diagnostic port.
2. Stop EnvBank gracefully if doing so will not destroy volatile evidence.
3. Preserve image digests, sanitized proxy/container logs, database and WAL/SHM
   files, and timestamps in access-controlled evidence storage.
4. Assume the attacker learned service metadata and ciphertext. If an endpoint
   may also be compromised, assume it learned vault keys and decrypted values.
5. Restore onto a clean host from a validated point, verify device and event
   state, revoke affected devices, and rotate upstream credentials as needed.
6. Remember that revocation cannot recall keys already retained by a device;
   EnvBank does not yet provide vault rekeying.

## Production-readiness checklist

- [ ] Exact image digest and source revision verified and recorded
- [ ] Dedicated patched, encrypted single host with local Docker storage
- [ ] One non-root container and one protected local named volume
- [ ] Read-only root, all capabilities dropped, no-new-privileges, PID/CPU/RAM
      limits, restart policy, and loopback-only port verified
- [ ] Database ownership and `0600` mode verified
- [ ] Authenticated private network and host firewall tested
- [ ] TLS, proxy limits/timeouts, no-cache behavior, and public-route rate limits
      tested
- [ ] Logs tested for excluded headers, bodies, queries, identifiers, and paths
- [ ] Health, graceful stop, clean restart, and volume persistence verified
- [ ] Validated database backup plus encrypted recovery artifact stored
      separately
- [ ] Database recovery and new-vault recovery drills completed
- [ ] Upgrade rollback, monitoring, alerting, and incident isolation rehearsed
- [x] Deployment guidance prepared
- [x] Cryptographic review packet prepared
- [x] Independent cryptographic review completed and findings remediated

Do not deploy until every environment-specific unchecked item is complete.
