# EnvBank Cloudflare Worker

This package is the production sync runtime: one SQLite-backed Durable Object
per vault, fronted by Cloudflare Access. The hostname must require an Access
service token; EnvBank request signatures remain mandatory behind Access.

`wrangler.toml` contains only non-secret bindings. Deployments use Workers
versions and separate promotion; do not add plaintext secret files.

North American placement is requested through Smart Placement and account
configuration, but it is not a strict data-residency guarantee.
