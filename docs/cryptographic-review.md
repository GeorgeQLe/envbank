# Cryptographic review brief

This packet defines the material for an independent cryptographic and protocol
review of EnvBank. Its preparation is not completion of that review. Findings
must be remediated and re-reviewed before broader production use is
recommended.

## Immutable review revision

The repository owner must give the reviewer a full 40-character commit SHA over
a clean tree and a private disclosure channel. The reviewer should clone into a
new directory and run:

```sh
export REVIEW_REVISION='REPLACE_WITH_40_CHARACTER_COMMIT_SHA'
git rev-parse --verify "${REVIEW_REVISION}^{commit}"
git status --short
git switch --detach "$REVIEW_REVISION"
test "$(git rev-parse HEAD)" = "$REVIEW_REVISION"
git status --short
```

Both status checks must be empty. Review source and documentation only from
that detached revision. Record the Go and Node versions and reproduce:

```sh
export GOCACHE="$(mktemp -d)"
go version
node --version
go test ./...
go vet ./...
go test -race ./...
node --test extension/test/*.test.js
go build -trimpath -o /tmp/envbank-review ./cmd/envbank
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o /tmp/envbank-review-linux-amd64 ./cmd/envbank
make recovery-drill
```

Review links below are repository-relative so they resolve to the pinned
revision. Validate the packet before handoff:

```sh
git grep -nE '\\]\\([^):#]+(#[^)]+)?\\)' -- docs/cryptographic-review.md
for path in README.md docs/architecture.md docs/recovery.md \
  docs/backup-and-restore.md docs/production-deployment.md \
  internal/secure/secure.go internal/protocol/protocol.go \
  internal/client/local.go internal/client/records.go internal/client/api.go \
  internal/server/server.go internal/server/events.go \
  internal/recovery/artifact.go internal/nativehost/host.go \
  internal/browser/origin.go extension/background.js extension/content.js \
  extension/core.js; do
  git cat-file -e "${REVIEW_REVISION}:${path}"
done
```

## Assets, actors, and boundaries

Assets are secret names and values, the 256-bit vault key, Ed25519 and X25519
private keys, local and recovery passphrases, browser-origin policy, recovery
plaintext, upstream credentials after injection, authorization/revocation
state, replay state, and the integrity/availability of current ciphertext.

Actors are the vault owner, approved/pending/revoked devices, the sync-service
operator, private-network and proxy operators, browser extension/native host,
secret-consuming child processes and pages, backup/recovery operators, and
unauthenticated remote callers that can reach the proxy.

Trust boundaries:

- plaintext and private keys cross only local client process/memory boundaries;
- encrypted API traffic crosses TLS, the private network, proxy, and untrusted
  sync service;
- the server database stores ciphertext plus public and operational metadata;
- enrollment approval crosses an out-of-band human fingerprint comparison;
- browser fill crosses into a selected page field and becomes page-readable;
- recovery decryption crosses into an offline process or replacement vault;
- child-process injection crosses into that process and its descendants.

Assume attackers can read/modify/replay/drop network traffic outside TLS, call
public vault/enrollment routes, compromise the sync service/database/proxy,
serve stale database state, observe ciphertext length and timing, steal
encrypted local configs or recovery artifacts, guess passphrases offline,
control a pending or revoked device, compromise a browser page or local
secret-consuming process, and obtain historical ciphertext and keys previously
stored by a revoked device. Distinguish those capabilities from full endpoint
compromise, which defeats plaintext confidentiality on that endpoint.

## Security claims and non-claims

Claims to evaluate:

- the service cannot decrypt record names/values without a vault key;
- record IDs hide names from parties without that key;
- encryption detects modification and binds objects to their intended context;
- approved-device signatures authenticate protected requests and persisted
  nonces reject replay within the accepted timestamp design;
- enrollment discloses a vault key only after signed approval to the intended
  pending X25519 identity;
- local configs and recovery artifacts resist offline guessing according to
  the stated PBKDF2 cost and authenticate their headers/context;
- revoked identities lose future server access, and restoration creates a
  separate authorization domain;
- exact-origin checks constrain browser filling as documented.

Non-claims: protection after endpoint/page/child-process compromise; key recall
from revoked devices; vault rekeying; server rollback detection; metadata,
traffic-analysis, or availability protection; high availability or multi-host
SQLite; hardware-backed key custody; memory-locking or guaranteed erasure;
automatic provider credential rotation; KMS/HSM equivalence.

## Primitive and format inventory

All binary values are unpadded base64url unless stated otherwise. Randomness is
Go `crypto/rand`. See [the security core](../internal/secure/secure.go),
[protocol types](../internal/protocol/protocol.go), and
[recovery format](../internal/recovery/artifact.go).

| Purpose | Primitive and exact parameters | Version/size |
| --- | --- | --- |
| Vault key | Uniform random bytes | 32 bytes |
| Device signing | Ed25519 | 32-byte public, 64-byte private, 64-byte signature |
| Device wrapping | X25519 ECDH | 32-byte public/private; fresh 32-byte ephemeral public per wrap |
| General AEAD | AES-256-GCM, random 12-byte nonce, 16-byte tag | `secure.Blob.version = 1` |
| Local config KDF | PBKDF2-HMAC-SHA-256, random 16-byte salt, 600,000 iterations, 32-byte output | config v1; reader permits 100,000–10,000,000 |
| Recovery KDF | PBKDF2-HMAC-SHA-256, random 16-byte salt, exactly 600,000 iterations, 32-byte output | artifact v1 |
| Wrap KDF | HKDF-SHA-256, X25519 shared secret, nil salt, context as `info`, 32-byte output | envelope v1 |
| Record ID | HMAC-SHA-256 keyed by vault key | 32 bytes before base64url |
| Device fingerprint | SHA-256 over domain and two encoded public keys; first 8 bytes as 16 lowercase hex characters | fingerprint v1 |
| Request body binding | SHA-256 of exact HTTP body | 32 bytes before base64url |
| Request nonce | random bytes | 18 bytes |
| Recovery identity | SHA-256 of exact artifact file | 32 bytes, lowercase hex |

Domain/context strings and constructions are exact:

```text
record ID input =
  "envbank.record.id.v1\x00" || UTF8(name)

device fingerprint input =
  "envbank.device.fingerprint.v1\x00" ||
  base64url(ed25519_public) || "\x00" || base64url(x25519_public)

record AAD =
  "envbank.record.v1\x00" || vault_id || "\x00" || record_id

local config AAD =
  "envbank.local.v1\x00" || server_url || "\x00" || vault_id ||
  "\x00" || device_id
  [ || "\x00recovery\x00" || lowercase_hex(sha256(artifact_file)) ]

vault-wrap HKDF info and AES-GCM AAD =
  "envbank.vault.wrap.v1\x00" || vault_id || "\x00" || device_id

recovery AAD =
  "envbank.recovery.v1\x00" || decimal(version) || "\x00" ||
  kdf_name || "\x00" || base64url(salt) || "\x00" ||
  decimal(iterations) || "\x00" || cipher_name

signed message =
  "envbank.request.v1\n" || HTTP_method || "\n" ||
  request_uri_path_and_query || "\n" || RFC3339_timestamp || "\n" ||
  base64url(18_random_bytes) || "\n" ||
  base64url(sha256(exact_body_bytes))
```

`recovery` KDF/cipher names are exactly `pbkdf2-hmac-sha256` and
`aes-256-gcm`. Recovery reads are capped at 256 MiB and server request bodies at
1 MiB. HTTP request headers are capped at 16 KiB in the server configuration.
Authenticated timestamps allow an absolute five-minute skew. A nonce is unique
per vault/device in SQLite; accepted nonces older than ten minutes are pruned
after authentication.

## Key lifecycle and protocol flows

### Local configuration

`init` generates Ed25519/X25519 identities and a vault key. Public keys go to
the service; private keys and vault key form `DeviceSecrets`, encrypted in the
v1 local config with the passphrase-derived key and local AAD. Save uses a
same-directory temporary file, rename, and mode `0600`. Unlock validates the
config version and iteration range, derives the key, authenticates/decrypts,
and returns secrets in process memory. Relevant code:
[local config](../internal/client/local.go),
[CLI initialization](../cmd/envbank/main.go), and
[security tests](../internal/secure/secure_test.go).

### Records

The keyed record ID derives from the plaintext name. `SecretRecord` JSON
contains name, value, timestamps, rotation policy, revision, and allowed
origins. It is AES-GCM encrypted under the vault key with record AAD and a fresh
nonce. On read, the client verifies both recomputed ID and encrypted revision
against server metadata. The server uses optimistic revisions but stores only
the latest blob. See [record crypto](../internal/client/records.go),
[record tests](../internal/client/records_test.go), and
[server integration tests](../internal/server/integration_test.go).

### Device enrollment and revocation

A pending device locally generates both key pairs and publicly submits its name
and public keys. An approved device retrieves it, compares the 64-bit displayed
fingerprint over a trusted out-of-band channel, creates an ephemeral X25519 key,
derives a wrapping key, encrypts the vault key for the pending vault/device
context, and signs the approval request. The pending signing key may retrieve
only its own status; after approval it unwraps and locally re-locks the vault
key. Revocation atomically marks the device and deletes its replay nonces but
does not delete its envelope or recalled local keys. See
[CLI enrollment](../cmd/envbank/main.go),
[server enrollment/authentication](../internal/server/server.go), and
[device tests](../cmd/envbank/device_test.go).

### Signed requests and replay protection

The client signs the exact method, path plus query, RFC3339 timestamp, random
nonce, and exact body digest. The server resolves the claimed known identity,
verifies the signature before authorization, checks nonce/timestamp, inserts
the nonce with a uniqueness constraint, applies authorization, and commits the
nonce, operation, and verified event together. A failed transaction does not
consume the nonce. See [API signing](../internal/client/api.go),
[canonical message](../internal/protocol/protocol.go),
[server authentication](../internal/server/server.go), and
[event transactions](../internal/server/events.go).

### Recovery and restoration

Export decrypts the current records, validates and sorts them by name,
serializes `{"records":[...]}`, derives a separate artifact key, and encrypts
one payload. The header fields are AAD. Creation is `0600`, synchronized, and
refuses overwrite. Offline commands decrypt locally. Restore creates a new
vault key and device identity, binds its local config to the source artifact
digest, resets record revisions to 1, and can resume only after checking
existing target plaintext equality. See
[recovery implementation](../internal/recovery/artifact.go),
[recovery CLI](../cmd/envbank/recovery.go),
[format tests](../internal/recovery/artifact_test.go), and
[CLI tests](../cmd/envbank/recovery_test.go).

### Browser filling

Origins are normalized to exact HTTPS origins or HTTP loopback origins. The
encrypted record carries the allowlist. The extension requests a list without
values; after a user chooses a record and top-frame field, a separate fill
request makes the native host refetch current ciphertext and recheck origin
immediately before returning the value. The decrypted key remains in native
host memory until lock, disconnect, or ten-minute idle expiry. See
[origin policy](../internal/browser/origin.go),
[native host](../internal/nativehost/host.go),
[extension core](../extension/core.js),
[background bridge](../extension/background.js), and
[content script](../extension/content.js).

## Security-critical code map

| Concern | Implementation | Primary tests/evidence |
| --- | --- | --- |
| Randomness, keys, AEAD, PBKDF2, HKDF, HMAC, signatures, fingerprint | [secure.go](../internal/secure/secure.go) | [secure_test.go](../internal/secure/secure_test.go) |
| Signature canonicalization and timestamp window | [protocol.go](../internal/protocol/protocol.go) | exercised by [integration_test.go](../internal/server/integration_test.go) |
| Local encrypted identity and AAD | [local.go](../internal/client/local.go) | CLI/recovery tests and secure tests |
| Record encryption, ID/revision binding | [records.go](../internal/client/records.go) | [records_test.go](../internal/client/records_test.go) |
| HTTP signing and nonce generation | [api.go](../internal/client/api.go) | server integration tests |
| Authentication, replay, enrollment, revocation, revisions, limits | [server.go](../internal/server/server.go) | [integration_test.go](../internal/server/integration_test.go) |
| Access-event transaction/privacy rules | [events.go](../internal/server/events.go) | [events_test.go](../internal/server/events_test.go) |
| Legacy/schema migrations | [migrate.go](../internal/server/migrate.go) | server integration/events tests |
| Recovery format/validation/write safety | [artifact.go](../internal/recovery/artifact.go) | [artifact_test.go](../internal/recovery/artifact_test.go) |
| Restore/resume boundaries | [recovery.go](../cmd/envbank/recovery.go) | [recovery_test.go](../cmd/envbank/recovery_test.go) |
| Browser origin canonicalization | [origin.go](../internal/browser/origin.go) | [origin_test.go](../internal/browser/origin_test.go) |
| Native secret lifetime and fill recheck | [host.go](../internal/nativehost/host.go) | [host_test.go](../internal/nativehost/host_test.go) |
| Extension isolation and fill behavior | [extension](../extension/) | [extension tests](../extension/test/) |
| Deployment, backup, and restore | [production runbook](production-deployment.md), [backup runbook](backup-and-restore.md) | `make recovery-drill`; production checklist |

## Known limitations

- PBKDF2 is CPU-hard but not memory-hard. Offline attackers can accelerate
  guesses; adequacy depends strongly on passphrase entropy and target hardware.
- A revoked device can retain its private keys, vault key, ciphertext, and
  plaintext. Revocation blocks only future service access.
- There is no vault rekey/re-encryption workflow and no cryptographic recall.
- The server can roll back, delete, reorder, or withhold database state. There
  are no signed checkpoints or client rollback resistance.
- Record count, device count, timestamps, ciphertext lengths, access patterns,
  public-key metadata, enrollment activity, and operational event metadata
  leak to the service/proxy.
- Vault creation and enrollment request surfaces are public to callers that
  reach the private proxy. Rate limiting is proxy-only.
- Endpoint, child-process, page, extension, native-host, or local-admin
  compromise can expose plaintext and keys at use time.
- Go-managed key/passphrase copies may remain in memory. Explicit clearing is
  best effort and is not guaranteed across compiler/runtime copies or swap.
- The 64-bit displayed fingerprint relies on correct out-of-band human
  comparison and has no words/checksum ceremony.
- Random AES-GCM nonces have no persistent per-key allocation or duplicate
  detection; safety relies on 96-bit random uniqueness.
- Format versions exist, but no algorithm/KDF migration implementation has yet
  been exercised in production.

## Focused reviewer questions

1. Are the shared `secure.Blob` encoding and distinct AAD/domain strings
   sufficient misuse resistance across local, record, wrap, and recovery uses?
2. Is request canonicalization unambiguous across Go client, reverse proxies,
   escaped paths, duplicate query parameters, and future clients?
3. Can timestamp/nonce validation, pruning, transaction rollback, concurrent
   processes, or database rollback enable replay or denial of service?
4. Does enrollment correctly authenticate and bind the approving device,
   pending signing identity, X25519 recipient, vault, and device ID? Is a 64-bit
   human fingerprint adequate?
5. Are PBKDF2 parameters and config reader bounds adequate for current offline
   attack economics, and what versioned memory-hard migration is advised?
6. Does recovery strictly authenticate every algorithm/parameter/context field,
   validate plaintext sufficiently, prevent unsafe overwrite/resume, and avoid
   cross-vault confusion?
7. Is key separation adequate when one vault key serves record AEAD and record
   ID HMAC? Should subkeys be derived, and how should migration work?
8. Is random 96-bit AES-GCM nonce generation safe at expected per-key volumes
   for records and wrap blobs, and should collision controls or derived subkeys
   be added?
9. Are revocation, retained envelopes/keys, browser refetch, and restoration
   boundaries accurately enforced and communicated?
10. Can all current versions migrate without nonce reuse, downgrade,
    reinterpretation, rollback acceptance, or loss of authenticated context?

## Finding and disclosure format

Report findings privately through the channel selected before handoff. Do not
open public issues or include real secrets, production artifacts, private keys,
passphrases, tokens, vault/device/record identifiers, production URLs, or
unsanitized databases/logs.

For each finding include: unique ID; title; severity and rationale; affected
review SHA/files/functions; violated claim; prerequisites and attacker
capability; reproducible steps using synthetic data only; observed and expected
behavior; confidentiality/integrity/availability impact; suggested remediation;
test or invariant that would prevent regression; and any migration,
compatibility, or disclosure concerns. Separate confirmed findings, hardening
recommendations, and unresolved questions. End with coverage, limitations, and
an explicit statement that absence of reported findings is not proof of
security.
