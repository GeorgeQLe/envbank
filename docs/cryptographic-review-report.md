# Independent cryptographic review report

## Disposition

The independent review of revision
`59446421f10bc3465adb1d70f30ad50259b9209d` confirmed three findings. All three
were remediated in
`505de15f6bc4840db3b9084866163ea3e5aba2b9`, then re-reviewed from a fresh,
detached `--no-local` clone. Both clean-clone status checks were empty and the
complete verification packet passed on 2026-08-06.

This closes the cryptographic-review milestone for the reviewed scope. It does
not convert EnvBank into a KMS/HSM, remove the documented non-claims, complete
the operational production checklist, or implement the separate crypto-v2
hardening recommendations below.

## Review environment and coverage

- Host: macOS Darwin 25.6.0, arm64
- Go: `go1.25.12 darwin/arm64`
- Node: `v25.2.1`
- Vulnerability scanner: `govulncheck v1.6.0`
- Vulnerability database update observed: 2026-07-27 20:14:16 UTC
- Initial reviewed SHA: `59446421f10bc3465adb1d70f30ad50259b9209d`
- Remediation re-review SHA:
  `505de15f6bc4840db3b9084866163ea3e5aba2b9`

The review covered key generation and encoding, fingerprints, local config and
recovery encryption, record encryption and IDs, vault-key wrapping, enrollment
and invitation identity binding, authenticated request construction, replay
retention, revocation, schema migrations, recovery behavior, browser/native
origin boundaries, build inputs, deployment guidance, and associated tests.

The detached re-review ran formatting checks, `go mod verify`, `go test ./...`,
`go test -race ./...`, `go vet ./...`, all extension tests, native and
Linux/amd64 builds, the recovery drill, review-link/file checks, and
`govulncheck ./...`. Results included nine passing extension tests, schema
version 5 recovery with both SQLite quick checks returning `ok`, and
`No vulnerabilities found.` The macOS linker emitted known `LC_DYSYMTAB`
warnings during race-test linking; the race suite completed successfully.

## Confirmed findings and remediation

### CR-01: Enrollment identity substitution — High

Affected initial-revision paths included enrollment/invitation creation,
approval, acceptance, and the pairing lab. A synthetic server response could
replace locally generated public keys or return a stale fingerprint; callers
displayed or persisted parts of that identity without consistently binding it
back to local keys. Acceptance also did not require the unwrapped vault key to
be exactly 32 bytes.

An attacker able to alter sync-service responses could redirect approval to an
attacker-selected X25519 identity or cause a client to persist an identity that
did not match its private keys. That violated the claim that approval delivers
the vault key only to the intended pending identity.

The remediation:

- requires canonical unpadded base64url and exact Ed25519/X25519 lengths;
- rejects invalid/low-order X25519 public points;
- recomputes fingerprints locally;
- binds creation responses to the requester's locally generated keys;
- binds approval to both the recomputed server identity and the out-of-band
  fingerprint;
- derives acceptance public keys from the decrypted private keys and compares
  them with the returned identity; and
- accepts only an unwrapped 32-byte vault key.

All vault, legacy-enrollment, invitation, CLI, and pairing-lab paths now use
equivalent fail-closed checks. Regression coverage substitutes creation
responses, changes keys without updating fingerprints, supplies malformed and
noncanonical keys, mismatches acceptance identities, and wraps an incorrectly
sized vault key.

Invariant: no fingerprint is displayed or persisted, and no vault key is
wrapped or accepted, until the complete returned public identity has been
validated and locally rebound.

### CR-02: Attacker-controlled replay retention timestamp — Medium

The initial server accepted general RFC3339 timestamp spellings, stored the
signed client timestamp text in `nonces.created_at`, and later compared that
text lexically with a UTC pruning cutoff. An otherwise current timestamp with a
large negative offset could therefore be inserted and immediately pruned.
Repeating the exact signed request after pruning could be accepted again.
Separate clock reads also made validation, insertion, and pruning needlessly
inconsistent.

The remediation requires canonical UTC-second RFC3339 timestamps and canonical
unpadded base64url nonces encoding exactly 18 bytes. Authentication captures
server time once and uses it for timestamp validation, nonce insertion, and
pruning. Schema v5 refreshes every existing nonce's retention timestamp to
migration time, conservatively preserving replay protection through upgrade
while still allowing normal expiry.

Regression coverage rejects offset/fractional timestamps and malformed or
padded nonces, proves a rejected offset request cannot consume or prematurely
prune a nonce, rejects an exact replay, and proves a nonce present during a
v4-to-v5 migration remains replay-blocking.

Invariant: replay-retention ordering depends only on canonical server time,
never attacker-controlled timestamp text.

### CR-03: Vulnerable minimum Go runtime — Medium

The initial module declared Go 1.25.0 and the Docker builder used the mutable
`golang:1.25-alpine` tag. That allowed builds with a runtime below the required
security patch floor and made the container toolchain input mutable.

The minimum is now Go 1.25.12. The builder is pinned to the official
multi-platform `golang:1.25.12-alpine` image index at
`sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587`.
Installation and deployment guidance state the same floor.
`govulncheck ./...` is a documented external security check and is not an
application dependency.

Invariant: supported builds use Go 1.25.12 or later, container builds resolve
the reviewed builder digest, and release evidence includes a current
vulnerability scan.

## Compatibility and migration

Protocol v1 now rejects timestamp offsets, fractional seconds, padded nonces,
and incorrectly sized nonces. Existing clients already emit the accepted
canonical forms. SQLite advances from schema v4 to v5. Ciphertext, envelope,
local config, recovery artifact, and record formats remain version 1; no data
re-encryption is required.

The v5 migration intentionally extends retention for existing nonces by at most
the normal retention interval. This avoids a migration-time replay window at
the cost of temporarily retaining some otherwise expiring replay rows.

## Separate crypto-v2 recommendations

These are hardening recommendations, not confirmed defects in the reviewed v1
formats. They remain deferred so this remediation does not silently change
existing ciphertext or recovery compatibility:

- define a versioned PBKDF2-to-Argon2id migration with explicit memory, time,
  parallelism, downgrade, and resource-exhaustion rules;
- derive domain-separated record encryption and record-ID subkeys instead of
  using the vault key directly for both constructions;
- lengthen device fingerprints and define a usable transition/display format;
- replace unconstrained random AES-GCM nonces with a versioned strategy that
  gives a stronger per-key uniqueness bound; and
- add authenticated rollback resistance for server state, ciphertext
  revisions, authorization state, and audit history.

Production claims must continue to respect these deferrals, especially the
documented lack of rollback detection and vault rekeying.

## Limitations

This was a source, protocol, test, migration, build-input, and documentation
review of the two immutable revisions above. It did not include formal proofs,
side-channel or fault-injection analysis, fuzzing at production scale, an
external penetration test, compromised-endpoint resistance, proxy/VPN
configuration validation, binary reproducibility across all platforms, or a
live production deployment. The clean re-review validates the committed source
and local evidence, not every future build or operator configuration.

The review packet's file-existence loop originally used `path`, which is a
special zsh parameter and can erase command lookup inside the loop. The
evidence was rerun successfully with `file_path`, and the packet was corrected
in the milestone documentation commit.

Absence of reported findings is not proof of security.
