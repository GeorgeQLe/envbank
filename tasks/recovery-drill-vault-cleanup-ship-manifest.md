# Recovery-drill vault cleanup ship manifest

## User goal

Safely remove exactly the two accidental empty `recovery-drill` vaults from
the separate local showcase database while preserving its configured
`showcase` vault, device, and encrypted record, retaining a verified rollback
point, and correcting the project task record.

## Changed files

- `tasks/todo.md`
- `tasks/history.md`
- `tasks/siftcut-vault-object-foundation-ship-manifest.md`
- `tasks/recovery-drill-vault-cleanup-ship-manifest.md`

The SQLite database, rollback backup, and failed-attempt quarantine are local
operational artifacts under `/private/tmp/envbank-showcase` and are not part of
the Git commit.

## Per-file purpose

- `tasks/todo.md`: mark the approved two-vault cleanup complete and clear the
  operator-approval blocker.
- `tasks/history.md`: record the exact-ID transactional cleanup and successful
  integrity, authentication, decryption, health, and stopped-service checks.
- `tasks/siftcut-vault-object-foundation-ship-manifest.md`: correct the earlier
  count from one accidental vault to two and replace the completed cleanup next
  step with the next implementation slice.
- `tasks/recovery-drill-vault-cleanup-ship-manifest.md`: define and verify this
  exact documentation and operational shipping boundary.

## User-goal mapping

- The two approved vault IDs were deleted in one immediate foreign-key-enabled
  SQLite transaction guarded by exact inventory and zero-content assertions.
- The configured showcase vault, device, and encrypted record were compared
  with the pre-cleanup backup and remained unchanged.
- The task documents now describe two accidental vaults, the completed cleanup,
  the retained rollback point, and no remaining cleanup blocker.

## Tests run

Executable operational verification:

- Confirmed no listener on port 17337 and no process holding the database or
  its WAL sidecars before mutation.
- Required SQLite schema version 5, `PRAGMA quick_check = ok`, and an empty
  `PRAGMA foreign_key_check` before and after cleanup on both the live database
  and retained backup.
- Verified the exact three-vault precondition, both approved target IDs and
  their zero-data state, the configured device binding, and the exact one-vault
  final inventory.
- Compared the showcase vault, device, and encrypted record rows against the
  rollback backup without displaying encrypted or decrypted values.
- Started a schema-5 binary on `127.0.0.1:17337`, verified `/healthz`, and ran
  an authenticated list/decryption smoke test with output suppressed.
- Stopped the service and confirmed port 17337 was free.

Documentation verification:

- `git diff --check` passed.

## Skipped tests

- Go, extension, race, vet, security, cross-build, and recovery-drill suites
  were not rerun because this shipping boundary changes only task documents and
  the already-verified external SQLite data; it changes no source, test,
  script, schema definition, dependency, or build artifact.
- `scripts/audit-task-docs.mjs` was not run because the repository does not
  contain that optional audit script.
- `docs/quality-gate-contract.md` is absent, so this manifest applies the
  complete quality-gate fields required directly by the `ship-end` workflow.

## Adversarial review

- Revalidated exact IDs and names inside the write transaction so a concurrent
  inventory change would have failed closed and rolled back.
- Explicitly deleted and asserted zero target rows in `nonces` and
  `invitations`, whose foreign-key coverage differs from the directly
  vault-linked tables.
- A first smoke attempt used the current schema-6 binary. The post-smoke schema
  assertion rejected it, quarantined that database, and restored the verified
  backup. The cleanup was then repeated and verified with a rehearsed schema-5
  binary.
- No record blobs, encrypted configuration fields, passphrases, record names,
  or decrypted values were printed during inspection or smoke testing.

No unresolved finding remains in the live cleanup result or committed task
documentation.

## Residual risk

The mode-`0600` rollback backup remains beside the live database pending
explicit approval to delete it. The failed smoke attempt is retained in a
mode-`0700` quarantine directory and also contains an encrypted database copy;
both local artifacts require the same host access controls as the live
database. The authenticated smoke test added normal showcase audit/nonce state
but did not change the vault, device, or encrypted record rows.

## Rollback note

Stop the showcase service, confirm port 17337 and all database files are unused,
quarantine the current database and WAL sidecars, copy the verified mode-`0600`
backup back to `server.db`, and rerun schema, quick, foreign-key, health, and
authenticated list/decryption checks. Do not overwrite or delete the retained
backup during rollback.

Revert the documentation commit if the project record itself must be rolled
back.

## Next command

Run `$exec` for the pending Milestone 5 local `bundle prepare` and
`bundle status` implementation slice.
