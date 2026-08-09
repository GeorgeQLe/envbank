# Release-settings reconciliation ship manifest

## User goal

Wrap up the session with project task records aligned to the verified GitHub
launch state.

## Changed files

- `tasks/todo.md`
- `tasks/history.md`
- `tasks/launch-v0.1.0-ship-manifest.md`
- `tasks/release-settings-reconciliation-ship-manifest.md`

## Per-file purpose

- `tasks/todo.md`: mark the completed branch-protection and release-publication
  launch task complete.
- `tasks/history.md`: record the remote branch, tag, prerelease, and package
  evidence discovered during protected-branch shipping.
- `tasks/launch-v0.1.0-ship-manifest.md`: narrow the remaining launch work to
  anonymous post-publication verification.
- `tasks/release-settings-reconciliation-ship-manifest.md`: preserve the exact
  reconciliation boundary, evidence, risk, rollback, and next action.

## User-goal mapping

The ship-end workflow exposed that the next checklist item was already complete
on GitHub. The updated task records now reflect enforced `main` protection, the
annotated `v0.1.0` tag, published alpha prerelease and GHCR image package, and
public package visibility.

## Tests run

- GitHub branch-protection API verification: administrators are enforced, pull
  request reviews are required, and 11 status checks are required.
- Git object verification: `v0.1.0` resolves to an annotated tag object.
- GitHub release verification: `v0.1.0` is published, non-draft, and marked as
  a prerelease.
- GitHub Packages verification: the `envbank` container package is public.
- `git diff --check`.

## Skipped tests

Go, extension, race, vet, build, and recovery tests are not relevant to this
task-document reconciliation. The preceding documentation PR passed all 11 CI
and security checks, and this boundary changes no source, workflow, build, or
runtime input.

## Adversarial review

The exact diff was checked against live GitHub state, for accidental completion
of the separate anonymous-verification task, for release claims not supported
by the API, for credential content, and for unrelated changes.

## Residual risk

Release assets, checksums, SBOMs, attestations, image health, digest pulls, and
the legacy redirect have not yet been verified anonymously. They remain the
explicit final launch task.

## Rollback note

Revert this documentation commit if the recorded release state is incorrect.
That revert does not change branch protection, tags, releases, images, or
package visibility on GitHub.

## Next command

Verify the public release and legacy repository redirect anonymously.
