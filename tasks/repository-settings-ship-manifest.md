# Repository visibility and security-settings ship manifest

## User goal

Complete and ship the unchecked EnvBank repository visibility and GitHub
security-settings launch task.

## Changed files

- `tasks/todo.md`
- `tasks/history.md`
- `tasks/launch-v0.1.0-ship-manifest.md`
- `tasks/repository-settings-ship-manifest.md`

## Per-file purpose

- `tasks/todo.md`: mark the repository visibility and security-settings launch
  task complete.
- `tasks/history.md`: record the verified public repository and enabled GitHub
  security controls.
- `tasks/launch-v0.1.0-ship-manifest.md`: remove the completed repository step
  from the list of remaining external launch work.
- `tasks/repository-settings-ship-manifest.md`: preserve the exact shipping
  boundary, verification evidence, risks, rollback, and next action.

## User-goal mapping

The repository is named `GeorgeQLe/envbank` and GitHub reports it as public.
Private vulnerability reporting, vulnerability alerts, Dependabot security
updates, secret scanning, secret-scanning push protection, and the repository's
security workflow are enabled. The task and launch records now match that live
state.

## Tests run

- GitHub API verification of repository identity and public visibility.
- GitHub API verification of private vulnerability reporting.
- GitHub API verification of vulnerability alerts and automated security
  fixes.
- GitHub API verification of Dependabot security updates, secret scanning,
  secret-scanning push protection, and the active security workflow.
- `git diff --check`.

## Skipped tests

Go, extension, race, vet, build, and recovery tests are not relevant because
the shipping boundary changes only task documentation and remote repository
settings; it does not change source code, tests, build inputs, workflows, or
runtime behavior.

## Adversarial review

The exact diff was checked for claims broader than GitHub's reported state,
accidental completion of the separate branch-protection/release task, stale
remaining-work language, credential content, and unrelated file changes. The
optional secret-scanning validity-check and non-provider-pattern settings
remain disabled and are not claimed as completed launch controls.

## Residual risk

GitHub may add or change security controls after this verification. Optional
secret-scanning validity checks and non-provider-pattern scanning were not
available through the current repository settings and remain disabled.

## Rollback note

Revert the documentation commit if the recorded state is incorrect. Reverting
the commit does not change live GitHub settings; those must be changed through
the repository settings or API.

## Next command

Complete the remaining `main` protection, `v0.1.0` prerelease, GHCR publication,
and package-visibility launch task.
