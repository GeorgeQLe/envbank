# Security policy

EnvBank handles sensitive material and is currently alpha-quality software. It
is not a KMS, HSM, or enterprise secrets manager.

Generated passwords are plaintext only inside the generating CLI/native-host
process, encrypted record handling, and the explicitly selected destination
field. They are never returned by metadata APIs or exposed through command
output, extension storage, clipboard operations, logs, or popup JavaScript.
An authorized or compromised destination page can read a value after filling;
exact-origin authorization is not protection from page-level compromise.

## Supported versions

Only the latest release receives security fixes. Until a stable release exists,
that is the latest `v0.x` prerelease listed on GitHub. The `main` branch and
older releases are unsupported.

## Reporting a vulnerability

Report vulnerabilities only through
[GitHub private vulnerability reporting](https://github.com/GeorgeQLe/envbank/security/advisories/new).
Do not open a public issue, discussion, or pull request, and do not include real
secrets or private artifacts in a report.

Include affected versions, impact, prerequisites, and the smallest safe
reproduction description you can provide. You should receive an acknowledgment
within seven days. The maintainer will coordinate validation, a fix, disclosure
timing, and credit with you. Please allow a reasonable remediation window
before public disclosure; the target is 90 days unless active exploitation or
another exceptional risk requires a different timeline.

GitHub private vulnerability reporting is the project's only private security
channel. If it is unavailable, wait for it to return rather than disclosing a
vulnerability in a public project channel.
