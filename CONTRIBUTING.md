# Contributing to EnvBank

EnvBank welcomes focused bug fixes, tests, documentation improvements, and
carefully scoped feature proposals. It is alpha-quality security software, so
changes should preserve the documented threat model and fail closed.

## Development setup

Install Go 1.25.13 or later and Node.js 24. Then run:

```sh
go mod download
make format-check
go mod verify
make test
make e2e
make race
make vet
make recovery-drill
make build-cross
```

Install website dependencies with `npm ci --prefix website` before running the
network-free E2E gate. Browser, Keychain, release-artifact, and opt-in provider
acceptance are documented in the [E2E runbook](docs/e2e-testing.md); they are
local release checks and are not substitutes for `make e2e`.

Install `govulncheck` and Gitleaks to run the remaining security checks:

```sh
govulncheck ./...
gitleaks git --redact
```

## Pull requests

Open an issue before a large design change. Keep each pull request narrow,
explain its security and compatibility impact, add tests for changed behavior,
update documentation, and ensure every required check passes. Never commit real
credentials, device configs, databases, recovery artifacts, or generated
binaries.

By intentionally submitting a contribution, you agree that it is provided
under the project's [Apache License 2.0](LICENSE), as described in section 5 of
that license. No CLA or DCO sign-off is required.

Be respectful, constructive, and mindful that maintainers and contributors may
have different backgrounds and constraints. A standalone Code of Conduct is
deferred until the project has a separate private conduct-reporting channel.

Security vulnerabilities must not be reported in issues or pull requests.
Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting.
