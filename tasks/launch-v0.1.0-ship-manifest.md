# EnvBank v0.1.0 launch ship manifest

## User goal

Rename and publish EnvBank as an explicitly alpha-quality Apache-2.0
open-source project with public governance, security automation, release
archives, checksums, an SPDX JSON SBOM, provenance, and a multi-architecture
GHCR image.

## Changed files and purpose

- `go.mod`, `cmd/**/*.go`, and `internal/**/*.go`: rename the module and imports
  to `github.com/GeorgeQLe/envbank`.
- `cmd/envbank/main.go` and `cmd/envbank/main_test.go`: add tested development
  and link-time release version metadata.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`: establish the
  Apache-2.0 license and public contribution, disclosure, support, and release
  policies.
- `README.md`, `docs/production-deployment.md`, and
  `.github/release-notes-v0.1.0.md`: document alpha limitations, supported
  platforms, unsigned macOS binaries, installation, checksums, SBOM and
  provenance verification, and the canonical repository/image names.
- `.github/ISSUE_TEMPLATE/*.yml`: provide public bug and feature forms while
  routing vulnerability reports to GitHub private vulnerability reporting.
- `.github/dependabot.yml`: schedule weekly Go module and Actions updates.
- `.github/workflows/ci.yml`: add formatting, module, Go/Linux/macOS, race, vet,
  Node 24 extension, recovery, cross-build, and vulnerability checks.
- `.github/workflows/security.yml`: add full-history Gitleaks and Go/JavaScript
  CodeQL scanning.
- `.github/workflows/release.yml`: enforce the annotated on-main `v0.1.0` tag,
  rerun release gates, natively build and execute four platform archives,
  audit dependency licenses, generate checksums and SPDX JSON, attest artifacts,
  publish and attest an AMD64/ARM64 GHCR image, and create a prerelease.
- `.gitleaks.toml` and `scripts/test-gitleaks-config.sh`: allow only the known
  public Chrome key and symbolic HMAC example while proving a synthetic secret
  remains detectable.
- `Dockerfile`: propagate release metadata and OCI labels while preserving the
  non-root, shell-free image.
- `Makefile`: expose format, secret-policy, and four-target build validation.
- `.gitignore`: ignore local Codex, Claude, and skillpack state while retaining
  tracked `.agents/project.json`.
- `tasks/todo.md`, `tasks/history.md`, and this manifest: record launch progress,
  evidence, remaining external steps, and the shipping boundary.

## User-goal mapping

Every requested repository-readiness change is represented above. The GitHub
rename, public visibility, private vulnerability reporting, and supported
repository security settings are complete. Branch protection, tagging,
publication, package visibility, and anonymous verification remain explicit
post-commit launch steps because they operate on the remote repository.

## Executable tests run

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `node --test extension/test/*.test.js`
- `make recovery-drill`
- `make build-cross`
- `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`
- `go run github.com/google/go-licenses/v2@v2.0.1 check ./...`
- `gitleaks git --redact --config .gitleaks.toml --verbose`
- `make secret-scan-test`
- `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`
- `docker build ... -t envbank:launch-test .`
- container version, UID/GID, shell-absence, and `/healthz` checks
- `go mod tidy -diff`, `git diff --check`, Go formatting, action-pin, and stale
  repository-name checks

## Skipped tests

Actual GitHub artifact/image attestation, release download, SBOM generation,
multi-architecture registry pull, and anonymous access checks require the
committed workflows and public remote. They are the next launch phase and are
not claimed as locally complete.

## Adversarial review

The shipping diff was checked for stale module/repository/image names,
unpinned Actions, broad secret exclusions, a bypassable tag gate, missing
release permissions, unsupported runner labels, production overclaims, and
credential-bearing local directories. The target repository name is currently
available, the source repository is private, the two historical Gitleaks
findings are narrowly allowed by exact content, and a synthetic credential is
still rejected. Current GitHub documentation confirms the four native runner
labels.

## Residual risk

The GitHub settings APIs and first workflow runs may expose plan/account
limitations or platform-specific action behavior that cannot be reproduced
locally. Publication must stop before tagging if required CI or security
settings fail. The release remains alpha and inherits the documented threat
model and deferred cryptographic/operational hardening.

## Rollback note

Before tagging, revert the launch-readiness commit and rename the repository
back if necessary. After publishing immutable artifacts, preserve the release
record and issue a clearly documented corrective prerelease instead of
rewriting the tag.

## Next command

`git push origin main`
