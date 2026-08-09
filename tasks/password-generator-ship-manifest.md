# Password generator ship manifest

## User goal

Add cryptographically secure random-character password generation to EnvBank's
CLI and Chrome extension while keeping generated plaintext out of command
output, metadata responses, popup JavaScript, extension storage, clipboard, and
logs.

## Changed files and per-file purpose

- `README.md` — document password generation, replacement, policy flags, and
  the distinction from URL-safe rotation tokens.
- `SECURITY.md` — document plaintext and authorized-page boundaries.
- `cmd/envbank/generate_test.go` — cover CLI creation, refusal, replacement,
  metadata, rotation policy, and output redaction.
- `cmd/envbank/main.go` — add the `generate` command and help text.
- `docs/architecture.md` — document generator cryptography and native/browser
  trust boundaries.
- `extension/README.md` — document popup generation and navigation behavior.
- `extension/background.js` — revalidate origins, request native generation,
  and arm the existing fill flow.
- `extension/popup.css` — style generator controls.
- `extension/popup.html` — add policy inputs and explicit confirmation dialog.
- `extension/popup.js` — validate policy, identify replacement revisions, and
  submit confirmed generation requests.
- `extension/test/core.test.js` — cover confirmation, revision forwarding,
  origin changes, navigation races, and prohibited APIs.
- `internal/nativehost/host.go` — add protocol-v1 `generate_password`,
  optimistic replacement, exact-origin authorization, encrypted persistence,
  and redacted metadata.
- `internal/nativehost/host_test.go` — cover create/replace, stale revisions,
  validation, origin preservation, ciphertext persistence, and redaction.
- `internal/password/password.go` — implement secure class-aware generation
  with rejection sampling and a cryptographic Fisher-Yates shuffle.
- `internal/password/password_test.go` — cover defaults, bounds, validation,
  allowed/required classes, reader failures, and biased-tail rejection.
- `tasks/history.md` — record the completed session.
- `tasks/todo.md` — mark secure CLI/browser generation complete.
- `tasks/password-generator-ship-manifest.md` — record this exact quality and
  rollback boundary.

## User-goal mapping

- Shared generator: `internal/password/*`.
- CLI command and compatibility: `cmd/envbank/main.go` and
  `cmd/envbank/generate_test.go`.
- Native-host security boundary: `internal/nativehost/*`.
- Popup generation-to-fill experience: `extension/popup.*`,
  `extension/background.js`, and `extension/test/core.test.js`.
- User/security/architecture guidance: `README.md`, `SECURITY.md`,
  `extension/README.md`, and `docs/architecture.md`.

## Tests run

Executable verification:

- `go test ./...` — passed, including loopback pairing tests outside the
  restricted command sandbox.
- `go vet ./...` — passed without warnings.
- `node --test extension/test/*.test.js` — 13/13 passed.
- `go test -race ./internal/password ./internal/nativehost ./cmd/envbank` —
  passed.
- `go build -o /tmp/invisible-envs-bank-envbank ./cmd/envbank` — passed without
  warnings in the approved execution context.
- `make format-check` — passed.
- `git diff --check` — passed.
- `gitleaks dir --redact --no-banner .` — passed with no leaks.

Documentation/task checks:

- Reviewed task status and history against the implementation and test output.
- No task-document audit script exists in this repository.

## Skipped tests

- A real Chrome/native-messaging acceptance test was not run because it
  requires the installed macOS native-host manifest, Keychain user presence,
  and manual field selection in a browser profile. Automated extension and
  native-host tests cover the protocol and navigation-race behavior, but do not
  replace this interactive smoke test.
- The full repository race suite was not repeated; targeted race tests covered
  every changed Go runtime path, while the full non-race suite covered all
  packages.

## Adversarial review

Reviewed the combined `main`-to-working-tree boundary for modulo bias, class
omission, invalid lengths and empty policies, random-reader failure, creation
races, stale replacement revisions, metadata loss, unauthorized origin
changes, navigation between storage and fill arming, and accidental plaintext
egress through CLI output, native metadata/errors, popup state, logging,
clipboard, or browser storage. The encrypted upload was decrypted in tests to
verify its content while the wire request was checked not to contain the
plaintext. No blocking findings remain.

## Residual risk

- Go strings cannot be reliably zeroed, so generated plaintext remains subject
  to ordinary process-memory exposure until reclaimed; it is never deliberately
  persisted outside the encrypted record.
- An authorized or compromised destination page can read a filled password.
- Real-browser UX and Keychain prompts retain the manual smoke-test gap noted
  above.

## Rollback note

Revert the password-generator shipping commit to remove the additive CLI,
native protocol action, popup controls, tests, and documentation. Existing
encrypted records need no migration and remain readable.

## Next command

Install the guided walkthrough pack, then complete the first unchecked launch
task for repository rename/public visibility and GitHub security settings.
