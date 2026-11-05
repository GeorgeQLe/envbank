# Codex lifecycle-hook integration — 2026-11-04

Owner request: fix the missing integration hook; implement with Opus 5.5;
parent reviews, tests and merges. Branch `feat/protected-host-hooks`.

Corrects the November 3–4 wording ("the CUA interface exposes no hook"):
documented Codex lifecycle hooks exist; their fail-open/coverage limits prevent
treating them as a global barrier or Driver registration. Older dated records
keep their original evidence boundaries.

## Done in source (a)

- [x] `protectedfill.ProbeGate`: read-only view of the single durable latch.
- [x] `pkg/codexhook` + `envbank codex-hook pre-tool-use|post-tool-use|capabilities|init-gate`.
- [x] Fixed capability statement (v2): no global barrier, runtime may fail
      open, missing/untrusted hooks do not run, specialized paths may opt out,
      `write_stdin` PreToolUse and hosted tools uncovered, PostToolUse
      `decision: "block"` rejects a code-mode nested promise but undoes no side
      effects, no in-flight drain, credential release refused.
- [x] Owner-review artifacts: `integrations/codex/{README.md,hooks.example.json}`.
- [x] Adversarial tests: see `integrations/codex/README.md#tests`.
- [x] Docs blocker resolved by source check (review pass, November 4): the
      parent-downloaded official `codex-hooks.md` and `codex-plugin-build.md`
      were read. Evidence used:
      - config shape, `timeout` in seconds (default 600), `matcher` `"*"`/`""`
        matches every occurrence; `PreToolUse`/`PostToolUse` honor `matcher`;
      - PreToolUse deny: `hookSpecificOutput.permissionDecision: "deny"` with
        `permissionDecisionReason`; exit 0 with no output continues; unsupported
        fields fail the hook run and continue the tool call (fail open);
      - PostToolUse `decision: "block"` + `reason` replaces the tool result;
        the code-mode table says the nested promise rejects with the hook
        reason, while `continue: false` does not reject it. The prior capability
        `post_tool_use_rejects_nested_result: false` was wrong and is replaced;
      - Tool coverage table: hosted tools No/No; `write_stdin` does not rerun
        PreToolUse; specialized paths can opt out ("a useful guardrail, not a
        complete enforcement boundary");
      - non-managed (user/project/plugin) hooks are skipped until trusted;
        plugin hooks need a manually installed desktop plugin; `async` hooks
        cannot block.
      Not verified: behavior of an installed Codex runtime.
- [x] Slow-input handling: the read uses one fixed buffer and a reader that
      finishes after the 2 s bound wipes it instead of retaining it.

## Not done — owner/host blockers (b, c)

- [ ] Owner decision whether to install through Codex's own trust flow on a
      controlled host, and where the private gate directory lives.
- [ ] A protected-operation authority (`OpenGate` + qualified `Driver`) running
      on that host. None exists for the installed CUA; the hook only observes.
- [ ] Installed-runtime qualification (fail-open behavior, coverage of every
      tool route, sentinel scans). Not attempted; not claimed.

Required parent checks: `go test ./...`, `go test -race ./pkg/... ./cmd/envbank`,
`go vet ./...`, build, and secret scans, with `TMPDIR` on disposable T7 storage.

## Parent verification — November 4, 2026

Claude Opus 5.5 implemented and performed a fresh source review; the parent
reviewed the diff and corrected the new fixture's initial-effect accounting.
Source review approves merging with credential delivery disabled. Observed:

- Full `go test ./...`, `go vet ./...`, and CLI build passed.
- `go test -race ./pkg/... ./cmd/envbank` passed; after the protocol corrections,
  focused hook/gate/CLI race tests also passed.
- Node 24 extension tests: 20 passed.
- Gitleaks staged scan: no leaks found; `git diff --check` passed.
- The hook config and response schemas were compared to the official docs;
  no hook installation, trust change, real credential read or provider operation
  was performed. Installed-runtime and real-provider acceptance remain pending.

GitHub main requires its existing CI/security checks; Actions was disabled when
inspected. Merge must honor those checks, without changing workflows or bypassing
branch protection.
