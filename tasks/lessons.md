# Lessons

## 2026-08-15 — distinguish repeated authentication prompts

- Avoid asking for a sequence of visually similar approvals without naming the
  purpose and expected button for each prompt; repeated generic instructions
  make it easy to approve a cancellation test accidentally.
- For interactive Keychain acceptance, label every handoff as either
  **APPROVAL CHECK — Allow Once** or **DENIAL CHECK — Deny**, wait for the user
  to report that exact outcome, and reset disposable state before retrying a
  prompt whose result is ambiguous.
- Apply this whenever a test or release workflow presents more than one native
  authentication sheet, especially when approval and cancellation are both
  acceptance criteria.
