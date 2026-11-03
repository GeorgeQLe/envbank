# Brave protected-fill implementation

Owner: George. Requirement: computer use operates the safe shell; a trusted
controller owns the sensitive phase. Design and exact limits:
[protected computer use](../docs/protected-computer-use.md).

- [x] Add Brave installer/uninstaller target and preserve explicit existing targets.
- [x] Add durable global gate SDK, stale-capture rejection, crash latch and recovery.
- [x] Add fixed-status coordinator with trusted validation/private execution and
  verified destruction of the dedicated context before observation resumes.
- [x] Add native protected protocol and host-only embedding API; reject legacy
  release/mutations in computer-use mode and refuse without a configured controller.
- [x] Add UI for non-secret record/field/submit selection. No field value is
  returned through the protected native protocol or selection script.
- [ ] Integrate an actual observation-controlling host and qualified Driver.
  Blocker: the current computer-use API has no documented global observation
  gate/driver integration. Do not substitute a page or agent acknowledgment.
- [ ] Qualify actual Brave native messaging, installation and human approval.
- [ ] Run integrated sentinel tests through every real capture/trace channel,
  including OCR, AX, DOM, clipboard, logs, delayed callbacks and concurrent tools.
- [ ] Qualify provider capture and Vercel settings persistence with exact approved
  project/environment/variable scope before any real credential transfer.
- [ ] Independent source/security review and explicit integrated release approval.

The implementation is intentionally unavailable for real protected filling until
the host integration is present. No live credentials, vault enrollment, key
rotation, provider permission changes or everyday browser-profile changes are
part of this implementation.

Verification: [non-secret evidence](../docs/protected-computer-use-verification-2026-11-03.json).
Full hermetic end-to-end gate, scoped race, vet, 20 JavaScript tests and 17
browser DOM cases passed. Actual OS/Brave confidentiality remains unqualified.
