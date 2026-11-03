# Protected filling through computer use

Implementation status, November 3, 2026: Brave native-host installation support,
an extension selection flow, a controller SDK, and refusal without host protection
are implemented. No real computer-use controller driver is connected. This is
not an operational credential-transfer feature or a security qualification of
Brave, OS capture, or the current agent tools. No real credentials were used.

The owner required the agent to be able to operate the non-secret controls.
The independent Opus 5.5 consultation reviewed the general design and public
1Password documentation; it was not a source-code audit or a test run.

## Visible interaction

The agent can choose a record by name, click **Protected fill**, select an empty
password field, and choose that form's submit button. Selection contains only
opaque handles. It cannot release a value or submit the form by itself. The
native host returns only fixed status codes from the protected operation.

The selection flow accepts top-frame, visible, empty password fields in
same-origin POST forms, rejects GET forms, submit overrides, iframes, detached or
changed fields, script-generated clicks, and cancellation. The native coordinator
requires an exact HTTPS origin. Loopback DOM fixtures test selection only.

The standalone native host reports protected filling unavailable. Ordinary
human fill remains separate and is **not agent-safe**. A trusted embedding must
use `pkg/computeruse.NewNativeHost`, which disables legacy value release,
generation and origin-policy changes even when protection is unavailable.
There is no command-line flag, native message or page acknowledgment that can
enable protection, override the gate, or resume observations.

## Controller integration contract

Use the public `pkg/protectedfill` SDK and one authority shared across all agent
sessions. `OpenGate` takes an absolute private directory, holds an exclusive
process lock, and persists a blocked latch before value retrieval. Restarting
with that latch blocks observation until trusted orphan-context destruction.

Every screenshot (including automatic screenshots), accessibility/DOM capture,
screen recording, debug trace, browser tool and ordinary input route must pass
through `Gate.Observe`. Results must not be logged, streamed or published outside
that wrapper. The barrier cancels pending capture contexts; stale results are
erased/discarded even if they finish after observations resume. Other tools such
as unrestricted shell/DevTools access must be contained during the protected
phase. Using separate gates per session or ignoring a tool route breaks the
claimed boundary. The extension cannot enforce any of this by itself.

A trusted controller supplies a `Driver` through bootstrap code:

- `Validate`: consume a single-use human authorization bound to record, origin,
  context, document, field and submit action; prove the target belongs to a
  dedicated controller-owned browser context. Resolve opaque extension handles
  inside the extension isolated world. Recheck top frame, current document,
  focus/field/form identity, exact approved destination and HTTPS POST action.
  Validation is pure: rejecting a target must not close arbitrary user tabs.
- `FillAndSubmit`: revalidate at use time, privately insert and submit, honor
  cancellation and avoid logging, returning or retaining values. Only the
  trusted driver receives the mutable value buffer; native response JSON and the
  selection script never receive it.
- `Destroy`: prove **all** pages, popups, pending capture artifacts and the
  isolated context are gone before returning success. Clearing a field, a
  navigation, a success toast, or an extension claim is insufficient. The driver
  must never destroy the user's everyday browser context.
- `DestroyOrphans`: establish the same postcondition after a crashed controller.
  `Coordinator.Recover` is host-only and refuses to interrupt an active operation.

The current computer-use API exposes no documented way to install this global
barrier or a qualified driver. Thus actual controller integration remains a
concrete external blocker. Do not add an extension checkbox or agent-provided
"paused" acknowledgment as a substitute.

## Operation and failure behavior

The state sequence is: ready → durable blocked latch → trusted validation →
retrieve value → private submission attempt → destroy isolated context → resume.
This conservative version destroys its isolated context and does not preserve a
logged-in browser session for subsequent agent work. A qualified authenticated-
session handoff would be separate integration work; do not silently copy browser
state into an observable context.

An invalid target is rejected before value retrieval and must not destroy an
unowned tab. A crash or failed cleanup leaves observations blocked. Only trusted
recovery after context destruction can reopen them. The operation and recovery
share a lock so recovery cannot resume observation during an active fill.

`SUBMISSION_ATTEMPTED_CONTEXT_CLOSED` reports an attempt and verified context
destruction, not authentication success or remote persistence. The other results
are `FAILED_CONTEXT_CLOSED`, `TARGET_REJECTED`, `HOST_PROTECTION_UNAVAILABLE`,
`PROTECTED_OPERATION_BUSY`, and `RECOVERY_REQUIRED`. Driver errors, page text,
values and value hashes never become receipts. Mutable buffers are wiped; this
does not guarantee erasure of immutable strings or all process-memory copies.

## Scope and transport

The first version prepares one password field and one same-origin POST submit.
Arbitrary API-key settings pages, show-once provider capture, OAuth/key creation,
rotation/revocation and Vercel project/environment persistence checks require
separate qualified flows. The SDK is reusable; a source/destination pair does not
need its own duplicated vault or broker.

The protected native protocol carries metadata only. The trusted driver receives
bytes in-process; an out-of-process driver needs its own authenticated encrypted
channel. Provider traffic must use HTTPS. Existing encrypted vault storage/sync
remains unchanged. Values necessarily exist in trusted process/browser memory
and at the destination. Destination scripts and malicious same-user or privileged
code remain outside this boundary. Ordinary human-fill native messaging remains
the existing local private-pipe path; it is not newly claimed to be encrypted
end to end or safe for an observing agent.

## Verification boundaries

Go tests cover barrier-before-retrieval, denied callback routes, late-result
erasure, concurrent operations/recovery, error redaction, value-buffer wiping,
exclusive/private state, failed cleanup and durable blocking after SIGKILL.
Native tests use encrypted disposable fixture records and verify no protected
value response, origin/record binding, legacy refusal and no vault read without
protection. JavaScript tests cover capabilities, downgrade refusal, document/
origin/frame binding, single-use selection and response filtering.

`make e2e-protected-selection` uses the pinned headless test browser and fresh
contexts to exercise the actual DOM selection script. Its metadata-only bridge
fixture does not release a value or integrate a native host. This is not an
installed-extension, Brave or OS screenshot/AX confidentiality test.

Still required before real use: a qualified observation-controlling host and
Driver; disposable-sentinel capture tests through actual screenshots/OCR, AX,
DOM, console/logs, clipboard, traces and indirect captures; navigation and
framework mirrors/echoes; driver/process crashes and concurrent tool sessions;
real Brave extension/native-host acceptance; independent source/security review.
All real secret creation/import/transfer/rotation stays with the owner until
that exact integrated path is approved and qualified.
