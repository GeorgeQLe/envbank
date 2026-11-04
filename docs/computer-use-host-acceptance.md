# External computer-use host: integration and acceptance checklist

Status (November 4, 2026): **not integrated, fail-closed.** The installed
computer-use (CUA) tool API documents no global observation barrier and no
Driver registration hook. EnvBank does not invent one, and no browser
extension can hide native screenshots, accessibility trees or OS capture. No
new in-repo component was added: a controller-side "barrier" built here would
be another simulation, because EnvBank does not own the routes listed below.

What exists in this repository is only the embedding contract:
`pkg/protectedfill` (`Gate`, `Driver`, `Coordinator`) and
`pkg/computeruse.NewNativeHost`. Without a host-supplied `Gate` **and**
`Driver`, every value-releasing or credential-mutating action is refused before
the config or Keychain is opened (`HOST_PROTECTION_UNAVAILABLE`). This is
proven by `pkg/computeruse/host_test.go`,
`internal/nativehost/protected_test.go` and `pkg/protectedfill/operation_test.go`.
Those are isolated tests, not external acceptance.

## Ownership the host must prove

The host vendor (not EnvBank, not the agent) must own and document each route,
and route it through ONE shared `Gate.Observe` for all sessions:

| Route | Owner must provide | Evidence required |
| --- | --- | --- |
| Screenshots (explicit and automatic, thumbnails, previews) | Capture call site wrapped by `Gate.Observe`; no pre-barrier cache | Sentinel never appears in any image/OCR during or after the protected phase |
| Screen recording / video / streaming | Paused and segment discarded across the barrier | Recorded artifacts free of sentinel |
| Accessibility tree / AX queries | AX reads wrapped; no AX snapshot cache | AX dumps free of sentinel; field value never exposed |
| DOM / CDP / page scripts | Controller-owned isolated browser context; no DOM read/eval during protected phase; DevTools closed | DOM, console and network logs free of sentinel |
| Clipboard / pasteboard | Never used for value transfer; clipboard reads wrapped | Pasteboard history unchanged |
| Logs, traces, crash reports, telemetry | Value-bearing buffers excluded; tool results not logged outside the wrapper | Log/trace grep free of sentinel |
| Delayed callbacks / late results | Captures started before the barrier are cancelled and discarded (`epoch`) | Late-result test against the real capture pipeline |
| Parallel agents / sessions / sub-agents | Single process-wide authority (`OpenGate` lock) shared by every session | Concurrent session cannot observe during protected phase |
| Input tools (click/type/keys) | Wrapped by the same Gate; blocked during the protected phase | No agent input reaches the isolated context mid-fill |
| Shell / file / process inspection | Contained or disabled during the phase | Documented sandbox boundary |
| Driver (`Validate`, `FillAndSubmit`, `Destroy`, `DestroyOrphans`) | Single-use human authorization bound to record/origin/context/document/field/submit; proof all pages/popups/artifacts destroyed | Crash/kill tests leave the durable latch blocked until trusted recovery |

## Acceptance procedure (owner + host vendor)

1. Obtain written host API documentation for the barrier and Driver hook. If
   it does not exist, stop: the blocker remains.
2. Wire `protectedfill.OpenGate` (private absolute directory) and a reviewed
   `Driver` in the host's own bootstrap, then `computeruse.NewNativeHost`.
3. Use a disposable fake site and a random disposable sentinel record (never a
   real credential). Exercise every route above during and after a protected
   fill, including forced late captures, parallel sessions, driver crash and
   SIGKILL of the host.
4. Scan every artifact (images via OCR, AX dumps, DOM/HAR, clipboard history,
   logs, traces, crash reports) for the sentinel. Any hit fails acceptance.
5. Independent source/security review of the host integration and Driver.
6. Only then may show-once provider key capture be designed as a separate,
   separately approved flow.

Until all steps pass, protected filling and browser capture of provider keys
stay unavailable, and the Vercel REST path remains the only supported route.
