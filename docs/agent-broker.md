# Agent broker: secrets for coding agents without revealing them

Status (November 4, 2026): **implemented, independently security-reviewed, and
tested end to end against a disposable local server and vault. Not yet used
with an owner's real vault.** Mode: owner-approved commands with output
redaction. The placeholder egress proxy, the planned stronger mode for HTTP
API keys, is not built yet.

Coding agents (Claude Code, Codex and similar) need to *use* API keys, for
example to deploy or call a provider. They should never *read* them. The
ordinary CLI cannot be handed to an agent: `envbank get` prints values, and
`envbank run` injects every record into any command. The agent broker splits
custody so that the agent never holds the vault passphrase and has no
operation that returns a value.

## How it works

```
 owner terminal                          agent (same user)
 ┌────────────────────────────┐          ┌──────────────────────────────┐
 │ envbank agent-broker       │◀─socket──│ envbank mcp serve  (MCP)     │
 │  unlocked by the owner     │  0600    │ envbank agent ...  (CLI)     │
 │  approvals + secret entry  │          │  no passphrase, no vault key │
 │  spawns approved commands  │          └──────────────────────────────┘
 └────────────────────────────┘
```

The owner starts `envbank agent-broker` in their own terminal and types the
vault passphrase there. The broker listens on
`~/.envbank/agent-broker/broker.sock`, in a 0700 directory, with a 0600 socket
and a peer-uid check. It locks (exits and wipes the vault key) after 30 minutes
idle or 12 hours total, or on Ctrl-C.

Agents get four operations, through `envbank mcp serve` or the
`envbank agent` CLI:

| MCP tool / CLI | What the agent gets |
| --- | --- |
| `envbank_secret_names` / `envbank agent names` | Secret **names** only. |
| `envbank_secret_request` / `envbank agent request --reason TEXT NAME` | The owner is prompted in the broker terminal. The owner types the value twice, with no echo (replacing an existing secret needs a separate yes). The agent receives `stored` or `denied`. |
| `envbank_secret_relay_request` / `envbank agent relay-request --name NAME --reason TEXT` | The owner picks another enrolled device, compares a relay code and types the value there with `envbank relay send`; it arrives sealed to the broker ([cross-device relay](cross-device-relay.md)). The agent receives `stored`, `denied` or `expired`. |
| `envbank_secret_run` / `envbank agent run --secret NAME -- CMD ARGS` | The owner approves the exact command: **once**, **always for this exact command**, or **no**. The broker spawns it with only the named secrets plus a minimal environment. The agent receives exit code, stdout and stderr with values redacted. |

There is no get, set, export or raw tool.

## Guarantees (tested in `internal/agentbroker`)

- **No value in any response.** Every response type is value-free. Errors are
  fixed codes and never echo caller input or vault details.
- **Owner-only ingest.** Values are typed into the broker terminal with no
  echo and entered twice. Agent-supplied names and reasons are validated and
  sanitized: control characters, `ESC`/OSC/CSI sequences and bidi overrides
  are rendered as escapes, so an agent cannot spoof the prompt. Values must be
  8 bytes to 64 KiB.
- **Exact-command approval.** Before prompting, the broker resolves the command:
  - the executable to an absolute real path, using the **broker's** PATH and
    never `.` or relative entries;
  - the working directory, which must be absolute;
  - the set of secret names.

  The prompt shows each part **in full**, with nothing truncated:
  - the executable and its SHA-256;
  - any shebang interpreter and its SHA-256;
  - every argument on its own numbered line with its byte length. Runs of
    spaces are shown as `\x{20}×N`, so padding cannot push a payload out of
    view. Commands too long to show in full (over 8 KiB) are refused.
  - every argument that names an existing file (for example `deploy.py`),
    with its SHA-256.

  All of these form the approval key. Immediately before execution the
  broker re-resolves and re-hashes everything; if anything changed since
  approval (edited script, swapped binary, changed argument, directory or
  secrets), the run is refused.

  **"Always" is offered only for fixed programs.** It is never offered for
  commands that run project code: shells, interpreters, package managers,
  `git`, shebang scripts, or file arguments inside the working directory. It
  is also not offered when the executable is inside the working directory.
  Those are approved one run at a time. "Always" approvals are memory-only.
- **Refused outright, with no prompt:**
  - environment dumpers: `env`, `printenv`;
  - wrappers that run whatever follows them: `timeout`, `nice`, `time`,
    `stdbuf`, `caffeinate`, `xargs`, `nohup`, `busybox`, `ssh`, `open`,
    `launchctl` and others;
  - editors and filters that execute or print from arguments: `vim -c`,
    `jq`, `sed`;
  - privilege escalation and debuggers: `sudo`, `su`, `doas`, `lldb`, `gdb`;
  - inline code, including combined short-flag clusters: `sh`/`bash -c`,
    `python -c`/`-Ic`, `node -e/-p/--require/--import`, `perl -e/-E/-M`,
    `ruby -e/-r`, `php -r`, `osascript -e`, `awk`;
  - `git -c` / `--config-env`, and `find -exec`;
  - shebang lines that use `env -S` or a refused interpreter;
  - unknown secrets, and secrets shorter than 8 bytes (checked again at
    execution time), which cannot be redacted safely.

  An agent therefore cannot ask the owner to approve arbitrary code typed into
  the request.
- **Child isolation.** The broker, not the agent, spawns the process:
  - no shell;
  - stdin from `/dev/null`;
  - its own process group, killed as a whole on timeout (default 2 minutes,
    maximum 30) and after exit, so an ordinary backgrounded child cannot
    outlive the run. A child that calls `setsid` to leave the group can
    (residual risk);
  - environment of only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`,
    `TMPDIR`, `TERM=dumb` plus the named secrets. The agent's environment and
    `ENVBANK_*` variables are never passed.
- **Redaction.** Before output is returned, every injected value is replaced
  with `[REDACTED:NAME]`, along with:
  - its standard and URL-safe base64 (padded and unpadded);
  - lower and upper hex;
  - query and path escaping, and JSON escaping;
  - all of the above for the trimmed value;
  - for multi-line values, LF and CRLF forms and each line on its own.

  Matching is span-based over the original output, so overlapping secrets
  leave no fragments. Output is captured up to 4 MiB per stream and returned
  up to 256 KiB. If the capture limit splits a value, the trailing fragment of
  any length is removed.
- **Bounded owner channel.** One prompt at a time, a queue of 4, and the rest
  are `BROKER_BUSY`. A request whose agent hangs up while queued is never
  shown to the owner.

## Residual risks (read before approving)

- **An approved command receives the values.** If it runs code an agent can
  edit (`npm run`, `make`, repository scripts, `python script.py`), that code
  can exfiltrate them over the network, to a file, or encoded in a way
  redaction misses (reversed, encrypted, hashed, Unicode-renormalized). The
  edit-after-approval check narrows but does not eliminate this: an agent can
  edit files the approved program reads that are not arguments (imports,
  configs), and a small race remains between the final check and exec. The
  prompt warns when
  a command runs project code or the executable is inside the working
  directory. Prefer fixed binaries (`vercel`, `gh`, `curl` with fixed
  arguments) over project scripts.
- **Same-user processes.** The agent runs as you, so it can read the broker
  terminal's screen (computer use), connect to the socket (it can only make
  requests), and, where developer tools allow debugging same-user processes,
  inspect broker memory. Keep developer-mode debugging restricted.
- **Computer-use agents can drive the broker terminal.** An agent with
  screen and keyboard control (computer use, Accessibility) can read the
  broker terminal and **type into it**: approve a run, or answer a setup
  prompt with a passphrase it chose. While the broker is running, do not
  give agents computer use or Accessibility access, or keep the broker on a
  display or Space they are not driving. Setup mode is opt-in
  (`--setup`) for this reason.
- **Passphrase custody.** If the agent can read a passphrase file or
  `ENVBANK_PASSPHRASE`, it can unlock the vault itself and bypass the broker.
  The broker prompts for the passphrase when neither is set; do not keep a
  passphrase file where agent sessions can read it.
- **Not a sandbox.** This narrows what an agent can see; it does not contain a
  malicious approved program. The planned placeholder egress proxy keeps
  values out of every agent-reachable process for HTTP API keys.

## Setup

1. In **your own terminal** (not the agent's):

   ```sh
   envbank agent-broker            # prompts for the vault passphrase
   ```

2. Give the agent the MCP server, which needs no passphrase. For Claude Code:

   ```sh
   claude mcp add envbank -- envbank mcp serve
   ```

   For Codex, add an `[mcp_servers.envbank]` entry with
   `command = "envbank"` and `args = ["mcp", "serve"]`. Or let the agent use
   the CLI: `envbank agent names`, `envbank agent run --secret VERCEL_TOKEN -- vercel deploy`.

3. Approve or deny requests as they appear in the broker terminal. Long
   approvals can exceed an MCP client's tool timeout; raise it, for example
   with `MCP_TOOL_TIMEOUT` in Claude Code.

`envbank mcp serve --no-agent-broker` omits the secret tools.

## Not done

- Use with an owner's real vault. Unit tests use a fake vault, with real
  command execution, a real socket, the real MCP server and the real terminal
  prompter. A disposable end-to-end run used the real binary, a loopback
  `envbank serve`, a throwaway vault and a pseudo-terminal for the owner's
  typing. It passed 15 checks:
  - only names are listed;
  - the approval prompt shows the file hash;
  - the run's output is redacted, with no raw or base64 value;
  - `printenv` is refused without a prompt;
  - ingest stores the typed value, and the agent learns only `stored`;
  - nothing typed is echoed;
  - Ctrl-C locks the broker and removes the socket;
  - the agent fails closed afterwards.
- Placeholder egress proxy mode (next).
- Persistent approval policy, multi-line values through the broker prompt
  (use `envbank set` with stdin for those), and non-terminal approval
  channels (macOS dialog, phone approval).
