# Private provider intake

`envbank bundle prepare-exec` lets a trusted local password-manager or provider
program supply missing bundle imports without exposing its stdout to an
operator terminal, Computer Use, or EnvBank command output.

```sh
envbank bundle prepare-exec \
  --manifest /secure/project/staging.envbank.yaml \
  --config /secure/envbank/device.json \
  --passphrase-file /secure/envbank/passphrase \
  -- /absolute/path/to/trusted-source --non-secret locator
```

The source must write exactly the same bounded JSON object accepted by
`bundle prepare`. EnvBank starts it directly, without a shell, with no stdin.
Its stdout is an EnvBank-owned private pipe; stderr is discarded because
third-party diagnostics can contain values. EnvBank removes every
`ENVBANK_*` variable before starting the source, requires an explicit
passphrase file, validates the complete payload before storage, and wipes
temporary byte buffers where Go permits. Source arguments are visible to the
operating system and must contain identifiers or locators only, never values.

Only use audited, absolute-path executables. The source inherits the rest of
the caller environment because password-manager and provider CLIs may keep
their own authenticated session references there. A malicious source remains
able to read that inherited environment, contact the network, and return
incorrect values. This command narrows secret presentation; it does not make
an untrusted source safe.

## Clerk helper on macOS

Build both programs with cgo enabled so macOS Keychain user-presence controls
are available:

```sh
go build -o envbank ./cmd/envbank
go build -o envbank-provider-clerk ./cmd/envbank-provider-clerk
```

Install Clerk's official CLI and authenticate it outside Computer Use. Clerk's
browser login does not reveal an application key to the terminal:

```sh
clerk auth login
clerk whoami
```

Clerk currently exposes application publishable and secret keys through
`clerk env pull`, but documents webhook signing-secret retrieval through the
Dashboard. Seed that one dashboard-only value once through the helper's hidden
terminal prompt. The helper stores it in a `ThisDeviceOnly`, user-presence
protected Keychain item under a hashed account identifier:

```sh
envbank-provider-clerk webhook-store \
  --app app_example \
  --instance ins_example \
  --authorized-party https://staging.example.com
```

Then prepare the bundle without a plaintext `.env` file:

```sh
envbank bundle prepare-exec \
  --manifest /secure/project/staging.envbank.yaml \
  --config /secure/envbank/device.json \
  --passphrase-file /secure/envbank/passphrase \
  -- /absolute/path/envbank-provider-clerk export \
     --clerk /absolute/path/clerk \
     --app app_example \
     --instance ins_example \
     --authorized-party https://staging.example.com
```

The helper refuses to export to a terminal. It asks Keychain for the webhook
secret, directs `clerk env pull` to `/dev/stdout` captured inside the helper,
parses the two Clerk keys, derives the public issuer from the publishable key,
and emits the five-field JSON only into EnvBank's private pipe. Computer Use
may safely start this final command and observe its names-only status, but it
must not enter or view the webhook secret during `webhook-store`.

The plaintext necessarily exists briefly in the Clerk CLI, helper, EnvBank
client, and OS process memory. This design avoids UI capture, clipboard,
command arguments, shell history, terminal rendering, and named plaintext
files; it does not provide an HSM boundary or protection from a compromised
endpoint, provider CLI, debugger, crash dump, or privileged process inspector.
