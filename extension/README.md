# EnvBank Fill extension

This directory is an unpacked, dependency-free Manifest V3 extension. Build
the Go binary, run `envbank keychain-store`, then run `envbank browser-install`
before loading this directory from `brave://extensions` in developer mode.
Brave is the installer default; use `--browser brave` explicitly when desired.
Explicit Chrome/Chromium targets remain supported for existing installations.
The installer refuses to overwrite existing native-host manifests.

The development public key in `manifest.json` fixes the ID to
`pgbpmecaapiknpejgdkpaifpjcnckcnk`, which is the only extension origin accepted
by the installed native host.

The popup can generate a password directly into a new or existing vault
record. Choose the record name, length, and character classes, then confirm the
exact origin that will be authorized. Existing records show the revision that
will be replaced. Generation happens in the native host; popup JavaScript never
receives the plaintext, and the extension does not reveal, copy, log, or store
it. After storage, the normal 30-second field-selection flow starts. If the tab
navigates before that flow can start, the popup reports that the password is
still stored and authorized.

Run the extension unit tests with:

```sh
node --test test/*.test.js
```

`test/fixture.html` is a local acceptance page containing text, password,
textarea, hidden, file, and iframe targets. Serve this directory over loopback
HTTP; do not open it as a `file:` URL, which is intentionally ineligible.

## Protected computer use

`Protected fill` requires a connected observation-controlling host. The default
standalone native host reports it unavailable; it never turns an agent's pause
claim into permission to release a value. In a qualified controller embedding,
choose a record, the empty password field and its POST submit button. The trusted
host owns validation, private submission and context destruction, returning only
fixed status. Ordinary `Choose` remains human fill and is not agent-safe.

See [the host contract and verification limits](../docs/protected-computer-use.md).
No real credentials should be used until the integrated path is qualified.
