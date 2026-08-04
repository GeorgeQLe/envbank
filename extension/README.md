# EnvBank Fill extension

This directory is an unpacked, dependency-free Manifest V3 extension. Build
the Go binary, run `envbank keychain-store`, then run `envbank browser-install`
before loading this directory from `chrome://extensions` in developer mode.

The development public key in `manifest.json` fixes the ID to
`pgbpmecaapiknpejgdkpaifpjcnckcnk`, which is the only extension origin accepted
by the installed native host.

Run the extension unit tests with:

```sh
node --test test/*.test.js
```

`test/fixture.html` is a local acceptance page containing text, password,
textarea, hidden, file, and iframe targets. Serve this directory over loopback
HTTP; do not open it as a `file:` URL, which is intentionally ineligible.
