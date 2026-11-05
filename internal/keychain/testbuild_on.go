//go:build envbank_testapprover

package keychain

// testBuild is true in the disposable test-approver build: every Keychain
// service is moved under TestService (see ServiceName), so such a binary can
// never read, overwrite or delete production Keychain items.
const testBuild = true
