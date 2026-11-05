//go:build envbank_testapprover

package client

// testBuild is true in the disposable test-approver build: every config it
// creates is marked as a test vault, and it refuses to load any config
// without that marker (see TestVaultMarker).
const testBuild = true
