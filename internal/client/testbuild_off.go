//go:build !envbank_testapprover

package client

// testBuild is false in the default build: configs carry no test marker and
// none is required.
const testBuild = false
