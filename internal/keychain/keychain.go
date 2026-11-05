package keychain

import "errors"

const Service = "com.envbank.native"

// TestService is the separate Keychain service namespace of a binary built
// with the test-approver tag. Production items are never under it.
const TestService = "com.georgeqle.envbank.testapprover"

// ServiceName is the Keychain service SystemStore actually uses for service:
// service itself in the default build, and service moved under TestService
// in a test-approver build, so a tagged build can never unlock or reuse
// production Keychain material.
func ServiceName(service string) string {
	if testBuild {
		return TestService + "/" + service
	}
	return service
}

// IsTestBuild reports whether this is a test-approver build.
func IsTestBuild() bool { return testBuild }

var ErrNotFound = errors.New("keychain item not found")

type Store interface {
	Put(service, account string, secret []byte) error
	Get(service, account, prompt string) ([]byte, error)
	Delete(service, account string) error
}

type SystemStore struct{}
