//go:build envbank_testapprover

package keychain

import (
	"strings"
	"testing"
)

func TestTestBuildUsesASeparateKeychainService(t *testing.T) {
	if !IsTestBuild() {
		t.Fatal("tagged build does not know it is a test build")
	}
	for _, s := range []string{Service, "railway", ""} {
		got := ServiceName(s)
		if got == s || !strings.HasPrefix(got, TestService+"/") {
			t.Fatalf("%q -> %q: production service reachable from a test build", s, got)
		}
	}
}
