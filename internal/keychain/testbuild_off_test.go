//go:build !envbank_testapprover

package keychain

import "testing"

func TestDefaultBuildUsesServicesAsNamed(t *testing.T) {
	if IsTestBuild() || ServiceName(Service) != Service || ServiceName("x") != "x" {
		t.Fatal("default build rewrote a Keychain service")
	}
}
