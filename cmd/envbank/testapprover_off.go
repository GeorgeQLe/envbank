//go:build !envbank_testapprover

package main

import (
	"flag"

	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
)

// registerTestApprover adds nothing in the default build: production
// approvals are always Touch ID (see testapprover_on.go for the disposable
// end-to-end build).
func registerTestApprover(*flag.FlagSet) func() approval.Approver {
	return func() approval.Approver { return nil }
}

// ownerInputIdentifier is the code-signing identifier the broker expects of
// the owner-input XPC service by default.
const ownerInputIdentifier = ownerinput.ServiceIdentifier

// testBuildGuard restricts nothing in the default build.
func testBuildGuard(string, string, string) error { return nil }
