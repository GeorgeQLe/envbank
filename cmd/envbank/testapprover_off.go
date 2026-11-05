//go:build !envbank_testapprover

package main

import (
	"flag"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// registerTestApprover adds nothing in the default build: production
// approvals are always Touch ID (see testapprover_on.go for the disposable
// end-to-end build).
func registerTestApprover(*flag.FlagSet) func() approval.Approver {
	return func() approval.Approver { return nil }
}
