//go:build envbank_testapprover

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

// TEST-ONLY BUILD (-tags envbank_testapprover). This file is not compiled
// into the default binary. It adds --test-approver-file so disposable
// end-to-end runs can answer approvals without a fingerprint. Never use such
// a binary with a real vault.
func registerTestApprover(fs *flag.FlagSet) func() approval.Approver {
	path := fs.String("test-approver-file", "", "TEST BUILD ONLY: file whose content (approve, deny or unavailable) answers every approval")
	return func() approval.Approver {
		if *path == "" {
			return nil
		}
		fmt.Println("WARNING: TEST APPROVER BUILD: approvals are read from " + *path + ", not Touch ID. Disposable vaults only.")
		return fileApprover{path: *path}
	}
}

// fileApprover reads its answer from a file at every approval and prints
// the reason it would have shown.
type fileApprover struct{ path string }

func (f fileApprover) answer() string {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return "deny"
	}
	return strings.TrimSpace(string(raw))
}

func (f fileApprover) Available() bool { return f.answer() != "unavailable" }

func (f fileApprover) Approve(ctx context.Context, reason string) approval.Outcome {
	fmt.Println("  [test approver] reason: " + approval.Clean(reason, approval.MaxReasonBytes))
	if ctx.Err() != nil {
		return approval.Denied
	}
	switch f.answer() {
	case "approve":
		return approval.Approved
	case "unavailable":
		return approval.Unavailable
	default:
		return approval.Denied
	}
}
