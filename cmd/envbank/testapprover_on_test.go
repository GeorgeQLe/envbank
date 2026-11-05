//go:build envbank_testapprover

package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/approval"
)

func TestFileApproverAnswersFromItsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answer")
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	get := registerTestApprover(fs)
	if get() != nil {
		t.Fatal("approver without the flag")
	}
	if err := fs.Parse([]string{"--test-approver-file", path}); err != nil {
		t.Fatal(err)
	}
	a := get()
	for content, want := range map[string]approval.Outcome{"approve\n": approval.Approved, "deny": approval.Denied, "unavailable": approval.Unavailable, "y": approval.Denied} {
		_ = os.WriteFile(path, []byte(content), 0o600)
		if got := a.Approve(context.Background(), "test"); got != want {
			t.Fatalf("%q: %v", content, got)
		}
	}
	_ = os.Remove(path)
	if a.Approve(context.Background(), "test") != approval.Denied {
		t.Fatal("missing file must deny")
	}
}
