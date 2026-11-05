//go:build !envbank_testapprover

package main

import (
	"flag"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBuildHasNoTestApprover(t *testing.T) {
	if registerTestApprover(flag.NewFlagSet("x", flag.ContinueOnError))() != nil {
		t.Fatal("default build returned a test approver")
	}
	err := agentBrokerCommand([]string{"--test-approver-file", filepath.Join(t.TempDir(), "approve")})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("--test-approver-file accepted in the default build: %v", err)
	}
}
