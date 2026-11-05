//go:build envbank_testapprover

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

// testBuildRefused is the fixed refusal of the test-approver build.
const testBuildRefused = "TEST_APPROVER_BUILD_REFUSED"

// testBuildGuard keeps a test-approver binary away from anything real: it
// never uses Chromux or any XPC agent channel (only the terminal and the
// development socket), and it only opens device configs under TMPDIR, so a
// real vault cannot be unlocked with file-answered approvals.
func testBuildGuard(ownerInput, configPath string) error {
	if ownerInput != "terminal" {
		return errors.New(testBuildRefused + ": a test-approver build never uses --owner-input chromux or any XPC agent channel")
	}
	if !underTempDir(configPath) {
		return errors.New(testBuildRefused + ": a test-approver build only opens device configs under TMPDIR (disposable vaults)")
	}
	return nil
}

// underTempDir reports whether path resolves inside the (resolved) TMPDIR,
// which must itself be a dedicated directory: not /, the home directory or
// an ancestor of the real default config.
func underTempDir(path string) bool {
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil || !filepath.IsAbs(tmp) || tmp == string(filepath.Separator) {
		return false
	}
	if home, err := os.UserHomeDir(); err == nil {
		if h, err := filepath.EvalSymlinks(home); err == nil && within(h, tmp) {
			return false // TMPDIR is the home directory or above it
		}
	}
	if def := resolvedPath(defaultConfigPath()); def != "" && within(def, tmp) {
		return false
	}
	p := resolvedPath(path)
	return p != "" && p != tmp && within(p, tmp)
}

// resolvedPath makes path absolute and resolves symlinks in its longest
// existing prefix.
func resolvedPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	rest := ""
	for dir := abs; ; dir = filepath.Dir(dir) {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
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
