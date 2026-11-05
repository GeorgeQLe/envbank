package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/check-sign-target.sh refuses binaries built with the
// test-approver tag (alone or among others), refuses files without Go build
// information, and accepts a default build.
func TestCheckSignTargetRefusesTestApproverBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "check-sign-target.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(name string, args ...string) string {
		out := filepath.Join(dir, name)
		cmd := exec.Command("go", append(append([]string{"build", "-o", out}, args...), src)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, b)
		}
		return out
	}
	check := func(path string) (string, bool) {
		b, err := exec.Command("/bin/sh", script, path).CombinedOutput()
		return string(b), err == nil
	}
	notGo := filepath.Join(dir, "plain")
	if err := os.WriteFile(notGo, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		ok   bool
	}{
		"default":        {build("default"), true},
		"other tag":      {build("other", "-tags", "netgo"), true},
		"test tag":       {build("tagged", "-tags", "envbank_testapprover"), false},
		"test tag among": {build("among", "-tags", "netgo,envbank_testapprover"), false},
		"not go":         {notGo, false},
		"missing":        {filepath.Join(dir, "absent"), false},
	} {
		out, ok := check(tc.path)
		if ok != tc.ok || (!ok && !strings.Contains(out, "REFUSED")) {
			t.Fatalf("%s: ok=%v\n%s", name, ok, out)
		}
	}
	if _, ok := check(""); ok {
		t.Fatal("empty argument accepted")
	}
}
