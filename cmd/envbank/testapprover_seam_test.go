package main

import (
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Source/build check of the test-approver seam: the default build compiles
// testapprover_off.go and not testapprover_on.go, only the tagged build adds
// the seam, and no other file of the command mentions it.
func TestTestApproverSeamExistsOnlyInTheTaggedBuild(t *testing.T) {
	def, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	tagged := build.Default
	tagged.BuildTags = append(slices.Clone(tagged.BuildTags), "envbank_testapprover")
	tag, err := tagged.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(def.GoFiles, "testapprover_on.go") || !slices.Contains(def.GoFiles, "testapprover_off.go") {
		t.Fatalf("default build files: %v", def.GoFiles)
	}
	if !slices.Contains(tag.GoFiles, "testapprover_on.go") || slices.Contains(tag.GoFiles, "testapprover_off.go") {
		t.Fatalf("tagged build files: %v", tag.GoFiles)
	}
	for _, f := range def.GoFiles {
		raw, err := os.ReadFile(filepath.Join(".", f))
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, seam := range []string{"test-approver-file", "fileApprover", "envbank_testapprover"} {
			if strings.Contains(src, seam) && f != "testapprover_off.go" {
				t.Fatalf("%s (default build) mentions %q", f, seam)
			}
		}
	}
	on, err := os.ReadFile("testapprover_on.go")
	if err != nil || !strings.HasPrefix(string(on), "//go:build envbank_testapprover\n") ||
		!strings.Contains(string(on), `ownerInput != "terminal"`) || !strings.Contains(string(on), "underTempDir(configPath)") {
		t.Fatal("testapprover_on.go is not tag-gated or lacks the chromux/TMPDIR guard")
	}
}
