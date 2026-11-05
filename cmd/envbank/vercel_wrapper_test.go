package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the interactive wrapper with a synthetic PTY and helper only.
// It must preserve the selected helper identity and never invoke go build.
func TestVercelAcceptanceWrapperUsesSelectedHelperWithoutRebuilding(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS script(1) PTY contract; provider commands are covered separately")
	}
	scriptTool, e := exec.LookPath("script")
	if e != nil {
		t.Fatal("PTY test tool unavailable")
	}
	wrapper, e := filepath.Abs(filepath.Join("..", "..", "scripts", "e2e-live.sh"))
	if e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	helper := filepath.Join(directory, "selected helper")
	fakeGo := filepath.Join(directory, "go")
	marker := filepath.Join(directory, "unexpected-build")
	helperSource := `#!/bin/sh
[ "$1" = vercel ] && [ "$2" = "$ENVBANK_TEST_EXPECT_MODE" ] || exit 93
printf '%s\n' '{"result":"PASS","acceptance_level":"synthetic-wrapper-only","full_workflow":"not-qualified"}'
`
	if e = os.WriteFile(helper, []byte(helperSource), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(fakeGo, []byte("#!/bin/sh\ntouch \"$ENVBANK_TEST_GO_MARKER\"\nexit 94\n"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []struct {
		name, provider, target, cli, expect, mode string
		pass                                      bool
	}{
		{"missing-helper", "vercel", "disposable:team_fixture/prj_fixture/envbank-acceptance-run@envbank-acceptance-run", "", "TRUSTED_CLI_REQUIRED", "accept", false},
		{"relative-helper", "vercel", "disposable:team_fixture/prj_fixture/envbank-acceptance-run@envbank-acceptance-run", "relative-helper", "TRUSTED_CLI_REQUIRED", "accept", false},
		{"preview", "vercel", "disposable:team_fixture/prj_fixture/envbank-acceptance-run@envbank-acceptance-run", helper, `"result":"PASS"`, "accept", true},
		{"production", "vercel-production", "disposable-production:team_fixture/prj_fixture/envbank-acceptance-run", helper, `"result":"PASS"`, "accept-production", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			// These are fixture paths and public IDs, not any real credential/config.
			t.Setenv("ENVBANK_LIVE_ACCEPTANCE", "1")
			t.Setenv("ENVBANK_VERCEL_ACCEPTANCE_TARGET", scenario.target)
			t.Setenv("VERCEL_ACCEPTANCE_CLI", scenario.cli)
			t.Setenv("VERCEL_ACCEPTANCE_MANIFEST", filepath.Join(directory, "fixture.yaml"))
			t.Setenv("VERCEL_ACCEPTANCE_CONFIG", filepath.Join(directory, "fake-config.json"))
			t.Setenv("VERCEL_ACCEPTANCE_PASSPHRASE_FILE", filepath.Join(directory, "fake-passphrase"))
			t.Setenv("VERCEL_ACCEPTANCE_PLAN", strings.Repeat("a", 64))
			t.Setenv("ENVBANK_TEST_EXPECT_MODE", scenario.mode)
			t.Setenv("ENVBANK_TEST_GO_MARKER", marker)
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			for _, name := range append([]string{"STRIPE_SECRET_KEY", "STRIPE_API_KEY", "RAILWAY_TOKEN", "RAILWAY_API_TOKEN", "CLOUDFLARE_API_TOKEN", "CLERK_SECRET_KEY", "CLERK_API_KEY"}, vercelAcceptanceForbiddenEnvironment...) {
				t.Setenv(name, "")
			}
			command := exec.Command(scriptTool, "-q", "/dev/null", "/bin/bash", wrapper, scenario.provider)
			command.Stdin = strings.NewReader("")
			output, err := command.CombinedOutput()
			if (err == nil) != scenario.pass || !strings.Contains(string(output), scenario.expect) {
				t.Fatal("wrapper violated trusted-helper/refusal contract; diagnostics withheld")
			}
			if _, err = os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("wrapper rebuilt a different helper identity")
			}
		})
	}
}
