package main

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	originalVersion, originalCommit, originalBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = originalVersion, originalCommit, originalBuildDate
	})
	version, commit, buildDate = "v0.2.0", "abc123", "2026-08-10T12:00:00Z"

	var output bytes.Buffer
	originalStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	t.Cleanup(func() { os.Stdout = originalStdout })

	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(output.String()), "envbank v0.2.0 (commit abc123, built 2026-08-10T12:00:00Z)"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
	if err := run([]string{"version", "extra"}); err == nil {
		t.Fatal("version accepted an argument")
	}
}

func TestHTTPServerSecurityLimits(t *testing.T) {
	httpServer := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if httpServer.MaxHeaderBytes != 16<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", httpServer.MaxHeaderBytes, 16<<10)
	}
	if httpServer.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 5s", httpServer.ReadHeaderTimeout)
	}
}

func TestWritePrivateFileExclusiveRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-host.json")
	if err := writePrivateFileExclusive(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileExclusive(path, []byte("replacement")); err == nil {
		t.Fatal("exclusive write overwrote an existing native-host manifest")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "original"; got != want {
		t.Fatalf("existing contents = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("exclusive file mode = %o, want 600", got)
	}
}

func TestBrowserManifestPathTargets(t *testing.T) {
	for browser, suffix := range map[string]string{
		"google-chrome":      filepath.Join("Google", "Chrome", "NativeMessagingHosts", "com.envbank.native.json"),
		"chrome-for-testing": filepath.Join("Google", "Chrome for Testing", "NativeMessagingHosts", "com.envbank.native.json"),
		"chromium":           filepath.Join("Chromium", "NativeMessagingHosts", "com.envbank.native.json"),
	} {
		path, err := browserManifestPath(browser)
		if err != nil {
			t.Fatalf("browserManifestPath(%q): %v", browser, err)
		}
		if !strings.HasSuffix(path, suffix) {
			t.Fatalf("browserManifestPath(%q) = %q, want suffix %q", browser, path, suffix)
		}
	}
	if _, err := browserManifestPath("safari"); err == nil {
		t.Fatal("unsupported browser target was accepted")
	}
}

func TestBrowserManifestPathForProfile(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "isolated", "profile")
	path, err := browserManifestPathForProfile("chrome-for-testing", profile)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(profile, "NativeMessagingHosts", "com.envbank.native.json")
	if path != want {
		t.Fatalf("profile manifest path = %q, want %q", path, want)
	}

	relative := filepath.Join("testdata", "..", "profile")
	path, err = browserManifestPathForProfile("chromium", relative)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		t.Fatalf("relative profile path was not cleaned and made absolute: %q", path)
	}

	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := browserManifestPathForProfile("google-chrome", filePath); err == nil {
		t.Fatal("file profile path was accepted")
	}
	if _, err := browserManifestPathForProfile("safari", profile); err == nil {
		t.Fatal("unsupported browser target was accepted with a profile directory")
	}
}

func TestBrowserInstallationSupportIsIsolatedByManifest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := browserInstallationPathsForProfile("google-chrome", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := browserInstallationPathsForProfile("chrome-for-testing", filepath.Join(t.TempDir(), "profile"))
	if err != nil {
		t.Fatal(err)
	}
	if first.manifest == second.manifest || first.directory == second.directory || first.binary == second.binary || first.locator == second.locator {
		t.Fatalf("browser installations shared support state: first=%+v second=%+v", first, second)
	}
	for _, installation := range []browserInstallationPaths{first, second} {
		if filepath.Dir(installation.binary) != installation.directory || filepath.Dir(installation.locator) != installation.directory {
			t.Fatalf("support artifacts escaped installation directory: %+v", installation)
		}
		if got := browserLocatorPathForExecutable(installation.binary); got != installation.locator {
			t.Fatalf("native host locator = %q, want %q", got, installation.locator)
		}
	}
}

func TestBrowserInstallationPathsValidateTargetBeforeUse(t *testing.T) {
	profileFile := filepath.Join(t.TempDir(), "profile-file")
	if err := os.WriteFile(profileFile, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := browserInstallationPathsForProfile("google-chrome", profileFile); err == nil {
		t.Fatal("file profile path was accepted")
	}
	if _, err := browserInstallationPathsForProfile("unsupported", ""); err == nil {
		t.Fatal("unsupported browser target was accepted")
	}
}

func TestBundleCheck(t *testing.T) {
	manifest := `version: 1
bundle: example/siftcut/staging
policies:
  password:
    type: password
    length: 32
    lowercase: true
records:
  DATABASE_PASSWORD:
    source: generate
    policy: password
targets:
  railway:
    project: siftcut-staging
    environment: staging
    services:
      api:
        order: 1
        variables:
          DATABASE_PASSWORD: {source: record, record: DATABASE_PASSWORD}
`
	path := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = write
	t.Cleanup(func() { os.Stdout = originalStdout })
	if err := run([]string{"bundle", "check", "--manifest", path}); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, safe := range []string{
		"bundle: example/siftcut/staging\n",
		"manifest digest: ",
		"records: 1\n",
		"targets: railway\n",
		"status: valid\n",
	} {
		if !strings.Contains(got, safe) {
			t.Fatalf("output %q does not contain %q", got, safe)
		}
	}
	for _, prohibited := range []string{"DATABASE_PASSWORD", "password", "siftcut-staging"} {
		if strings.Contains(got, prohibited) {
			t.Fatalf("output contains manifest detail %q: %s", prohibited, got)
		}
	}
}

func TestServeSIGTERMGracefulShutdown(t *testing.T) {
	if os.Getenv("ENVBANK_SERVE_SIGNAL_HELPER") == "1" {
		ctx, stop := shutdownSignalContext()
		defer stop()
		ready := os.Getenv("ENVBANK_SERVE_SIGNAL_READY")
		if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		httpServer := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
		listen := func() error {
			<-ctx.Done()
			return http.ErrServerClosed
		}
		if err := runHTTPServer(ctx, httpServer, listen); err != nil {
			t.Fatal(err)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(executable, "-test.run=^TestServeSIGTERMGracefulShutdown$")
	command.Env = append(os.Environ(),
		"ENVBANK_SERVE_SIGNAL_HELPER=1",
		"ENVBANK_SERVE_SIGNAL_READY="+ready,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatalf("server did not start: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("server did not exit successfully after SIGTERM: %v\n%s", err, output.String())
	}
}
