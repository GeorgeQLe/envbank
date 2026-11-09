package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/nativehost"
)

func TestBrowserBootstrapDefaultsToRefusalWithoutController(t *testing.T) {
	if err := runNativeHost([]string{"--human-fill"}); err == nil || err.Error() != "direct human-fill mode requires an explicit --config path" {
		t.Fatal("direct human selection without config was silently ignored")
	}
	host := browserNativeHost(filepath.Join(t.TempDir(), "missing-config"), false)
	status, _ := host.Handle(nativehost.Request{Version: 1, ID: "status", Action: "protected_status"})
	raw, _ := json.Marshal(status)
	if !strings.Contains(string(raw), `"computer_use":true`) || !strings.Contains(string(raw), `"available":false`) {
		t.Fatal("default host did not report unavailable computer-use mode")
	}
	for _, action := range []string{"get_for_fill", "generate_password", "allow_origin", "deny_origin"} {
		response, _ := host.Handle(nativehost.Request{Version: 1, ID: "refusal", Action: action})
		if response.Error != "standard credential operations are unavailable during computer use" {
			t.Fatalf("%s reached a credential operation: %v", action, response.Error)
		}
	}
	if browserNativeHost("unused-human-config", true).ComputerUse {
		t.Fatal("explicit human-only mode was not preserved")
	}
}

func TestBrowserLocatorModeCannotImplicitlyDowngrade(t *testing.T) {
	for _, text := range []string{`/private/disposable/device.json`, `{"config":"/private/disposable/device.json"}`, `{"config":"/private/disposable/device.json","mode":"computer-use"}`} {
		binding, err := parseBrowserLocator([]byte(text))
		if err != nil || binding.Mode != "computer-use" {
			t.Fatalf("safe/legacy locator mode: %v", err)
		}
	}
	binding, err := parseBrowserLocator([]byte(`{"config":"/private/disposable/device.json","mode":"human"}`))
	if err != nil || binding.Mode != "human" {
		t.Fatal("explicit local human selection was not retained")
	}
	for _, text := range []string{"", "relative-device.json", `{"config":"/private/device","mode":"unknown"}`, `{"config":"/private/device","unrecognized":true}`, `{"config":"/private/device"} {}`} {
		if _, err := parseBrowserLocator([]byte(text)); err == nil {
			t.Fatal("invalid locator accepted")
		}
	}
}

func TestInstalledNativeHostLocatorBootstrap(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(root, "envbank-native-host")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build disposable native host: %v: %s", err, output)
	}
	missingConfig := filepath.Join(root, "missing-device.json")
	for _, mode := range []string{"computer-use", "human", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			locator, _ := json.Marshal(browserLocator{Config: missingConfig, Mode: mode})
			if mode == "legacy" {
				locator = []byte(missingConfig + "\n")
			}
			if err := os.WriteFile(filepath.Join(root, "native-config"), locator, 0600); err != nil {
				t.Fatal(err)
			}
			actions := []string{"protected_status", "protected_execute"}
			if mode != "human" {
				actions = append(actions, "get_for_fill", "allow_origin", "deny_origin", "generate_password")
			}
			for _, action := range actions {
				raw, _ := json.Marshal(nativehost.Request{Version: 1, ID: "bootstrap", Action: action, Origin: "https://fake.invalid"})
				var input bytes.Buffer
				_ = binary.Write(&input, binary.LittleEndian, uint32(len(raw)))
				input.Write(raw)
				command := exec.Command(binaryPath)
				command.Stdin = &input
				output, err := command.Output()
				if err != nil || len(output) < 4 || int(binary.LittleEndian.Uint32(output[:4])) != len(output)-4 {
					t.Fatalf("native framing for %s: %v", action, err)
				}
				var response nativehost.Response
				if json.Unmarshal(output[4:], &response) != nil {
					t.Fatal("invalid native response")
				}
				switch action {
				case "protected_status":
					status := response.Result.(map[string]any)
					if status["computer_use"] != (mode != "human") || status["available"] != false {
						t.Fatal("installed bootstrap selected the wrong mode")
					}
				case "protected_execute":
					if response.Result.(map[string]any)["status"] != "HOST_PROTECTION_UNAVAILABLE" {
						t.Fatal("unconfigured host did not refuse protected filling")
					}
				default:
					if response.Error != "standard credential operations are unavailable during computer use" {
						t.Fatal("installed bootstrap reached legacy credential access")
					}
				}
			}
		})
	}
}

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
		"brave":              filepath.Join("BraveSoftware", "Brave-Browser", "NativeMessagingHosts", "com.envbank.native.json"),
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
