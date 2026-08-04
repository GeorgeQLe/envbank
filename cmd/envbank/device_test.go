package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/server"
)

type cliDeviceFixture struct {
	service           *server.Server
	passphrasePath    string
	firstConfigPath   string
	secondConfigPath  string
	firstID           string
	secondID          string
	firstFingerprint  string
	secondFingerprint string
}

var cliFixtureSequence atomic.Uint64

type cliHandlerTransport struct {
	handler http.Handler
}

func (t cliHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func newCLIDeviceFixture(t *testing.T) *cliDeviceFixture {
	t.Helper()
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	scheme := fmt.Sprintf("envbanktest%d", cliFixtureSequence.Add(1))
	http.DefaultTransport.(*http.Transport).RegisterProtocol(scheme, cliHandlerTransport{handler: service})
	serverURL := scheme + "://server"

	dir := t.TempDir()
	passphrase := []byte("test passphrase")
	passphrasePath := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(passphrasePath, passphrase, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	first.Secrets.VaultKey = secure.Encode(vaultKey)
	api := client.NewAPI(serverURL)
	created, err := api.CreateVault("test", protocol.PublicDevice{
		Name: "first", SigningPublic: first.SigningPublic, WrappingPublic: first.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstConfig, err := client.NewConfig(serverURL, created.VaultID, created.DeviceID,
		"first", first, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	firstConfigPath := filepath.Join(dir, "first.json")
	if err := firstConfig.Save(firstConfigPath); err != nil {
		t.Fatal(err)
	}
	api.Config = firstConfig
	api.Secrets = first.Secrets

	second, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := api.RequestEnrollment(created.VaultID, protocol.EnrollmentRequest{
		Name: "second", SigningPublic: second.SigningPublic, WrappingPublic: second.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secure.WrapVaultKey(vaultKey, second.WrappingPublic,
		created.VaultID, enrollment.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.ApproveEnrollment(enrollment.Device.ID, envelope); err != nil {
		t.Fatal(err)
	}
	second.Secrets.VaultKey = secure.Encode(vaultKey)
	secondConfig, err := client.NewConfig(serverURL, created.VaultID, enrollment.Device.ID,
		"second", second, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	secondConfigPath := filepath.Join(dir, "second.json")
	if err := secondConfig.Save(secondConfigPath); err != nil {
		t.Fatal(err)
	}
	return &cliDeviceFixture{
		service: service, passphrasePath: passphrasePath,
		firstConfigPath: firstConfigPath, secondConfigPath: secondConfigPath,
		firstID: created.DeviceID, secondID: enrollment.Device.ID,
		firstFingerprint:  secure.PublicFingerprint(first.SigningPublic, first.WrappingPublic),
		secondFingerprint: enrollment.Device.Fingerprint,
	}
}

func authArgs(f *cliDeviceFixture, configPath string) []string {
	return []string{"--config", configPath, "--passphrase-file", f.passphrasePath}
}

func captureRun(t *testing.T, args []string) (string, string, error) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	runErr := run(args)
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, _ := io.ReadAll(stdoutReader)
	stderr, _ := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	return string(stdout), string(stderr), runErr
}

func TestDeviceRevokeCLIValidatesFingerprintAndSelfConfirmation(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	base := append([]string{"device-revoke"}, authArgs(fixture, fixture.firstConfigPath)...)
	if _, _, err := captureRun(t, append(base, fixture.secondID)); err == nil ||
		!strings.Contains(err.Error(), "--fingerprint") {
		t.Fatalf("missing fingerprint error = %v", err)
	}
	mismatch := append(base, "--fingerprint", "wrong", fixture.secondID)
	if _, _, err := captureRun(t, mismatch); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched fingerprint error = %v", err)
	}
	self := append(base, "--fingerprint", fixture.firstFingerprint, fixture.firstID)
	if _, _, err := captureRun(t, self); err == nil || !strings.Contains(err.Error(), "--allow-self") {
		t.Fatalf("missing self confirmation error = %v", err)
	}
}

func TestDeviceRevokeCLINormalAndSelfRevocation(t *testing.T) {
	normal := newCLIDeviceFixture(t)
	args := append([]string{"device-revoke"}, authArgs(normal, normal.firstConfigPath)...)
	args = append(args, "--fingerprint", strings.ToLower(normal.secondFingerprint), normal.secondID)
	stdout, stderr, err := captureRun(t, args)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "revoked device "+normal.secondID) || stderr != "" {
		t.Fatalf("unexpected normal output: stdout=%q stderr=%q", stdout, stderr)
	}
	listArgs := append([]string{"device-list"}, authArgs(normal, normal.firstConfigPath)...)
	stdout, _, err = captureRun(t, listArgs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, normal.secondID+"\tsecond\t"+normal.secondFingerprint+"\trevoked\t") {
		t.Fatalf("device-list did not show revoked device: %q", stdout)
	}

	self := newCLIDeviceFixture(t)
	selfArgs := append([]string{"device-revoke"}, authArgs(self, self.secondConfigPath)...)
	selfArgs = append(selfArgs, "--fingerprint", self.secondFingerprint, "--allow-self", self.secondID)
	stdout, stderr, err = captureRun(t, selfArgs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "revoked device "+self.secondID) ||
		!strings.Contains(stderr, "local config and Keychain entry were preserved") {
		t.Fatalf("unexpected self-revocation output: stdout=%q stderr=%q", stdout, stderr)
	}
	if _, err := os.Stat(self.secondConfigPath); err != nil {
		t.Fatalf("self-revocation removed local config: %v", err)
	}
}

func TestEventListCLIPrintsTSVAndCursorHint(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	args := append([]string{"event-list", "--limit", "1"},
		authArgs(fixture, fixture.firstConfigPath)...)
	stdout, stderr, err := captureRun(t, args)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(stdout), "\t")
	if len(fields) != 7 {
		t.Fatalf("event-list fields = %d, want 7: %q", len(fields), stdout)
	}
	if fields[1] != fixture.firstID || fields[2] != "true" ||
		fields[3] != "event_list" || fields[4] != "succeeded" ||
		fields[5] != "-" || fields[6] != "-" {
		t.Fatalf("unexpected event-list row: %q", stdout)
	}
	if !strings.HasPrefix(stderr, "next cursor: ") {
		t.Fatalf("missing next cursor hint: %q", stderr)
	}
}
