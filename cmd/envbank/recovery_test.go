package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/server"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

type failingPutHandler struct {
	next     http.Handler
	failAt   int64
	putCount atomic.Int64
	fail     atomic.Bool
}

func (h *failingPutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.fail.Load() && r.Method == http.MethodPut &&
		h.putCount.Add(1) == h.failAt {
		http.Error(w, `{"error":"injected upload failure"}`, http.StatusServiceUnavailable)
		return
	}
	h.next.ServeHTTP(w, r)
}

func TestRecoveryCLIExportsOfflineAccessAndRestores(t *testing.T) {
	source := newCLIDeviceFixture(t)
	sourceRecords := recoverySourceRecords()
	storeFixtureRecords(t, source, sourceRecords)
	sourceAPI, sourceKey := unlockedFixtureAPI(t, source.firstConfigPath, source.passphrasePath)
	if _, err := sourceAPI.PutObject(sourceKey, vaultobject.KindBundleSnapshot,
		"recovery-bundle", map[string]any{"version": 1, "source_revision": 7}, 0); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	recoveryPassPath := writeTestPrivateFile(t, dir, "recovery.pass", "separate recovery passphrase")
	artifactPath := filepath.Join(dir, "vault.recovery")

	exportArgs := []string{
		"recovery-export", "--output", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--config", source.firstConfigPath,
		"--passphrase-file", source.passphrasePath,
	}
	stdout, stderr, err := captureRun(t, exportArgs)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRecoverySecrets(t, stdout+stderr)
	if info, err := os.Stat(artifactPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("artifact permissions: info=%v err=%v", info, err)
	}

	if err := source.service.Close(); err != nil {
		t.Fatal(err)
	}
	common := []string{"--artifact", artifactPath, "--recovery-passphrase-file", recoveryPassPath}
	stdout, stderr, err = captureRun(t, append([]string{"recovery-verify"}, common...))
	if err != nil {
		t.Fatal(err)
	}
	assertNoRecoverySecrets(t, stdout+stderr)
	stdout, stderr, err = captureRun(t, append([]string{"recovery-list"}, common...))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "ALPHA_TOKEN") || !strings.Contains(stdout, "source_revision=7") {
		t.Fatalf("recovery-list output = %q", stdout)
	}
	assertNoRecoverySecrets(t, stdout+stderr)
	getArgs := append([]string{"recovery-get"}, common...)
	getArgs = append(getArgs, "ALPHA_TOKEN")
	stdout, stderr, err = captureRun(t, getArgs)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "alpha-secret-value" || stderr != "" {
		t.Fatalf("recovery-get stdout=%q stderr=%q", stdout, stderr)
	}
	runArgs := append([]string{"recovery-run"}, common...)
	runArgs = append(runArgs, "--", "/bin/sh", "-c", `printf '%s' "$BETA_TOKEN"`)
	stdout, stderr, err = captureRun(t, runArgs)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "beta-secret-value" || stderr != "" {
		t.Fatalf("recovery-run stdout=%q stderr=%q", stdout, stderr)
	}
	t.Setenv("ENVBANK_RECOVERY_PASSPHRASE", "separate recovery passphrase")
	stdout, stderr, err = captureRun(t, []string{
		"recovery-run", "--artifact", artifactPath, "--", "/bin/sh", "-c",
		`test "$BETA_TOKEN" = "beta-secret-value" && test -z "$ENVBANK_RECOVERY_PASSPHRASE"`,
	})
	if err != nil || stdout != "" || stderr != "" {
		t.Fatalf("environment recovery-run stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}

	replacement, replacementURL := newCLIService(t, nil)
	configPath := filepath.Join(dir, "replacement.json")
	localPassPath := writeTestPrivateFile(t, dir, "replacement.pass", "new local passphrase")
	restoreArgs := []string{
		"recovery-restore", "--artifact", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--server", replacementURL, "--vault", "recovered",
		"--device", "replacement", "--config", configPath,
		"--passphrase-file", localPassPath,
	}
	stdout, stderr, err = captureRun(t, restoreArgs)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRecoverySecrets(t, stdout+stderr)
	if info, err := os.Stat(configPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions: info=%v err=%v", info, err)
	}
	restored := loadFixtureRecords(t, configPath, localPassPath)
	assertRestoredMetadata(t, restored, sourceRecords)
	restoredAPI, restoredKey := unlockedFixtureAPI(t, configPath, localPassPath)
	restoredObjects, err := restoredAPI.ListObjects(restoredKey)
	if err != nil || len(restoredObjects) != 1 || restoredObjects[0].Revision != 1 ||
		restoredObjects[0].Kind != vaultobject.KindBundleSnapshot {
		t.Fatalf("restored objects = %#v, %v", restoredObjects, err)
	}

	oldStdin := os.Stdin
	valueReader, valueWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = valueWriter.WriteString("post-restore-value")
	_ = valueWriter.Close()
	os.Stdin = valueReader
	setArgs := []string{"set", "--config", configPath, "--passphrase-file", localPassPath, "POST_RESTORE"}
	_, _, err = captureRun(t, setArgs)
	os.Stdin = oldStdin
	_ = valueReader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := findRecord(loadFixtureRecords(t, configPath, localPassPath), "POST_RESTORE"); got == nil ||
		got.Value != "post-restore-value" {
		t.Fatal("post-restore write was not readable")
	}
	_ = replacement
}

func TestRecoveryRestoreResumeAndTargetSafety(t *testing.T) {
	artifactPath, recoveryPassPath := createRecoveryArtifact(t)
	dir := t.TempDir()
	failure := &failingPutHandler{failAt: 2}
	failure.fail.Store(true)
	_, serverURL := newCLIService(t, failure)
	configPath := filepath.Join(dir, "resume.json")
	localPassPath := writeTestPrivateFile(t, dir, "local.pass", "local resume passphrase")
	args := []string{
		"recovery-restore", "--artifact", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--server", serverURL, "--vault", "resume", "--device", "replacement",
		"--config", configPath, "--passphrase-file", localPassPath,
	}
	stdout, stderr, err := captureRun(t, args)
	if err == nil || !strings.Contains(err.Error(), "use recovery-restore --resume") {
		t.Fatalf("injected failure stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	assertNoRecoverySecrets(t, stdout+stderr+err.Error())
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("resume config was not saved: %v", err)
	}
	failure.fail.Store(false)
	resume := []string{
		"recovery-restore", "--resume", "--artifact", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--config", configPath, "--passphrase-file", localPassPath,
	}
	stdout, stderr, err = captureRun(t, resume)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRecoverySecrets(t, stdout+stderr)
	if got := loadFixtureRecords(t, configPath, localPassPath); len(got) != 2 {
		t.Fatalf("restored record count = %d, want 2", len(got))
	}

	t.Run("conflicting record", func(t *testing.T) {
		artifact, recoveryPass := createRecoveryArtifact(t)
		testRecoveryTargetRejection(t, artifact, recoveryPass, true)
	})
	t.Run("unexpected record", func(t *testing.T) {
		artifact, recoveryPass := createRecoveryArtifact(t)
		testRecoveryTargetRejection(t, artifact, recoveryPass, false)
	})
}

func TestRecoveryCLIWrongPassphraseDoesNotLeakInputs(t *testing.T) {
	artifactPath, _ := createRecoveryArtifact(t)
	dir := t.TempDir()
	wrongPath := writeTestPrivateFile(t, dir, "wrong.pass", "wrong recovery phrase")
	stdout, stderr, err := captureRun(t, []string{
		"recovery-verify", "--artifact", artifactPath,
		"--recovery-passphrase-file", wrongPath,
	})
	if err == nil {
		t.Fatal("wrong recovery passphrase was accepted")
	}
	assertNoRecoverySecrets(t, stdout+stderr+err.Error())
	if strings.Contains(stdout+stderr+err.Error(), "wrong recovery phrase") {
		t.Fatal("error output exposed the recovery passphrase")
	}
}

func testRecoveryTargetRejection(t *testing.T, artifactPath, recoveryPassPath string, conflict bool) {
	t.Helper()
	dir := t.TempDir()
	failure := &failingPutHandler{failAt: 2}
	failure.fail.Store(true)
	_, serverURL := newCLIService(t, failure)
	configPath := filepath.Join(dir, "target.json")
	localPassPath := writeTestPrivateFile(t, dir, "local.pass", "target passphrase")
	args := []string{
		"recovery-restore", "--artifact", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--server", serverURL, "--vault", "target", "--device", "replacement",
		"--config", configPath, "--passphrase-file", localPassPath,
	}
	if _, _, err := captureRun(t, args); err == nil {
		t.Fatal("expected injected restore failure")
	}
	failure.fail.Store(false)
	api, key := unlockedFixtureAPI(t, configPath, localPassPath)
	if conflict {
		records := loadFixtureRecords(t, configPath, localPassPath)
		record := records[0]
		record.Value = "conflicting-value"
		expectedRevision := record.Revision
		record.Revision++
		id, blob, err := client.EncryptRecord(api.Config.VaultID, key, record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.PutRecord(id, protocol.PutRecordRequest{
			ExpectedRevision: expectedRevision,
			Blob:             blob,
		}); err != nil {
			t.Fatal(err)
		}
	} else {
		record := protocol.SecretRecord{
			Name: "UNRELATED", Value: "unrelated-value",
			CreatedAt: "2026-08-05T12:00:00Z", RotatedAt: "2026-08-05T12:00:00Z",
			Revision: 1,
		}
		id, blob, err := client.EncryptRecord(api.Config.VaultID, key, record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.PutRecord(id, protocol.PutRecordRequest{Blob: blob}); err != nil {
			t.Fatal(err)
		}
	}
	resume := []string{
		"recovery-restore", "--resume", "--artifact", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--config", configPath, "--passphrase-file", localPassPath,
	}
	stdout, stderr, err := captureRun(t, resume)
	if err == nil {
		t.Fatal("unsafe target was accepted")
	}
	if conflict && !strings.Contains(err.Error(), "conflicting record") {
		t.Fatalf("conflict error = %v", err)
	}
	if !conflict && !strings.Contains(err.Error(), "unexpected record") {
		t.Fatalf("unexpected error = %v", err)
	}
	assertNoRecoverySecrets(t, stdout+stderr+err.Error())
}

func createRecoveryArtifact(t *testing.T) (string, string) {
	t.Helper()
	source := newCLIDeviceFixture(t)
	storeFixtureRecords(t, source, recoverySourceRecords())
	dir := t.TempDir()
	recoveryPassPath := writeTestPrivateFile(t, dir, "recovery.pass", "separate recovery passphrase")
	artifactPath := filepath.Join(dir, "vault.recovery")
	args := []string{
		"recovery-export", "--output", artifactPath,
		"--recovery-passphrase-file", recoveryPassPath,
		"--config", source.firstConfigPath, "--passphrase-file", source.passphrasePath,
	}
	if _, _, err := captureRun(t, args); err != nil {
		t.Fatal(err)
	}
	return artifactPath, recoveryPassPath
}

func recoverySourceRecords() []protocol.SecretRecord {
	return []protocol.SecretRecord{
		{
			Name: "ALPHA_TOKEN", Value: "alpha-secret-value",
			CreatedAt: "2026-05-01T10:00:00Z", RotatedAt: "2026-07-01T10:00:00Z",
			RotateEveryDays: 45, Revision: 7,
			AllowedOrigins: []string{"https://example.com"},
		},
		{
			Name: "BETA_TOKEN", Value: "beta-secret-value",
			CreatedAt: "2026-06-01T11:00:00Z", RotatedAt: "2026-08-01T11:00:00Z",
			Revision: 2,
		},
	}
}

func storeFixtureRecords(t *testing.T, fixture *cliDeviceFixture, records []protocol.SecretRecord) {
	t.Helper()
	api, key := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	for _, record := range records {
		for revision := int64(1); revision <= record.Revision; revision++ {
			version := record
			version.Revision = revision
			id, blob, err := client.EncryptRecord(api.Config.VaultID, key, version)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.PutRecord(id, protocol.PutRecordRequest{
				ExpectedRevision: revision - 1,
				Blob:             blob,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func loadFixtureRecords(t *testing.T, configPath, passphrasePath string) []protocol.SecretRecord {
	t.Helper()
	api, key := unlockedFixtureAPI(t, configPath, passphrasePath)
	encrypted, err := api.ListRecords()
	if err != nil {
		t.Fatal(err)
	}
	records, err := client.DecryptRecords(api.Config.VaultID, key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func unlockedFixtureAPI(t *testing.T, configPath, passphrasePath string) (*client.API, []byte) {
	t.Helper()
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	passphrase, err := os.ReadFile(passphrasePath)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := cfg.Unlock(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	key, err := requireVaultKey(secrets)
	if err != nil {
		t.Fatal(err)
	}
	api := client.NewAPI(cfg.Server)
	api.Config, api.Secrets = cfg, secrets
	return api, key
}

func newCLIService(t *testing.T, wrapper *failingPutHandler) (*server.Server, string) {
	t.Helper()
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	var handler http.Handler = service
	if wrapper != nil {
		wrapper.next = handler
		handler = wrapper
	}
	scheme := fmt.Sprintf("envbanktest%d", cliFixtureSequence.Add(1))
	http.DefaultTransport.(*http.Transport).RegisterProtocol(scheme, cliHandlerTransport{handler: handler})
	return service, scheme + "://server"
}

func writeTestPrivateFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertRestoredMetadata(t *testing.T, restored, source []protocol.SecretRecord) {
	t.Helper()
	if len(restored) != len(source) {
		t.Fatalf("restored count = %d, want %d", len(restored), len(source))
	}
	for _, wantSource := range source {
		got := findRecord(restored, wantSource.Name)
		if got == nil {
			t.Fatalf("missing restored record %s", wantSource.Name)
		}
		if got.Value != wantSource.Value || got.CreatedAt != wantSource.CreatedAt ||
			got.RotatedAt != wantSource.RotatedAt ||
			got.RotateEveryDays != wantSource.RotateEveryDays ||
			fmt.Sprint(got.AllowedOrigins) != fmt.Sprint(wantSource.AllowedOrigins) {
			t.Fatalf("restored metadata mismatch: got=%#v want=%#v", got, wantSource)
		}
		if got.Revision != 1 {
			t.Fatalf("restored revision for %s = %d, want 1", got.Name, got.Revision)
		}
	}
}

func findRecord(records []protocol.SecretRecord, name string) *protocol.SecretRecord {
	for i := range records {
		if records[i].Name == name {
			return &records[i]
		}
	}
	return nil
}

func assertNoRecoverySecrets(t *testing.T, output string) {
	t.Helper()
	for _, secret := range []string{
		"alpha-secret-value", "beta-secret-value", "separate recovery passphrase",
		"local resume passphrase", "target passphrase", "unrelated-value",
		"conflicting-value",
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("output exposed sensitive value %q: %q", secret, output)
		}
	}
}
