package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

const bundlePrepareManifest = `version: 1
bundle: example/siftcut/staging
policies:
  generated:
    type: password
    length: 24
    lowercase: true
    uppercase: true
    digits: true
records:
  ALPHA:
    source: generate
    policy: generated
  BETA:
    source: generate
    policy: generated
  GAMMA:
    source: generate
    policy: generated
  IMPORTED:
    source: import
    sensitivity: secret
  FIRST_URL:
    source: derive
    template: postgresql://user:${secret:ALPHA}@database.internal/first
  SECOND_URL:
    source: derive
    template: postgresql://user:${secret:IMPORTED}@database.internal/second
targets:
  railway:
    project: siftcut
    environment: staging
    services:
      api:
        order: 1
        variables:
          FIRST_URL: {source: record, record: FIRST_URL}
          SECOND_URL: {source: record, record: SECOND_URL}
`

func TestBundlePrepareStatusIdempotencyAndStaleness(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(manifestPath, []byte(bundlePrepareManifest), 0600); err != nil {
		t.Fatal(err)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	statusArgs := append([]string{"bundle", "status", "--manifest", manifestPath}, auth...)
	stdout, stderr, err := captureRun(t, statusArgs)
	if err != nil || !strings.Contains(stdout, "status: missing") || stderr != "" {
		t.Fatalf("initial status stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}

	const imported = "fixture-import-sentinel-4f8c2b"
	prepareArgs := append([]string{"bundle", "prepare", "--manifest", manifestPath}, auth...)
	stdout, stderr, err = captureRunWithStdin(t, prepareArgs, `{"IMPORTED":"`+imported+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleOutputIsRedacted(t, stdout+stderr, imported)
	if !strings.Contains(stdout, "status: prepared") {
		t.Fatalf("prepare output = %q", stdout)
	}
	prepareOutput := stdout + stderr

	api, key := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	records := loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath)
	values, revisions := logicalBundleValues(t, records, "example/siftcut/staging")
	policy := password.Policy{Length: 24, Lowercase: true, Uppercase: true, Digits: true}
	seen := map[string]bool{}
	for _, name := range []string{"ALPHA", "BETA", "GAMMA"} {
		if err := passwordPolicyMatch(values[name], policy); err != nil {
			t.Fatalf("%s policy: %v", name, err)
		}
		if seen[values[name]] {
			t.Fatalf("generated values were not independent")
		}
		seen[values[name]] = true
	}
	if values["FIRST_URL"] != "postgresql://user:"+values["ALPHA"]+"@database.internal/first" ||
		values["SECOND_URL"] != "postgresql://user:"+imported+"@database.internal/second" {
		t.Fatal("derived values do not match their inputs")
	}
	for _, value := range values {
		assertBundleOutputIsRedacted(t, prepareOutput, value)
	}
	assertBundleOutputIsRedacted(t, prepareOutput, "postgresql://", "database.internal")
	objects, err := api.ListObjects(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 {
		t.Fatalf("object count = %d, want snapshot and journal", len(objects))
	}
	for _, object := range objects {
		for _, value := range values {
			if strings.Contains(string(object.Payload), value) {
				t.Fatal("encrypted bookkeeping payload contains a record value")
			}
		}
	}

	stdout, stderr, err = captureRunWithStdin(t, prepareArgs, "")
	if err != nil {
		t.Fatal(err)
	}
	assertBundleOutputIsRedacted(t, stdout+stderr, imported)
	_, afterRevisions := logicalBundleValues(t,
		loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "example/siftcut/staging")
	for name, revision := range revisions {
		if afterRevisions[name] != revision {
			t.Fatalf("idempotent prepare changed %s revision", name)
		}
	}

	alphaPhysical := bundle.PhysicalName("example/siftcut/staging", "ALPHA")
	var alpha protocol.SecretRecord
	for _, record := range records {
		if record.Name == alphaPhysical {
			alpha = record
		}
	}
	alpha.Value = "ConcurrentReplacement9"
	expected := alpha.Revision
	alpha.Revision++
	id, blob, err := client.EncryptRecord(api.Config.VaultID, key, alpha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = captureRun(t, statusArgs)
	if err != nil || !strings.Contains(stdout, "status: stale") || stderr != "" {
		t.Fatalf("stale status stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	assertBundleOutputIsRedacted(t, stdout, alphaPhysical)
	if !strings.Contains(stdout, "ALPHA: stale") {
		t.Fatalf("stale logical record missing from %q", stdout)
	}
	stdout, stderr, err = captureRunWithStdin(t, prepareArgs, "")
	if err != nil || !strings.Contains(stdout, "status: prepared") {
		t.Fatalf("reprepare stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	objects, err = api.ListObjects(key)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot bundle.Snapshot
	for _, object := range objects {
		if object.Kind == vaultobject.KindBundleSnapshot {
			if err := json.Unmarshal(object.Payload, &snapshot); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := snapshot.PreviousRecordRevisions["ALPHA"]; len(got) != 1 || got[0] != expected {
		t.Fatalf("ALPHA previous revisions = %v, want [%d]", got, expected)
	}
	if got := snapshot.PreviousRecordRevisions["FIRST_URL"]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("FIRST_URL previous revisions = %v, want [1]", got)
	}
}

type bundleFailingHandler struct {
	next  http.Handler
	at    int64
	count atomic.Int64
	fail  atomic.Bool
}

func (handler *bundleFailingHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler.fail.Load() && request.Method == http.MethodPut && handler.count.Add(1) == handler.at {
		http.Error(writer, `{"error":"injected failure"}`, http.StatusServiceUnavailable)
		return
	}
	handler.next.ServeHTTP(writer, request)
}

func TestBundlePrepareResumesWithoutRegeneratingDurableSource(t *testing.T) {
	failure := &bundleFailingHandler{at: 2}
	failure.fail.Store(true)
	fixture := newCLIDeviceFixtureWithWrapper(t, func(next http.Handler) http.Handler {
		failure.next = next
		return failure
	})
	manifest := strings.Replace(bundlePrepareManifest,
		"  BETA:\n    source: generate\n    policy: generated\n  GAMMA:\n    source: generate\n    policy: generated\n", "", 1)
	manifest = strings.Replace(manifest,
		"  FIRST_URL:\n    source: derive\n    template: postgresql://user:${secret:ALPHA}@database.internal/first\n  SECOND_URL:\n    source: derive\n    template: postgresql://user:${secret:IMPORTED}@database.internal/second\n", "", 1)
	manifest = strings.Replace(manifest,
		"          FIRST_URL: {source: record, record: FIRST_URL}\n          SECOND_URL: {source: record, record: SECOND_URL}\n", "          ALPHA: {source: record, record: ALPHA}\n", 1)
	path := filepath.Join(t.TempDir(), "resume.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"bundle", "prepare", "--manifest", path}, authArgs(fixture, fixture.firstConfigPath)...)
	stdout, stderr, err := captureRunWithStdin(t, args, `{"IMPORTED":"resume-import-sentinel"}`)
	if err == nil {
		t.Fatal("injected checkpoint failure was accepted")
	}
	assertBundleOutputIsRedacted(t, stdout+stderr+err.Error(), "resume-import-sentinel")
	before, _ := logicalBundleValues(t,
		loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "example/siftcut/staging")
	if before["ALPHA"] == "" {
		t.Fatal("generated source was not durable before checkpoint failure")
	}

	failure.fail.Store(false)
	stdout, stderr, err = captureRunWithStdin(t, args, `{"IMPORTED":"resume-import-sentinel"}`)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleOutputIsRedacted(t, stdout+stderr, "resume-import-sentinel")
	after, _ := logicalBundleValues(t,
		loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "example/siftcut/staging")
	if after["ALPHA"] != before["ALPHA"] {
		t.Fatal("resume regenerated an already durable password")
	}
}

func captureRunWithStdin(t *testing.T, args []string, input string) (string, string, error) {
	t.Helper()
	oldStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(input); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	os.Stdin = reader
	stdout, stderr, runErr := captureRun(t, args)
	os.Stdin = oldStdin
	_ = reader.Close()
	return stdout, stderr, runErr
}

func logicalBundleValues(t *testing.T, records []protocol.SecretRecord, bundleID string) (map[string]string, map[string]int64) {
	t.Helper()
	values := map[string]string{}
	revisions := map[string]int64{}
	for _, logical := range []string{"ALPHA", "BETA", "GAMMA", "IMPORTED", "FIRST_URL", "SECOND_URL"} {
		physical := bundle.PhysicalName(bundleID, logical)
		for _, record := range records {
			if record.Name == physical {
				values[logical] = record.Value
				revisions[logical] = record.Revision
			}
		}
	}
	return values, revisions
}

func passwordPolicyMatch(value string, policy password.Policy) error {
	if len(value) != policy.Length || !strings.ContainsAny(value, password.Lowercase) ||
		!strings.ContainsAny(value, password.Uppercase) || !strings.ContainsAny(value, password.Digits) {
		return errors.New("generated value does not satisfy policy")
	}
	return nil
}

func assertBundleOutputIsRedacted(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(output, value) {
			t.Fatalf("bundle output exposed forbidden data: %q", output)
		}
	}
	if strings.Contains(output, "ENVBANK_B1_") {
		t.Fatalf("bundle output exposed a physical record name: %q", output)
	}
	for _, kind := range []string{vaultobject.KindBundlePrepare, vaultobject.KindBundleSnapshot} {
		if strings.Contains(output, kind) {
			t.Fatalf("bundle output exposed internal object kind %q", kind)
		}
	}
}
