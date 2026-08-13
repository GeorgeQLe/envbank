package testlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
)

func TestFullLifecycleThroughMCPAndEncryptedPersistence(t *testing.T) {
	directory := t.TempDir()
	lab, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	server := mcpserver.Server{Backend: lab.Production(), Extension: lab.Extension()}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"envbank_workflow_start","arguments":{"provider":"stripe"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"envbank_test_clock_advance","arguments":{"duration":"30s"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"envbank_workflow_resume","arguments":{"operation_id":"op-000001"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"envbank_test_clock_advance","arguments":{"duration":"15m"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"envbank_workflow_resume","arguments":{"operation_id":"op-000001"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"envbank_test_assert_secret_flow","arguments":{"operation_id":"op-000001","vercel_project_id":"vercel-project","railway_project_id":"railway-project"}}}`,
	}, "\n") + "\n"
	var output strings.Builder
	if err := server.Serve(context.Background(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `\"stage\":\"complete\"`) || !strings.Contains(output.String(), `\"all_match\":true`) {
		t.Fatalf("unexpected MCP output: %s", output.String())
	}
	for _, forbidden := range []string{"whsec_testlab_", "sk_testlab_", "digest"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("MCP output leaked %q", forbidden)
		}
	}
	if err := lab.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "vault.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "whsec_testlab_") {
		t.Fatal("SQLite bytes contain plaintext synthetic credential")
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.clock.Now(); got != time.Date(2026, 8, 13, 12, 15, 30, 0, time.UTC) {
		t.Fatalf("virtual clock was not restored: %s", got)
	}
}

func TestBrowserSimulatorRejectsUnsafeContextsAndReturnsAcknowledgementOnly(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	recipe := BrowserRecipe{Version: 2, Origin: "https://dashboard.clerk.test", Route: "/apps/app/keys", Selector: "[data-key]", Record: "CLERK_SECRET_KEY", Prefix: "sk_testlab_", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	recipe.Sign(private)
	writer := &memoryRecordWriter{}
	sink, _ := lifecycle.NewSecretSink(writer, recipe.Record)
	browser := &BrowserSimulator{PublicKey: public, Now: func() time.Time { return now }}
	receipt, err := browser.Capture(context.Background(), recipe, BrowserCapture{Origin: recipe.Origin, Route: recipe.Route, SelectorMatches: 1, Masked: true, DOMStable: true}, sink)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(receipt)
	if strings.Contains(string(raw), "sk_testlab_") || !receipt.Acknowledged || receipt.Mode != "simulated-interactive" {
		t.Fatalf("unsafe receipt: %s", raw)
	}
	unsafeSink, _ := lifecycle.NewSecretSink(&memoryRecordWriter{}, recipe.Record)
	unsafeBrowser := &BrowserSimulator{PublicKey: public, Now: func() time.Time { return now }}
	if _, err := unsafeBrowser.Capture(context.Background(), recipe, BrowserCapture{Origin: recipe.Origin, Route: recipe.Route, SelectorMatches: 1, Masked: true, DOMStable: true, InFrame: true}, unsafeSink); err == nil {
		t.Fatal("iframe capture accepted")
	}
}

type memoryRecordWriter struct{ revision int64 }

func (writer *memoryRecordWriter) StoreSecret(_ context.Context, _ string, provide func(func([]byte) error) error) (int64, error) {
	if err := provide(func(value []byte) error {
		if !strings.HasPrefix(string(value), "sk_testlab_") {
			return os.ErrInvalid
		}
		return nil
	}); err != nil {
		return 0, err
	}
	writer.revision++
	return writer.revision, nil
}

func TestStrictSchemasAndReverseRollback(t *testing.T) {
	lab, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	for _, tool := range lab.Extension().Tools() {
		if tool.Schema["additionalProperties"] != false {
			t.Fatalf("%s schema is not closed", tool.Name)
		}
	}
	ext := lab.Extension()
	_, err = ext.Call(context.Background(), "envbank_test_fault_set", json.RawMessage(`{"provider":"railway","checkpoint":"activate:railway","behavior":"terminal","count":1}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := lab.Production().Call(context.Background(), "envbank_workflow_start", mcpserver.Request{Provider: "stripe"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stage != "rolled-back" {
		t.Fatalf("stage=%s", result.Stage)
	}
	lab.mu.Lock()
	checkpoints := strings.Join(lab.state.Operations[result.OperationID].Checkpoints, ",")
	lab.mu.Unlock()
	if !strings.Contains(checkpoints, "rollback:railway,rollback:vercel") || !strings.Contains(checkpoints, "quarantine-new-credential") {
		t.Fatalf("checkpoints=%s", checkpoints)
	}
	if _, err := ext.Call(context.Background(), "envbank_test_clock_advance", json.RawMessage(`{"duration":"32d","secret":"x"}`)); err == nil {
		t.Fatal("unknown argument accepted")
	}
}

func TestLeaseHasOneWinnerAndOneSafeNoOp(t *testing.T) {
	lab, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	results := make(chan mcpserver.Result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, _ := lab.Production().Call(context.Background(), "envbank_workflow_start", mcpserver.Request{Provider: "stripe"})
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	winners, noops := 0, 0
	for result := range results {
		if result.Stage == "verifying" {
			winners++
		}
		if result.Stage == "safe-no-op" && result.BlockerCode == "LEASE_HELD" {
			noops++
		}
	}
	if winners != 1 || noops != 1 {
		t.Fatalf("winners=%d noops=%d", winners, noops)
	}
}
