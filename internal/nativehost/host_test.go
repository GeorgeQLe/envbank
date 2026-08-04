package nativehost

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

type mockKeychain struct {
	passphrase []byte
	accounts   []string
	returned   [][]byte
}

func (m *mockKeychain) Get(_, account, _ string) ([]byte, error) {
	m.accounts = append(m.accounts, account)
	value := append([]byte(nil), m.passphrase...)
	m.returned = append(m.returned, value)
	return value, nil
}

func TestHostUnlocksKeychainOncePerSessionAndZeroesPassphrase(t *testing.T) {
	passphrase := []byte("correct horse battery staple")
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	keys.Secrets.VaultKey = secure.Encode(vaultKey)
	cfg, err := client.NewConfig("https://server.example", "vault-id", "device-id", "test", keys, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "device.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	store := &mockKeychain{passphrase: passphrase}
	host := New(path, store)
	if err := host.unlock(); err != nil {
		t.Fatal(err)
	}
	if err := host.unlock(); err != nil {
		t.Fatal(err)
	}
	if len(store.accounts) != 1 || store.accounts[0] != "vault-id:device-id" {
		t.Fatalf("unexpected Keychain accesses: %#v", store.accounts)
	}
	if !allZero(store.returned[0]) {
		t.Fatal("mutable Keychain passphrase buffer was not zeroed")
	}
	host.clear()
	if err := host.unlock(); err != nil {
		t.Fatal(err)
	}
	if len(store.accounts) != 2 {
		t.Fatalf("new session did not reauthenticate: %d accesses", len(store.accounts))
	}
}

func TestIdleTimeoutClearsSession(t *testing.T) {
	reader, writer := io.Pipe()
	key := bytes.Repeat([]byte{9}, 32)
	host := &Host{api: client.NewAPI("https://server.example"), vaultKey: key, Idle: 10 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- host.Run(reader, io.Discard) }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if host.api != nil || host.vaultKey != nil || !allZero(key) {
		t.Fatal("idle timeout did not clear native session")
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func testHost(t *testing.T, handler http.HandlerFunc, records []protocol.SecretRecord) (*Host, *int) {
	t.Helper()
	key, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted []protocol.Record
	for _, record := range records {
		id, blob, err := client.EncryptRecord("vault", key, record)
		if err != nil {
			t.Fatal(err)
		}
		encrypted = append(encrypted, protocol.Record{ID: id, Revision: record.Revision, Blob: blob})
	}
	calls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		writer := &responseWriter{header: make(http.Header), status: http.StatusOK}
		if handler != nil {
			handler(writer, r)
		} else {
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(encrypted)
		}
		return &http.Response{StatusCode: writer.status, Header: writer.header, Body: io.NopCloser(strings.NewReader(writer.body.String()))}, nil
	})
	api := client.NewAPI("http://test.invalid")
	api.HTTPClient = &http.Client{Transport: transport}
	api.Config = &client.Config{VaultID: "vault", DeviceID: "device"}
	api.Secrets = keys.Secrets
	host := &Host{api: api, vaultKey: key, Now: func() time.Time { return time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC) }}
	return host, &calls
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

type responseWriter struct {
	header http.Header
	body   strings.Builder
	status int
}

func (w *responseWriter) Header() http.Header             { return w.header }
func (w *responseWriter) WriteHeader(status int)          { w.status = status }
func (w *responseWriter) Write(value []byte) (int, error) { return w.body.Write(value) }

func TestListDoesNotExposeValuesAndFillRechecksOrigin(t *testing.T) {
	record := protocol.SecretRecord{Name: "TOKEN", Value: "never-list-this", Revision: 4, RotatedAt: "2026-01-01T00:00:00Z", RotateEveryDays: 30, AllowedOrigins: []string{"https://example.com"}}
	host, calls := testHost(t, nil, []protocol.SecretRecord{record})
	list, _ := host.Handle(Request{Version: 1, ID: "list", Action: "list_for_origin", Origin: "https://example.com"})
	if !list.OK {
		t.Fatalf("list failed: %#v", list)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), record.Value) {
		t.Fatal("list response exposed a secret value")
	}
	items := list.Result.([]ListedRecord)
	if len(items) != 1 || !items[0].Allowed || !items[0].Due {
		t.Fatalf("unexpected list result: %#v", items)
	}
	fill, _ := host.Handle(Request{Version: 1, ID: "fill", Action: "get_for_fill", Name: "TOKEN", Origin: "https://example.com"})
	if !fill.OK || fill.Result.(map[string]string)["value"] != record.Value {
		t.Fatalf("fill failed: %#v", fill)
	}
	denied, _ := host.Handle(Request{Version: 1, ID: "deny", Action: "get_for_fill", Name: "TOKEN", Origin: "https://other.example"})
	if denied.OK || denied.Result != nil {
		t.Fatalf("unapproved fill succeeded: %#v", denied)
	}
	if *calls != 3 {
		t.Fatalf("expected each action to refetch records, got %d calls", *calls)
	}
}

func TestPolicyConflictUsesRedactedError(t *testing.T) {
	record := protocol.SecretRecord{Name: "TOKEN", Value: "sensitive-value", Revision: 2}
	var encrypted []protocol.Record
	host, _ := testHost(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"revision conflict"}`))
			return
		}
		json.NewEncoder(w).Encode(encrypted)
	}, nil)
	// Replace the closure-based fixture with ciphertext created from this host's key.
	id, blob, err := client.EncryptRecord("vault", host.vaultKey, record)
	if err != nil {
		t.Fatal(err)
	}
	encrypted = []protocol.Record{{ID: id, Revision: record.Revision, Blob: blob}}
	response, _ := host.Handle(Request{Version: 1, ID: "allow", Action: "allow_origin", Name: "TOKEN", Origin: "https://example.com"})
	if response.OK || !strings.Contains(response.Error, "concurrently") {
		t.Fatalf("unexpected response: %#v", response)
	}
	if strings.Contains(response.Error, record.Value) || strings.Contains(response.Error, record.Name) {
		t.Fatal("policy error leaked record data")
	}
}
