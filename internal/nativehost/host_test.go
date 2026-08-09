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

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
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

func TestGeneratePasswordCreatesEncryptedRedactedRecord(t *testing.T) {
	var put protocol.PutRecordRequest
	host, _ := testHost(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&put); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}, nil)
	policy := password.DefaultPolicy()
	response, _ := host.Handle(Request{Version: 1, ID: "generate", Action: "generate_password", Name: "LOGIN_PASSWORD", Origin: "https://example.com", Policy: policy})
	if !response.OK {
		t.Fatalf("generate failed: %#v", response)
	}
	raw, _ := json.Marshal(response)
	if strings.Contains(string(raw), "value") {
		t.Fatalf("response contains a value field: %s", raw)
	}
	metadata := response.Result.(ListedRecord)
	if metadata.Name != "LOGIN_PASSWORD" || metadata.Revision != 1 || !metadata.Allowed {
		t.Fatalf("metadata = %#v", metadata)
	}
	if put.ExpectedRevision != 0 || put.Blob.Ciphertext == "" {
		t.Fatalf("put = %#v", put)
	}
	id := secure.RecordID(host.vaultKey, "LOGIN_PASSWORD")
	decoded, err := client.DecryptRecords("vault", host.vaultKey, []protocol.Record{{ID: id, Revision: 1, Blob: put.Blob}})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || len(decoded[0].Value) != policy.Length || !browserOriginPresent(decoded[0].AllowedOrigins, "https://example.com") {
		t.Fatalf("stored record = %#v", decoded)
	}
	requestJSON, _ := json.Marshal(put)
	if strings.Contains(string(requestJSON), decoded[0].Value) {
		t.Fatal("server request exposed plaintext outside encrypted blob")
	}
}

func TestGeneratePasswordReplacementRequiresExactRevisionAndPreservesMetadata(t *testing.T) {
	existing := protocol.SecretRecord{Name: "PASSWORD", Value: "old-sensitive-value", CreatedAt: "2025-01-02T03:04:05Z", RotatedAt: "2025-02-03T04:05:06Z", RotateEveryDays: 60, Revision: 7, AllowedOrigins: []string{"https://old.example"}}
	var encrypted []protocol.Record
	var put protocol.PutRecordRequest
	host, _ := testHost(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(encrypted)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&put); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}, nil)
	id, blob, err := client.EncryptRecord("vault", host.vaultKey, existing)
	if err != nil {
		t.Fatal(err)
	}
	encrypted = []protocol.Record{{ID: id, Revision: existing.Revision, Blob: blob}}
	policy := password.DefaultPolicy()
	stale, _ := host.Handle(Request{Version: 1, ID: "stale", Action: "generate_password", Name: existing.Name, Origin: "https://new.example", Policy: policy, ExpectedRevision: 6})
	if stale.OK || !strings.Contains(stale.Error, "refresh") || strings.Contains(stale.Error, existing.Value) {
		t.Fatalf("stale response = %#v", stale)
	}
	response, _ := host.Handle(Request{Version: 1, ID: "replace", Action: "generate_password", Name: existing.Name, Origin: "https://new.example", Policy: policy, ExpectedRevision: 7})
	if !response.OK || put.ExpectedRevision != 7 {
		t.Fatalf("replacement response=%#v put=%#v", response, put)
	}
	decoded, err := client.DecryptRecords("vault", host.vaultKey, []protocol.Record{{ID: id, Revision: 8, Blob: put.Blob}})
	if err != nil {
		t.Fatal(err)
	}
	got := decoded[0]
	if got.CreatedAt != existing.CreatedAt || got.RotateEveryDays != existing.RotateEveryDays || got.Revision != 8 || got.Value == existing.Value || !browserOriginPresent(got.AllowedOrigins, "https://old.example") || !browserOriginPresent(got.AllowedOrigins, "https://new.example") {
		t.Fatalf("replacement = %#v", got)
	}
}

func TestGeneratePasswordValidatesNameOriginAndClasses(t *testing.T) {
	host, calls := testHost(t, nil, nil)
	policy := password.DefaultPolicy()
	for _, request := range []Request{
		{Version: 1, ID: "name", Action: "generate_password", Name: "BAD-NAME", Origin: "https://example.com", Policy: policy},
		{Version: 1, ID: "origin", Action: "generate_password", Name: "GOOD_NAME", Origin: "http://example.com", Policy: policy},
		{Version: 1, ID: "classes", Action: "generate_password", Name: "GOOD_NAME", Origin: "https://example.com", Policy: password.Policy{Length: 24}},
	} {
		response, _ := host.Handle(request)
		if response.OK || response.Result != nil {
			t.Fatalf("invalid request succeeded: %#v", response)
		}
	}
	if *calls != 0 {
		t.Fatalf("invalid requests contacted server %d times", *calls)
	}
}

func browserOriginPresent(origins []string, want string) bool {
	for _, origin := range origins {
		if origin == want {
			return true
		}
	}
	return false
}
