package server_test

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/relay"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"github.com/GeorgeQLe/envbank/internal/server"
)

const relayMarker = "relay-server-marker-value-0001"

type relayFixture struct {
	vaultFixture
	vaultKey []byte
	target   relay.Device
	sender   relay.Device
	clock    *testClock
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newRelayFixture(t *testing.T, service *server.Server) relayFixture {
	t.Helper()
	clock := &testClock{now: time.Now().UTC()}
	server.SetClock(service, clock.Now)
	f := createTwoDeviceVault(t, service)
	f.firstAPI.Now, f.secondAPI.Now = clock.Now, clock.Now
	vaultKey, _ := secure.Decode(f.firstKeys.Secrets.VaultKey)
	return relayFixture{
		vaultFixture: f, vaultKey: vaultKey, clock: clock,
		target: relay.Device{ID: f.firstID, Name: "first", SigningPublic: f.firstKeys.SigningPublic, WrappingPublic: f.firstKeys.WrappingPublic},
		sender: relay.Device{ID: f.secondID, Name: "second", SigningPublic: f.secondKeys.SigningPublic, WrappingPublic: f.secondKeys.WrappingPublic},
	}
}

func (f relayFixture) create(t *testing.T) (protocol.RelayCreateRequest, *relay.Request) {
	t.Helper()
	create, request, err := relay.NewRequest(f.vaultID, f.vaultKey, f.target, f.firstKeys.Secrets.SigningPrivate, f.sender,
		relay.Sink{Kind: relay.SinkIngest, Name: "RELAY_SINK_NAME"}, "server test", f.clock.Now(), protocol.RelayMaxTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.firstAPI.CreateRelay(create); err != nil {
		t.Fatal(err)
	}
	return create, request
}

func (f relayFixture) sealRequest(t *testing.T) protocol.RelaySealRequest {
	t.Helper()
	pending, skipped, err := relay.Pending(f.secondAPI, f.vaultID, f.vaultKey, f.sender, f.clock.Now())
	if err != nil || skipped != 0 || len(pending) != 1 {
		t.Fatalf("pending=%d skipped=%d err=%v", len(pending), skipped, err)
	}
	env, err := relay.Seal(pending[0], f.vaultKey, f.secondKeys.Secrets.SigningPrivate, []byte(relayMarker), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return protocol.RelaySealRequest{Version: 1, Envelope: env}
}

func status(err error) int {
	var serverError *client.ServerError
	if errors.As(err, &serverError) {
		return serverError.Status
	}
	if errors.Is(err, client.ErrRelayGone) {
		return http.StatusGone
	}
	return 0
}

func TestRelayEndpointsRequireDeviceAuthentication(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	f := newRelayFixture(t, service)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/relays"}, {http.MethodGet, "/relays"}, {http.MethodPost, "/relays/x/seal"},
		{http.MethodPost, "/relays/x/consume"}, {http.MethodDelete, "/relays/x"},
	} {
		request := httptest.NewRequest(route.method, "/v1/vaults/"+f.vaultID+route.path, strings.NewReader("{}"))
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s unauthenticated = %d", route.method, route.path, response.Code)
		}
	}
	// A replayed signed request is refused by the existing nonce check.
	create, _, _ := relay.NewRequest(f.vaultID, f.vaultKey, f.target, f.firstKeys.Secrets.SigningPrivate, f.sender,
		relay.Sink{Kind: relay.SinkIngest, Name: "N"}, "", f.clock.Now(), time.Minute)
	var captured *http.Request
	var body []byte
	f.firstAPI.HTTPClient = &http.Client{Transport: recordingTransport{handler: service, record: func(r *http.Request) {
		captured = r.Clone(r.Context())
		body, _ = readAll(r)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}}}
	if _, err := f.firstAPI.CreateRelay(create); err != nil {
		t.Fatal(err)
	}
	replay := httptest.NewRequest(captured.Method, captured.URL.RequestURI(), bytes.NewReader(body))
	replay.Header = captured.Header.Clone()
	response := httptest.NewRecorder()
	service.ServeHTTP(response, replay)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed creation = %d", response.Code)
	}
}

func TestRelayIsSingleUseAndActorBound(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	f := newRelayFixture(t, service)
	create, onTarget := f.create(t)
	if listed, err := f.firstAPI.ListRelays(); err != nil || len(listed) != 1 || listed[0].ID != create.ID {
		t.Fatalf("target list %v %v", listed, err)
	}
	seal := f.sealRequest(t)
	if err := f.firstAPI.SealRelay(create.ID, seal); status(err) != http.StatusForbidden {
		t.Fatalf("target sealing = %v", err)
	}
	if _, err := f.secondAPI.ConsumeRelay(create.ID); status(err) != http.StatusForbidden {
		t.Fatalf("sender consuming = %v", err)
	}
	if response, err := f.firstAPI.ConsumeRelay(create.ID); err != nil || response.State != protocol.RelayPending || response.Envelope != nil {
		t.Fatalf("pending consume %+v %v", response, err)
	}
	if err := f.secondAPI.SealRelay(create.ID, seal); err != nil {
		t.Fatal(err)
	}
	if err := f.secondAPI.SealRelay(create.ID, seal); status(err) != http.StatusConflict {
		t.Fatalf("second seal = %v", err)
	}
	if listed, _ := f.secondAPI.ListRelays(); len(listed) != 0 {
		t.Fatal("sealed request still listed as pending")
	}
	response, err := f.firstAPI.ConsumeRelay(create.ID)
	if err != nil || response.State != protocol.RelayConsumed || response.Envelope == nil {
		t.Fatalf("consume %+v %v", response, err)
	}
	value, err := relay.Open(onTarget, f.vaultKey, f.firstKeys.Secrets.WrappingPrivate, *response.Envelope, f.clock.Now())
	if err != nil || string(value) != relayMarker {
		t.Fatalf("open %v", err)
	}
	if _, err := f.firstAPI.ConsumeRelay(create.ID); !errors.Is(err, client.ErrRelayGone) {
		t.Fatalf("second fetch = %v", err)
	}
	if err := f.firstAPI.CancelRelay(create.ID); status(err) != http.StatusConflict {
		t.Fatalf("cancel after consume = %v", err)
	}
	// An id cannot be reused while its tombstone exists.
	if _, err := f.firstAPI.CreateRelay(create); status(err) != http.StatusConflict {
		t.Fatalf("id reuse = %v", err)
	}
	if _, err := f.firstAPI.ConsumeRelay("AAAAAAAAAAAAAAAAAAAAAAAA"); status(err) != http.StatusNotFound {
		t.Fatalf("unknown relay = %v", err)
	}
	// Cancellation by the target makes a later seal fail.
	create2, _ := f.create(t)
	seal2 := f.sealRequest(t)
	if err := f.secondAPI.CancelRelay(create2.ID); status(err) != http.StatusForbidden {
		t.Fatalf("sender cancel = %v", err)
	}
	if err := f.firstAPI.CancelRelay(create2.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.secondAPI.SealRelay(create2.ID, seal2); status(err) != http.StatusConflict {
		t.Fatalf("seal after cancel = %v", err)
	}
	// A revoked sender can no longer act.
	create3, _ := f.create(t)
	seal3 := f.sealRequest(t)
	if _, err := f.firstAPI.RevokeDevice(f.secondID); err != nil {
		t.Fatal(err)
	}
	if err := f.secondAPI.SealRelay(create3.ID, seal3); status(err) != http.StatusUnauthorized {
		t.Fatalf("revoked sender seal = %v", err)
	}
}

func TestRelayExpiresOnServerClock(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	f := newRelayFixture(t, service)
	create, _ := f.create(t)
	seal := f.sealRequest(t)
	f.clock.Advance(protocol.RelayMaxTTL + time.Second)
	if err := f.secondAPI.SealRelay(create.ID, seal); !errors.Is(err, client.ErrRelayGone) {
		t.Fatalf("expired seal = %v", err)
	}
	created2, _ := f.create(t)
	if err := f.secondAPI.SealRelay(created2.ID, f.sealRequest(t)); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(protocol.RelayMaxTTL)
	if _, err := f.firstAPI.ConsumeRelay(created2.ID); !errors.Is(err, client.ErrRelayGone) {
		t.Fatalf("expired consume = %v", err)
	}
	if listed, _ := f.secondAPI.ListRelays(); len(listed) != 0 {
		t.Fatal("expired request listed")
	}
}

func TestRelayCreationValidationAndRateLimits(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	f := newRelayFixture(t, service)
	base, _, _ := relay.NewRequest(f.vaultID, f.vaultKey, f.target, f.firstKeys.Secrets.SigningPrivate, f.sender,
		relay.Sink{Kind: relay.SinkIngest, Name: "N"}, "", f.clock.Now(), time.Minute)
	bigBlob, _ := secure.Seal(f.vaultKey, make([]byte, server.RelayLimits.DescriptorBytes+1), nil)
	for name, mutate := range map[string]func(r *protocol.RelayCreateRequest){
		"version":        func(r *protocol.RelayCreateRequest) { r.Version = 2 },
		"bad id":         func(r *protocol.RelayCreateRequest) { r.ID = "short" },
		"self as sender": func(r *protocol.RelayCreateRequest) { r.SenderDeviceID = f.firstID },
		"empty sender":   func(r *protocol.RelayCreateRequest) { r.SenderDeviceID = "" },
		"long expiry": func(r *protocol.RelayCreateRequest) {
			r.ExpiresAt = f.clock.Now().Add(6 * time.Minute).Format(time.RFC3339)
		},
		"past expiry": func(r *protocol.RelayCreateRequest) {
			r.ExpiresAt = f.clock.Now().Add(-time.Second).Format(time.RFC3339)
		},
		"noncanonical": func(r *protocol.RelayCreateRequest) {
			r.ExpiresAt = f.clock.Now().Add(time.Minute).Format(time.RFC3339Nano) + "x"
		},
		"big descriptor": func(r *protocol.RelayCreateRequest) { r.Descriptor = bigBlob },
		"bad descriptor": func(r *protocol.RelayCreateRequest) { r.Descriptor.Nonce = "!" },
		"unknown sender": func(r *protocol.RelayCreateRequest) { r.SenderDeviceID = "nobody" },
	} {
		request := base
		mutate(&request)
		_, err := f.firstAPI.CreateRelay(request)
		want := http.StatusBadRequest
		if name == "unknown sender" {
			want = http.StatusNotFound
		}
		if status(err) != want {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Per-target active limit.
	for i := 0; i < server.RelayLimits.ActivePerTarget; i++ {
		f.create(t)
	}
	create, _, _ := relay.NewRequest(f.vaultID, f.vaultKey, f.target, f.firstKeys.Secrets.SigningPrivate, f.sender,
		relay.Sink{Kind: relay.SinkIngest, Name: "N"}, "", f.clock.Now(), time.Minute)
	if _, err := f.firstAPI.CreateRelay(create); status(err) != http.StatusTooManyRequests {
		t.Fatalf("over active limit = %v", err)
	}
	// Envelope size and shape are bounded.
	pending, _, _ := relay.Pending(f.secondAPI, f.vaultID, f.vaultKey, f.sender, f.clock.Now())
	env, _ := relay.Seal(pending[0], f.vaultKey, f.secondKeys.Secrets.SigningPrivate, []byte(relayMarker), f.clock.Now())
	huge := env
	huge.Sealed.Blob.Ciphertext = secure.Encode(make([]byte, server.RelayLimits.SealBodyBytes))
	if err := f.secondAPI.SealRelay(pending[0].RequestID, protocol.RelaySealRequest{Version: 1, Envelope: huge}); status(err) != http.StatusBadRequest {
		t.Fatalf("oversized envelope = %v", err)
	}
	for name, mutate := range map[string]func(e *protocol.RelayEnvelope){
		"request id": func(e *protocol.RelayEnvelope) { e.RequestID = "other" },
		"sender id":  func(e *protocol.RelayEnvelope) { e.SenderDeviceID = f.firstID },
		"signature":  func(e *protocol.RelayEnvelope) { e.Signature = "AAAA" },
		"mac":        func(e *protocol.RelayEnvelope) { e.VaultMAC = "" },
		"ephemeral":  func(e *protocol.RelayEnvelope) { e.Sealed.EphemeralKey = "AAAA" },
	} {
		bad := env
		mutate(&bad)
		if err := f.secondAPI.SealRelay(pending[0].RequestID, protocol.RelaySealRequest{Version: 1, Envelope: bad}); status(err) != http.StatusBadRequest {
			t.Fatalf("envelope %s = %v", name, err)
		}
	}
	// Hourly creation limit counts tombstones.
	for i := 0; i < server.RelayLimits.CreatedPerHour; i++ {
		listed, _ := f.firstAPI.ListRelays()
		for _, r := range listed {
			_ = f.firstAPI.CancelRelay(r.ID)
		}
		create, _, _ := relay.NewRequest(f.vaultID, f.vaultKey, f.target, f.firstKeys.Secrets.SigningPrivate, f.sender,
			relay.Sink{Kind: relay.SinkIngest, Name: "N"}, "", f.clock.Now(), time.Minute)
		if _, err := f.firstAPI.CreateRelay(create); err != nil {
			if status(err) != http.StatusTooManyRequests {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("hourly creation limit not enforced")
}

func TestRelayDatabaseHoldsNoPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	service, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := newRelayFixture(t, service)
	create, _ := f.create(t)
	if err := f.secondAPI.SealRelay(create.ID, f.sealRequest(t)); err != nil {
		t.Fatal(err)
	}
	scan := func(stage string) {
		t.Helper()
		for _, suffix := range []string{"", "-wal"} {
			raw, err := os.ReadFile(path + suffix)
			if err != nil && suffix == "" {
				t.Fatal(err)
			}
			for _, marker := range []string{relayMarker, "RELAY_SINK_NAME", "server test"} {
				if bytes.Contains(raw, []byte(marker)) {
					t.Fatalf("%s: database%s contains %q", stage, suffix, marker)
				}
			}
		}
	}
	scan("sealed")
	if _, err := f.firstAPI.ConsumeRelay(create.ID); err != nil {
		t.Fatal(err)
	}
	scan("consumed")
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT name FROM pragma_table_info('relays')")
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		columns = append(columns, name)
	}
	rows.Close()
	sort.Strings(columns)
	if strings.Join(columns, ",") != "created_at,descriptor,envelope,expires_at,id,sender_device_id,state,target_device_id,vault_id" {
		t.Fatalf("relay columns %v", columns)
	}
	var descriptorLen int
	var envelope sql.NullString
	if err := db.QueryRow("SELECT length(descriptor), envelope FROM relays WHERE id = ?", create.ID).Scan(&descriptorLen, &envelope); err != nil {
		t.Fatal(err)
	}
	if descriptorLen != 0 || envelope.Valid {
		t.Fatal("consumed relay retains ciphertext")
	}
}

type recordingTransport struct {
	record  func(*http.Request)
	handler http.Handler
}

func (t recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.record(request)
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}
