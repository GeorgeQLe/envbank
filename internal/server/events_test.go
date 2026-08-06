package server

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	_ "modernc.org/sqlite"
)

func TestAccessEventPruningSeparatesVerifiedAndUnverifiedCaps(t *testing.T) {
	service, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	if _, err := service.db.Exec(`INSERT INTO vaults(id, name, created_at)
		VALUES ('vault', 'test', ?)`, now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	tx, err := service.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxVerifiedEvents; i++ {
		if _, err := tx.Exec(`INSERT INTO access_events(
			id, vault_id, timestamp, identity_id, identity_verified, operation, outcome
		) VALUES (?, 'vault', ?, 'device', 1, 'record_list', 'succeeded')`,
			fmt.Sprintf("v-%05d", i), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxUnverifiedEvents+1; i++ {
		if _, err := tx.Exec(`INSERT INTO access_events(
			id, vault_id, timestamp, identity_verified, operation, outcome
		) VALUES (?, 'vault', ?, 0, 'enrollment_request', 'rejected')`,
			fmt.Sprintf("u-%05d", i), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO access_events(
		id, vault_id, timestamp, identity_verified, operation, outcome
	) VALUES ('old', 'vault', ?, 0, 'enrollment_request', 'rejected')`,
		now.Add(-eventMaxAge-time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := service.insertAccessEvent(tx, "vault", eventDetails{
		identityID: "device", identityVerified: true,
		operation: "record_list", outcome: "succeeded",
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	for verified, want := range map[bool]int{true: maxVerifiedEvents, false: maxUnverifiedEvents} {
		var got int
		if err := service.db.QueryRow(`SELECT COUNT(*) FROM access_events
			WHERE vault_id = 'vault' AND identity_verified = ?`, verified).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("verified=%t count=%d, want %d", verified, got, want)
		}
	}
	var old int
	if err := service.db.QueryRow("SELECT COUNT(*) FROM access_events WHERE id = 'old'").Scan(&old); err != nil {
		t.Fatal(err)
	}
	if old != 0 {
		t.Fatal("90-day pruning retained an expired event")
	}
}

func TestEventPersistenceFailureRollsBackVerifiedOperationAndPublicEnrollment(t *testing.T) {
	service, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	api := NewTestAPI(service)
	created, err := api.CreateVault("test", protocol.PublicDevice{
		Name: "first", SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID}
	api.Secrets = keys.Secrets
	if _, err := service.db.Exec(`CREATE TRIGGER fail_access_events
		BEFORE INSERT ON access_events BEGIN SELECT RAISE(FAIL, 'forced event failure'); END`); err != nil {
		t.Fatal(err)
	}

	if _, err := api.PutRecord("opaque-record-id", protocol.PutRecordRequest{
		Blob: secure.Blob{Version: 1, Nonce: "opaque", Ciphertext: "secret-ciphertext"},
	}); err == nil {
		t.Fatal("record update succeeded despite forced event failure")
	}
	var records, nonces int
	if err := service.db.QueryRow("SELECT COUNT(*) FROM records").Scan(&records); err != nil {
		t.Fatal(err)
	}
	if err := service.db.QueryRow("SELECT COUNT(*) FROM nonces").Scan(&nonces); err != nil {
		t.Fatal(err)
	}
	if records != 0 || nonces != 0 {
		t.Fatalf("failed verified update left records=%d nonces=%d", records, nonces)
	}
	if _, err := api.ListRecords(); err == nil {
		t.Fatal("verified read succeeded despite forced event failure")
	}
	if err := service.db.QueryRow("SELECT COUNT(*) FROM nonces").Scan(&nonces); err != nil {
		t.Fatal(err)
	}
	if nonces != 0 {
		t.Fatalf("failed verified read left %d nonces", nonces)
	}

	badPublic := httptest.NewRequest(http.MethodPost,
		"/v1/vaults/"+created.VaultID+"/enrollments", http.NoBody)
	badPublicRecorder := httptest.NewRecorder()
	service.ServeHTTP(badPublicRecorder, badPublic)
	if badPublicRecorder.Code != http.StatusBadRequest {
		t.Fatalf("rejected public request status = %d, want 400", badPublicRecorder.Code)
	}

	badAuth := httptest.NewRequest(http.MethodGet,
		"/v1/vaults/"+created.VaultID+"/records", http.NoBody)
	badAuth.Header.Set(protocol.HeaderDevice, created.DeviceID)
	badAuth.Header.Set(protocol.HeaderTimestamp, time.Now().UTC().Format(time.RFC3339))
	badAuth.Header.Set(protocol.HeaderNonce, "bad-auth")
	badAuth.Header.Set(protocol.HeaderSignature, "invalid")
	badAuthRecorder := httptest.NewRecorder()
	service.ServeHTTP(badAuthRecorder, badAuth)
	if badAuthRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("failed authentication status = %d, want 401", badAuthRecorder.Code)
	}

	pending, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.RequestEnrollment(created.VaultID, protocol.EnrollmentRequest{
		Name: "pending", SigningPublic: pending.SigningPublic,
		WrappingPublic: pending.WrappingPublic,
	}); err == nil {
		t.Fatal("public enrollment succeeded despite forced event failure")
	}
	var enrollments int
	if err := service.db.QueryRow("SELECT COUNT(*) FROM enrollments").Scan(&enrollments); err != nil {
		t.Fatal(err)
	}
	if enrollments != 0 {
		t.Fatalf("failed public enrollment left %d rows", enrollments)
	}
}

func TestSchemaVersionTwoMigratesWithEmptyHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-two.db")
	service, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := service.db.Exec("INSERT INTO vaults VALUES ('vault', 'legacy', ?)", createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := service.db.Exec(`INSERT INTO devices(
		vault_id, id, name, signing_public, wrapping_public, fingerprint, created_at
	) VALUES ('vault', 'device', 'legacy', ?, ?, ?, ?)`, keys.SigningPublic,
		keys.WrappingPublic, secure.PublicFingerprint(keys.SigningPublic, keys.WrappingPublic),
		createdAt); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE access_events; PRAGMA user_version = 2;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var devices, events, version int
	if err := migrated.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRow("SELECT COUNT(*) FROM access_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if devices != 1 || events != 0 || version != 5 {
		t.Fatalf("migration result devices=%d events=%d version=%d", devices, events, version)
	}
}

type testHandlerTransport struct {
	handler http.Handler
}

func (t testHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func NewTestAPI(handler http.Handler) *client.API {
	api := client.NewAPI("http://envbank.test")
	api.HTTPClient = &http.Client{Transport: testHandlerTransport{handler: handler}}
	return api
}
