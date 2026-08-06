package server_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/server"
)

type vaultFixture struct {
	vaultID       string
	firstID       string
	secondID      string
	firstAPI      *client.API
	secondAPI     *client.API
	firstKeys     secure.DeviceKeys
	secondKeys    secure.DeviceKeys
	enrollmentID  string
	enrollmentKey secure.WrappedKey
}

func createTwoDeviceVault(t *testing.T, handler http.Handler) vaultFixture {
	t.Helper()
	httpClient := &http.Client{Transport: handlerTransport{handler: handler}}
	first, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	first.Secrets.VaultKey = secure.Encode(vaultKey)
	firstAPI := client.NewAPI("http://envbank.test")
	firstAPI.HTTPClient = httpClient
	created, err := firstAPI.CreateVault("test", protocol.PublicDevice{
		Name: "first", SigningPublic: first.SigningPublic, WrappingPublic: first.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID}
	firstAPI.Secrets = first.Secrets

	second, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := firstAPI.RequestEnrollment(created.VaultID, protocol.EnrollmentRequest{
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
	if err := firstAPI.ApproveEnrollment(enrollment.Device.ID, envelope); err != nil {
		t.Fatal(err)
	}
	second.Secrets.VaultKey = secure.Encode(vaultKey)
	secondAPI := client.NewAPI("http://envbank.test")
	secondAPI.HTTPClient = httpClient
	secondAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: enrollment.Device.ID}
	secondAPI.Secrets = second.Secrets
	return vaultFixture{
		vaultID: created.VaultID, firstID: created.DeviceID, secondID: enrollment.Device.ID,
		firstAPI: firstAPI, secondAPI: secondAPI, firstKeys: first, secondKeys: second,
		enrollmentID: enrollment.Device.ID, enrollmentKey: envelope,
	}
}

func TestAPIResponsesDisableCachingAndSniffing(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestMultiDeviceEnrollmentAndRecordSync(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	httpClient := &http.Client{Transport: handlerTransport{handler: service}}

	first, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, _ := secure.RandomBytes(32)
	first.Secrets.VaultKey = secure.Encode(vaultKey)
	firstAPI := client.NewAPI("http://envbank.test")
	firstAPI.HTTPClient = httpClient
	created, err := firstAPI.CreateVault("test", protocol.PublicDevice{
		Name: "first", SigningPublic: first.SigningPublic, WrappingPublic: first.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID}
	firstAPI.Secrets = first.Secrets

	second, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	status, err := firstAPI.RequestEnrollment(created.VaultID, protocol.EnrollmentRequest{
		Name: "second", SigningPublic: second.SigningPublic, WrappingPublic: second.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondAPI := client.NewAPI("http://envbank.test")
	secondAPI.HTTPClient = httpClient
	secondAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: status.Device.ID}
	secondAPI.Secrets = second.Secrets
	pendingStatus, err := secondAPI.GetEnrollment(status.Device.ID)
	if err != nil || pendingStatus.Approved {
		t.Fatalf("pending enrollment could not authenticate: %#v, %v", pendingStatus, err)
	}
	pending, err := firstAPI.ListEnrollments()
	if err != nil || len(pending) != 1 {
		t.Fatalf("unexpected pending enrollments: %#v, %v", pending, err)
	}
	envelope, err := secure.WrapVaultKey(vaultKey, second.WrappingPublic, created.VaultID, status.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstAPI.ApproveEnrollment(status.Device.ID, envelope); err != nil {
		t.Fatal(err)
	}

	approved, err := secondAPI.GetEnrollment(status.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := secure.UnwrapVaultKey(*approved.Envelope, second.Secrets.WrappingPrivate,
		created.VaultID, status.Device.ID)
	if err != nil || !bytes.Equal(unwrapped, vaultKey) {
		t.Fatalf("vault key unwrap failed: %v", err)
	}

	secret := protocol.SecretRecord{
		Name: "DATABASE_URL", Value: "not-a-real-secret", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		RotatedAt: time.Now().UTC().Format(time.RFC3339), RotateEveryDays: 30, Revision: 1,
	}
	id, blob, err := client.EncryptRecord(created.VaultID, vaultKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstAPI.PutRecord(id, protocol.PutRecordRequest{Blob: blob}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := secondAPI.ListRecords()
	if err != nil {
		t.Fatal(err)
	}
	records, err := client.DecryptRecords(created.VaultID, unwrapped, encrypted)
	if err != nil || len(records) != 1 || records[0].Value != secret.Value {
		t.Fatalf("synced record mismatch: %#v, %v", records, err)
	}
}

func TestSharedDatabaseSerializesConcurrentRevisionUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	firstService, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstService.Close()
	secondService, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondService.Close()

	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	keys.Secrets.VaultKey = secure.Encode(vaultKey)
	firstAPI := client.NewAPI("http://envbank.test")
	firstAPI.HTTPClient = &http.Client{Transport: handlerTransport{handler: firstService}}
	created, err := firstAPI.CreateVault("shared", protocol.PublicDevice{
		Name: "first", SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}

	newAPI := func(handler http.Handler) *client.API {
		api := client.NewAPI("http://envbank.test")
		api.HTTPClient = &http.Client{Transport: handlerTransport{handler: handler}}
		api.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID}
		api.Secrets = keys.Secrets
		return api
	}
	apis := []*client.API{newAPI(firstService), newAPI(secondService)}
	record := protocol.SecretRecord{
		Name: "SHARED", Value: "ciphertext", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		RotatedAt: time.Now().UTC().Format(time.RFC3339), Revision: 1,
	}
	id, blob, err := client.EncryptRecord(created.VaultID, vaultKey, record)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, len(apis))
	var workers sync.WaitGroup
	for _, api := range apis {
		workers.Add(1)
		go func(api *client.API) {
			defer workers.Done()
			<-start
			_, err := api.PutRecord(id, protocol.PutRecordRequest{Blob: blob})
			results <- err
		}(api)
	}
	close(start)
	workers.Wait()
	close(results)

	var successes, conflicts int
	for err := range results {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "revision conflict") {
			conflicts++
		} else {
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("got %d successes and %d conflicts; want one of each", successes, conflicts)
	}
}

func TestOpenMigratesLegacyJSONState(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	device := protocol.PublicDevice{
		ID: "device", Name: "legacy", SigningPublic: keys.SigningPublic,
		WrappingPublic: keys.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(keys.SigningPublic, keys.WrappingPublic),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	state := server.State{
		Version: 1,
		Vaults: map[string]*server.Vault{
			"vault": {
				ID: "vault", Name: "legacy", CreatedAt: time.Now().UTC().Format(time.RFC3339),
				Devices:     map[string]protocol.PublicDevice{"device": device},
				Enrollments: map[string]*server.Enrollment{},
				Records:     map[string]protocol.Record{},
			},
		},
		Nonces: map[string]string{},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	service, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	api := client.NewAPI("http://envbank.test")
	api.HTTPClient = &http.Client{Transport: handlerTransport{handler: service}}
	api.Config = &client.Config{VaultID: "vault", DeviceID: "device"}
	api.Secrets = keys.Secrets
	records, err := api.ListRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("unexpected migrated records: %#v", records)
	}
	if _, err := os.Stat(path + ".json.bak"); err != nil {
		t.Fatalf("legacy backup was not preserved: %v", err)
	}
	header := make([]byte, 16)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Read(header); err != nil {
		t.Fatal(err)
	}
	if string(header) != "SQLite format 3\x00" {
		t.Fatalf("migrated file is not SQLite: %q", header)
	}
}

func TestDeviceRevocationPersistsAndBlocksApprovedDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	service, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := createTwoDeviceVault(t, service)

	devices, err := fixture.firstAPI.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}
	for i, device := range devices {
		if device.RevokedAt != "" {
			t.Fatalf("device %d started revoked: %#v", i, device)
		}
		if i > 0 {
			previous := devices[i-1].Device
			current := device.Device
			if previous.CreatedAt > current.CreatedAt ||
				(previous.CreatedAt == current.CreatedAt && previous.ID > current.ID) {
				t.Fatalf("devices are not deterministically ordered: %#v", devices)
			}
		}
	}
	if _, err := fixture.secondAPI.ListDevices(); err != nil {
		t.Fatalf("second device could not establish a replay nonce: %v", err)
	}

	revoked, err := fixture.firstAPI.RevokeDevice(fixture.secondID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == "" || revoked.Device.ID != fixture.secondID {
		t.Fatalf("unexpected revocation response: %#v", revoked)
	}
	if _, err := fixture.secondAPI.ListRecords(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("revoked record access was not rejected: %v", err)
	}
	if _, err := fixture.secondAPI.GetEnrollment(fixture.secondID); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("revoked approved enrollment access was not rejected: %v", err)
	}
	vaultKey, err := secure.Decode(fixture.firstKeys.Secrets.VaultKey)
	if err != nil {
		t.Fatal(err)
	}
	recordID, blob, err := client.EncryptRecord(fixture.vaultID, vaultKey,
		protocol.SecretRecord{Name: "STILL_ACTIVE", Value: "ciphertext", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.firstAPI.PutRecord(recordID, protocol.PutRecordRequest{Blob: blob}); err != nil {
		t.Fatalf("remaining device lost record update access: %v", err)
	}
	records, err := fixture.firstAPI.ListRecords()
	if err != nil || len(records) != 1 {
		t.Fatalf("remaining device lost record read access: %#v, %v", records, err)
	}
	if _, err := fixture.firstAPI.RevokeDevice(fixture.secondID); err == nil ||
		!strings.Contains(err.Error(), "409") {
		t.Fatalf("repeated revocation did not conflict: %v", err)
	}
	enrollments, err := fixture.firstAPI.ListEnrollments()
	if err != nil {
		t.Fatal(err)
	}
	if len(enrollments) != 1 || enrollments[0].RevokedAt != revoked.RevokedAt {
		t.Fatalf("enrollment listing did not report revocation: %#v", enrollments)
	}

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	check, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	var targetNonces int
	if err := check.QueryRow("SELECT COUNT(*) FROM nonces WHERE vault_id = ? AND device_id = ?",
		fixture.vaultID, fixture.secondID).Scan(&targetNonces); err != nil {
		t.Fatal(err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	if targetNonces != 2 {
		t.Fatalf("got %d post-revocation denial nonces, want 2", targetNonces)
	}
	reopened, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fixture.firstAPI.HTTPClient = &http.Client{Transport: handlerTransport{handler: reopened}}
	devices, err = fixture.firstAPI.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	var persisted string
	for _, device := range devices {
		if device.Device.ID == fixture.secondID {
			persisted = device.RevokedAt
		}
	}
	if persisted != revoked.RevokedAt {
		t.Fatalf("revocation timestamp changed across restart: got %q want %q", persisted, revoked.RevokedAt)
	}
}

func TestSelfAndFinalDeviceRevocation(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixture := createTwoDeviceVault(t, service)

	if _, err := fixture.firstAPI.RevokeDevice("missing-device"); err == nil ||
		!strings.Contains(err.Error(), "404") {
		t.Fatalf("unknown device revocation did not return 404: %v", err)
	}
	revoked, err := fixture.secondAPI.RevokeDevice(fixture.secondID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == "" {
		t.Fatal("self-revocation did not return a timestamp")
	}
	if _, err := fixture.secondAPI.ListDevices(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("self-revoked caller remained active: %v", err)
	}
	if _, err := fixture.firstAPI.ListDevices(); err != nil {
		t.Fatalf("other device stopped working: %v", err)
	}
	if _, err := fixture.firstAPI.RevokeDevice(fixture.firstID); err == nil ||
		!strings.Contains(err.Error(), "409") {
		t.Fatalf("final active device revocation did not conflict: %v", err)
	}
}

func TestConcurrentMutualRevocationLeavesOneActiveDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	firstService, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstService.Close()
	secondService, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondService.Close()
	fixture := createTwoDeviceVault(t, firstService)
	fixture.secondAPI.HTTPClient = &http.Client{Transport: handlerTransport{handler: secondService}}

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := fixture.firstAPI.RevokeDevice(fixture.secondID)
		results <- err
	}()
	go func() {
		<-start
		_, err := fixture.secondAPI.RevokeDevice(fixture.firstID)
		results <- err
	}()
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "401") {
			conflicts++
		} else {
			t.Fatalf("unexpected mutual-revocation error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("got %d successes and %d conflicts; want one each", successes, conflicts)
	}
	var active int
	for _, api := range []*client.API{fixture.firstAPI, fixture.secondAPI} {
		if _, err := api.ListDevices(); err == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("got %d active authenticating devices, want 1", active)
	}
}

func TestVersionOneSQLiteMigratesDevicesAsActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-one.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	schema := `CREATE TABLE vaults (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE devices (
	vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, id TEXT NOT NULL,
	name TEXT NOT NULL, signing_public TEXT NOT NULL, wrapping_public TEXT NOT NULL,
	fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (vault_id, id));
CREATE TABLE enrollments (
	vault_id TEXT NOT NULL, device_id TEXT NOT NULL, name TEXT NOT NULL,
	signing_public TEXT NOT NULL, wrapping_public TEXT NOT NULL, fingerprint TEXT NOT NULL,
	created_at TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0, envelope BLOB,
	PRIMARY KEY (vault_id, device_id));
CREATE TABLE records (
	vault_id TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
	blob BLOB NOT NULL, modified_at TEXT NOT NULL, PRIMARY KEY (vault_id, id));
CREATE TABLE nonces (
	vault_id TEXT NOT NULL, device_id TEXT NOT NULL, nonce TEXT NOT NULL,
	created_at TEXT NOT NULL, PRIMARY KEY (vault_id, device_id, nonce));
CREATE INDEX nonces_created_at ON nonces(created_at);
PRAGMA user_version = 1;`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO vaults VALUES (?, ?, ?)", "vault", "legacy", createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"vault", "device", "legacy", keys.SigningPublic, keys.WrappingPublic,
		secure.PublicFingerprint(keys.SigningPublic, keys.WrappingPublic), createdAt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	service, err := server.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	check, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	var migratedEvents int
	if err := check.QueryRow("SELECT COUNT(*) FROM access_events").Scan(&migratedEvents); err != nil {
		t.Fatal(err)
	}
	if migratedEvents != 0 {
		t.Fatalf("version-one migration created %d access events", migratedEvents)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	api := client.NewAPI("http://envbank.test")
	api.HTTPClient = &http.Client{Transport: handlerTransport{handler: service}}
	api.Config = &client.Config{VaultID: "vault", DeviceID: "device"}
	api.Secrets = keys.Secrets
	devices, err := api.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].RevokedAt != "" {
		t.Fatalf("version-one device did not migrate as active: %#v", devices)
	}
	check, err = sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version int
	if err := check.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 3 {
		t.Fatalf("schema version = %d, err %v; want 3", version, err)
	}
}

func TestAccessEventsRecordOperationsAndPreservePrivacy(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixture := createTwoDeviceVault(t, service)

	vaultKey, err := secure.Decode(fixture.firstKeys.Secrets.VaultKey)
	if err != nil {
		t.Fatal(err)
	}
	const secretName = "EVENT_PRIVACY_SENTINEL"
	const secretValue = "never-store-this-secret"
	recordID, blob, err := client.EncryptRecord(fixture.vaultID, vaultKey,
		protocol.SecretRecord{Name: secretName, Value: secretValue, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.firstAPI.PutRecord(recordID,
		protocol.PutRecordRequest{Blob: blob}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.secondAPI.ListRecords(); err != nil {
		t.Fatal(err)
	}
	page, err := fixture.firstAPI.ListAccessEvents(100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) == 0 || page.Events[0].Operation != "event_list" ||
		page.Events[0].IdentityID != fixture.firstID || !page.Events[0].IdentityVerified {
		t.Fatalf("event-list did not record itself first: %#v", page.Events)
	}
	operations := map[string]bool{}
	for _, event := range page.Events {
		operations[event.Operation] = true
	}
	for _, operation := range []string{
		"enrollment_request", "enrollment_approval", "record_update", "record_list", "event_list",
	} {
		if !operations[operation] {
			t.Errorf("missing %s event in %#v", operation, page.Events)
		}
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secretName, secretValue, recordID, blob.Ciphertext} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("access-event response contains forbidden data %q", forbidden)
		}
	}
}

func TestAccessEventCursorAndLimitValidation(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixture := createTwoDeviceVault(t, service)
	for range 3 {
		if _, err := fixture.firstAPI.ListDevices(); err != nil {
			t.Fatal(err)
		}
	}
	first, err := fixture.firstAPI.ListAccessEvents(2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || first.NextCursor == "" {
		t.Fatalf("unexpected first event page: %#v", first)
	}
	second, err := fixture.firstAPI.ListAccessEvents(2, first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) == 0 {
		t.Fatal("second event page is empty")
	}
	for _, left := range first.Events {
		for _, right := range second.Events {
			if left.ID == right.ID {
				t.Fatalf("event %s appeared on both cursor pages", left.ID)
			}
		}
	}
	if _, err := fixture.firstAPI.ListAccessEvents(501, ""); err == nil ||
		!strings.Contains(err.Error(), "400") {
		t.Fatalf("invalid event limit error = %v", err)
	}
}

func TestAccessEventsAttributeAuthenticationFailuresTruthfully(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixture := createTwoDeviceVault(t, service)

	path := "/v1/vaults/" + fixture.vaultID + "/devices"
	now := time.Now().UTC().Format(time.RFC3339)
	if status := signedStatus(t, service, http.MethodGet, path, fixture.firstID,
		fixture.firstKeys.Secrets.SigningPrivate, now, "invalid-signature", nil, true); status != 401 {
		t.Fatalf("invalid-signature status = %d", status)
	}
	if status := signedStatus(t, service, http.MethodGet, path, fixture.firstID,
		fixture.firstKeys.Secrets.SigningPrivate,
		time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339),
		"stale", nil, false); status != 401 {
		t.Fatalf("stale status = %d", status)
	}
	if status := signedStatus(t, service, http.MethodGet, path, fixture.firstID,
		fixture.firstKeys.Secrets.SigningPrivate, now, "replay", nil, false); status != 200 {
		t.Fatalf("initial replay status = %d", status)
	}
	if status := signedStatus(t, service, http.MethodGet, path, fixture.firstID,
		fixture.firstKeys.Secrets.SigningPrivate, now, "replay", nil, false); status != 401 {
		t.Fatalf("replayed status = %d", status)
	}

	pendingKeys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := fixture.firstAPI.RequestEnrollment(fixture.vaultID, protocol.EnrollmentRequest{
		Name: "pending", SigningPublic: pendingKeys.SigningPublic,
		WrappingPublic: pendingKeys.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	recordsPath := "/v1/vaults/" + fixture.vaultID + "/records"
	if status := signedStatus(t, service, http.MethodGet, recordsPath, pending.Device.ID,
		pendingKeys.Secrets.SigningPrivate, now, "pending", nil, false); status != 401 {
		t.Fatalf("pending status = %d", status)
	}
	unknownKeys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if status := signedStatus(t, service, http.MethodGet, recordsPath, "attacker-chosen-id",
		unknownKeys.Secrets.SigningPrivate, now, "unknown", nil, false); status != 401 {
		t.Fatalf("unknown status = %d", status)
	}
	if _, err := fixture.firstAPI.RevokeDevice(fixture.secondID); err != nil {
		t.Fatal(err)
	}
	if status := signedStatus(t, service, http.MethodGet, recordsPath, fixture.secondID,
		fixture.secondKeys.Secrets.SigningPrivate, now, "revoked", nil, false); status != 401 {
		t.Fatalf("revoked status = %d", status)
	}

	page, err := fixture.firstAPI.ListAccessEvents(100, "")
	if err != nil {
		t.Fatal(err)
	}
	type attribution struct {
		identity string
		verified bool
	}
	got := map[string]attribution{}
	for _, event := range page.Events {
		if event.Outcome == "denied" {
			got[event.Reason] = attribution{event.IdentityID, event.IdentityVerified}
		}
	}
	want := map[string]attribution{
		"invalid_signature": {fixture.firstID, false},
		"stale_timestamp":   {fixture.firstID, true},
		"replay":            {fixture.firstID, true},
		"pending_device":    {pending.Device.ID, true},
		"unknown_device":    {"", false},
		"revoked_device":    {fixture.secondID, true},
	}
	for reason, expected := range want {
		if got[reason] != expected {
			t.Errorf("%s attribution = %#v, want %#v", reason, got[reason], expected)
		}
	}
}

func signedStatus(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	deviceID string,
	privateKey string,
	timestamp string,
	nonce string,
	body []byte,
	corruptSignature bool,
) int {
	t.Helper()
	signature, err := secure.Sign(privateKey,
		protocol.SignatureMessage(method, path, timestamp, nonce, body))
	if err != nil {
		t.Fatal(err)
	}
	if corruptSignature {
		signature = "invalid"
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set(protocol.HeaderDevice, deviceID)
	request.Header.Set(protocol.HeaderTimestamp, timestamp)
	request.Header.Set(protocol.HeaderNonce, nonce)
	request.Header.Set(protocol.HeaderSignature, signature)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}
