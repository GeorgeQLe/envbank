package server_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/server"
)

func TestMultiDeviceEnrollmentAndRecordSync(t *testing.T) {
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
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

	secondAPI := client.NewAPI("http://envbank.test")
	secondAPI.HTTPClient = httpClient
	secondAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: status.Device.ID}
	secondAPI.Secrets = second.Secrets
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

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}
