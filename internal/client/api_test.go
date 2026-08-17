package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestAccessHeadersAreOutsideSignedMessage(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI("https://example.invalid")
	api.Config = &Config{VaultID: "vault", DeviceID: "device"}
	api.Secrets = keys.Secrets
	api.Access = &AccessCredentials{ClientID: "client-id", ClientSecret: "client-secret"}
	api.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("CF-Access-Client-Id") != "client-id" ||
			request.Header.Get("CF-Access-Client-Secret") != "client-secret" {
			t.Fatal("request omitted Cloudflare Access headers")
		}
		message := protocol.SignatureMessage(request.Method, request.URL.RequestURI(),
			request.Header.Get(protocol.HeaderTimestamp), request.Header.Get(protocol.HeaderNonce), nil)
		if !secure.Verify(keys.SigningPublic, message, request.Header.Get(protocol.HeaderSignature)) {
			t.Fatal("Access headers changed the EnvBank signature message")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("[]")), Header: make(http.Header)}, nil
	})}
	if _, err := api.ListRecords(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedRedirectIsRefusedWithoutForwardingHeaders(t *testing.T) {
	requests := 0
	api := NewAPI("https://source.example")
	api.Access = &AccessCredentials{ClientID: "client-id", ClientSecret: "client-secret"}
	api.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		location, _ := url.Parse("https://destination.example/v1/vaults")
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Body: io.NopCloser(bytes.NewReader(nil)),
			Header: http.Header{"Location": []string{location.String()}}}, nil
	})}
	err := api.do(http.MethodGet, "/v1/vaults", nil, nil, false)
	if !errors.Is(err, ErrAuthenticatedRedirect) {
		t.Fatalf("redirect error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("authenticated redirect performed %d requests", requests)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestEnrollmentCreationRejectsSubstitutedServerIdentity(t *testing.T) {
	expected, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	substitute, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	response := `{"device":{"id":"device","name":"new","signing_public":"` +
		substitute.SigningPublic + `","wrapping_public":"` + substitute.WrappingPublic +
		`","fingerprint":"` + secure.PublicFingerprint(substitute.SigningPublic,
		substitute.WrappingPublic) + `","created_at":"2026-08-06T12:00:00Z"}}`
	api := NewAPI("https://example.invalid")
	api.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewBufferString(response)),
			Header: make(http.Header)}, nil
	})}
	_, err = api.RequestEnrollment("vault", protocol.EnrollmentRequest{Name: "new",
		SigningPublic: expected.SigningPublic, WrappingPublic: expected.WrappingPublic})
	if err == nil {
		t.Fatal("substituted enrollment identity was accepted")
	}
}

func TestInvitationCreationRejectsStaleFingerprint(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	response := `{"version":1,"device":{"id":"device","name":"new","signing_public":"` +
		keys.SigningPublic + `","wrapping_public":"` + keys.WrappingPublic +
		`","fingerprint":"0000000000000000","created_at":"2026-08-06T12:00:00Z"},` +
		`"state":"pending","expires_at":"2026-08-06T12:10:00Z","attempts_remaining":5}`
	api := NewAPI("https://example.invalid")
	api.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewBufferString(response)),
			Header: make(http.Header)}, nil
	})}
	_, err = api.CreateInvitation("vault", protocol.InvitationRequest{
		Version: protocol.InvitationProtocolVersion, Name: "new",
		SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic})
	if err == nil {
		t.Fatal("stale invitation fingerprint was accepted")
	}
}

func TestValidateDeviceIdentityRejectsMismatch(t *testing.T) {
	first, _ := secure.NewDeviceKeys()
	second, _ := secure.NewDeviceKeys()
	device := protocol.PublicDevice{SigningPublic: first.SigningPublic,
		WrappingPublic: first.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(first.SigningPublic, first.WrappingPublic)}
	if err := ValidateDeviceIdentity(device, second.SigningPublic, second.WrappingPublic); err == nil {
		t.Fatal("identity mismatch was accepted")
	}
}

func TestUnwrapEnrollmentVaultKeyRejectsIdentityMismatchAndWrongSize(t *testing.T) {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	device := protocol.PublicDevice{ID: "device", SigningPublic: keys.SigningPublic,
		WrappingPublic: keys.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(keys.SigningPublic, keys.WrappingPublic)}
	envelope, err := secure.WrapVaultKey(make([]byte, 31), keys.WrappingPublic,
		"vault", "device")
	if err != nil {
		t.Fatal(err)
	}
	status := protocol.EnrollmentStatus{Device: device, Approved: true, Envelope: &envelope}
	if _, err := UnwrapEnrollmentVaultKey(status, keys.Secrets, "vault", "device"); err == nil {
		t.Fatal("incorrectly sized vault key was accepted")
	}
	envelope, err = secure.WrapVaultKey(make([]byte, 32), keys.WrappingPublic,
		"vault", "device")
	if err != nil {
		t.Fatal(err)
	}
	status.Envelope = &envelope
	if _, err := UnwrapEnrollmentVaultKey(status, wrong.Secrets, "vault", "device"); err == nil {
		t.Fatal("identity mismatched with local private keys was accepted")
	}
}
