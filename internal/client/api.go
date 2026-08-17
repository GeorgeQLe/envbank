package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

type API struct {
	BaseURL    string
	HTTPClient *http.Client
	Config     *Config
	Secrets    secure.DeviceSecrets
	Now        func() time.Time
	Access     *AccessCredentials
}

var ErrAuthenticatedRedirect = errors.New("refusing to follow a redirect for an authenticated request")

func NewAPI(baseURL string) *API {
	return &API{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *API) CreateVault(name string, device protocol.PublicDevice) (protocol.CreateVaultResponse, error) {
	var response protocol.CreateVaultResponse
	err := a.do(http.MethodPost, "/v1/vaults", protocol.CreateVaultRequest{Name: name, Device: device}, &response, false)
	return response, err
}

func (a *API) RequestEnrollment(vaultID string, request protocol.EnrollmentRequest) (protocol.EnrollmentStatus, error) {
	var response protocol.EnrollmentStatus
	err := a.do(http.MethodPost, "/v1/vaults/"+url.PathEscape(vaultID)+"/enrollments", request, &response, false)
	if err == nil {
		err = validateCreatedIdentity(response.Device, request.Name,
			request.SigningPublic, request.WrappingPublic)
	}
	return response, err
}

func (a *API) ListEnrollments() ([]protocol.EnrollmentStatus, error) {
	var response []protocol.EnrollmentStatus
	err := a.do(http.MethodGet, a.vaultPath()+"/enrollments", nil, &response, true)
	return response, err
}

func (a *API) GetEnrollment(deviceID string) (protocol.EnrollmentStatus, error) {
	var response protocol.EnrollmentStatus
	err := a.do(http.MethodGet, a.vaultPath()+"/enrollments/"+url.PathEscape(deviceID), nil, &response, true)
	return response, err
}

func (a *API) ApproveEnrollment(deviceID string, envelope secure.WrappedKey) error {
	return a.do(http.MethodPost, a.vaultPath()+"/enrollments/"+url.PathEscape(deviceID),
		protocol.EnrollmentApproval{Envelope: envelope}, nil, true)
}

func (a *API) CreateInvitation(vaultID string, request protocol.InvitationRequest) (protocol.InvitationStatus, error) {
	var response protocol.InvitationStatus
	err := a.do(http.MethodPost, "/v1/vaults/"+url.PathEscape(vaultID)+"/invitations",
		request, &response, false)
	if err == nil {
		err = validateCreatedIdentity(response.Device, request.Name,
			request.SigningPublic, request.WrappingPublic)
	}
	return response, err
}

func (a *API) ListInvitations() ([]protocol.InvitationStatus, error) {
	var response []protocol.InvitationStatus
	err := a.do(http.MethodGet, a.vaultPath()+"/invitations", nil, &response, true)
	return response, err
}

func (a *API) GetInvitation(deviceID string) (protocol.InvitationStatus, error) {
	var response protocol.InvitationStatus
	err := a.do(http.MethodGet, a.vaultPath()+"/invitations/"+url.PathEscape(deviceID),
		nil, &response, true)
	return response, err
}

func (a *API) ApproveInvitation(deviceID string, approval protocol.InvitationApproval) (protocol.InvitationStatus, error) {
	var response protocol.InvitationStatus
	err := a.do(http.MethodPost, a.vaultPath()+"/invitations/"+
		url.PathEscape(deviceID)+"/approve", approval, &response, true)
	return response, err
}

func (a *API) RejectInvitation(deviceID string, transition protocol.InvitationTransition) (protocol.InvitationStatus, error) {
	var response protocol.InvitationStatus
	err := a.do(http.MethodPost, a.vaultPath()+"/invitations/"+
		url.PathEscape(deviceID)+"/reject", transition, &response, true)
	return response, err
}

func (a *API) CancelInvitation(deviceID string, transition protocol.InvitationTransition) (protocol.InvitationStatus, error) {
	var response protocol.InvitationStatus
	err := a.do(http.MethodPost, a.vaultPath()+"/invitations/"+
		url.PathEscape(deviceID)+"/cancel", transition, &response, true)
	return response, err
}

func (a *API) ListDevices() ([]protocol.DeviceStatus, error) {
	var response []protocol.DeviceStatus
	err := a.do(http.MethodGet, a.vaultPath()+"/devices", nil, &response, true)
	return response, err
}

func (a *API) RevokeDevice(deviceID string) (protocol.DeviceStatus, error) {
	var response protocol.DeviceStatus
	err := a.do(http.MethodDelete, a.vaultPath()+"/devices/"+url.PathEscape(deviceID), nil, &response, true)
	return response, err
}

func (a *API) ListRecords() ([]protocol.Record, error) {
	var response []protocol.Record
	err := a.do(http.MethodGet, a.vaultPath()+"/records", nil, &response, true)
	return response, err
}

func (a *API) PutRecord(recordID string, request protocol.PutRecordRequest) (protocol.Record, error) {
	var response protocol.Record
	err := a.do(http.MethodPut, a.vaultPath()+"/records/"+url.PathEscape(recordID), request, &response, true)
	return response, err
}

func (a *API) ListVaultObjects() ([]protocol.EncryptedVaultObject, error) {
	var response []protocol.EncryptedVaultObject
	err := a.do(http.MethodGet, a.vaultPath()+"/objects", nil, &response, true)
	return response, err
}

func (a *API) GetVaultObject(objectID string) (protocol.EncryptedVaultObject, error) {
	var response protocol.EncryptedVaultObject
	err := a.do(http.MethodGet, a.vaultPath()+"/objects/"+url.PathEscape(objectID), nil, &response, true)
	return response, err
}

func (a *API) PutVaultObject(objectID string, request protocol.PutVaultObjectRequest) (protocol.EncryptedVaultObject, error) {
	var response protocol.EncryptedVaultObject
	err := a.do(http.MethodPut, a.vaultPath()+"/objects/"+url.PathEscape(objectID), request, &response, true)
	return response, err
}

func (a *API) DeleteVaultObject(objectID string, expectedRevision int64) error {
	return a.do(http.MethodDelete, a.vaultPath()+"/objects/"+url.PathEscape(objectID),
		protocol.DeleteVaultObjectRequest{ExpectedRevision: expectedRevision}, nil, true)
}

func (a *API) ListAccessEvents(limit int, before string) (protocol.AccessEventPage, error) {
	var response protocol.AccessEventPage
	values := url.Values{}
	if limit != 0 {
		values.Set("limit", fmt.Sprint(limit))
	}
	if before != "" {
		values.Set("before", before)
	}
	path := a.vaultPath() + "/access-events"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	err := a.do(http.MethodGet, path, nil, &response, true)
	return response, err
}

func (a *API) vaultPath() string {
	return "/v1/vaults/" + url.PathEscape(a.Config.VaultID)
}

func (a *API) do(method, path string, request any, response any, authenticated bool) error {
	var body []byte
	var err error
	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, a.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Access != nil {
		if err := a.Access.Validate(); err != nil {
			return err
		}
		req.Header.Set("CF-Access-Client-Id", a.Access.ClientID)
		req.Header.Set("CF-Access-Client-Secret", a.Access.ClientSecret)
	}
	if authenticated {
		if a.Config == nil || a.Secrets.SigningPrivate == "" {
			return errors.New("authenticated client is not unlocked")
		}
		now := time.Now
		if a.Now != nil {
			now = a.Now
		}
		timestamp := now().UTC().Format(time.RFC3339)
		nonceBytes, err := secure.RandomBytes(18)
		if err != nil {
			return err
		}
		nonce := secure.Encode(nonceBytes)
		signature, err := secure.Sign(a.Secrets.SigningPrivate,
			protocol.SignatureMessage(method, path, timestamp, nonce, body))
		if err != nil {
			return err
		}
		req.Header.Set(protocol.HeaderDevice, a.Config.DeviceID)
		req.Header.Set(protocol.HeaderTimestamp, timestamp)
		req.Header.Set(protocol.HeaderNonce, nonce)
		req.Header.Set(protocol.HeaderSignature, signature)
	}
	httpClient := a.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	clientCopy := *httpClient
	originalRedirectPolicy := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(redirect *http.Request, via []*http.Request) error {
		for _, header := range []string{
			"CF-Access-Client-Id", "CF-Access-Client-Secret", protocol.HeaderDevice,
			protocol.HeaderTimestamp, protocol.HeaderNonce, protocol.HeaderSignature,
		} {
			redirect.Header.Del(header)
		}
		if a.Access != nil || authenticated {
			return ErrAuthenticatedRedirect
		}
		if originalRedirectPolicy != nil {
			return originalRedirectPolicy(redirect, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	res, err := clientCopy.Do(req)
	if err != nil {
		return fmt.Errorf("server request failed: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var serverError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &serverError) == nil && serverError.Error != "" {
			return fmt.Errorf("server returned %d: %s", res.StatusCode, serverError.Error)
		}
		return fmt.Errorf("server returned %d", res.StatusCode)
	}
	if response != nil && len(raw) != 0 {
		if err := json.Unmarshal(raw, response); err != nil {
			return fmt.Errorf("invalid server response: %w", err)
		}
	}
	return nil
}

func validateCreatedIdentity(
	device protocol.PublicDevice,
	expectedName, expectedSigning, expectedWrapping string,
) error {
	if device.ID == "" || device.Name != expectedName ||
		device.SigningPublic != expectedSigning || device.WrappingPublic != expectedWrapping {
		return errors.New("server-returned enrollment identity does not match locally generated identity")
	}
	if err := secure.ValidatePublicDeviceKeys(device.SigningPublic, device.WrappingPublic); err != nil {
		return errors.New("server-returned enrollment identity is invalid")
	}
	fingerprint := secure.PublicFingerprint(device.SigningPublic, device.WrappingPublic)
	if device.Fingerprint != fingerprint {
		return errors.New("server-returned enrollment fingerprint is invalid")
	}
	return nil
}

// ValidateDeviceIdentity binds a server-returned identity to expected public
// keys and its locally recomputed fingerprint.
func ValidateDeviceIdentity(
	device protocol.PublicDevice,
	expectedSigning, expectedWrapping string,
) error {
	if device.SigningPublic != expectedSigning || device.WrappingPublic != expectedWrapping {
		return errors.New("server-returned enrollment identity does not match local keys")
	}
	if err := secure.ValidatePublicDeviceKeys(device.SigningPublic, device.WrappingPublic); err != nil {
		return errors.New("server-returned enrollment identity is invalid")
	}
	if device.Fingerprint != secure.PublicFingerprint(device.SigningPublic, device.WrappingPublic) {
		return errors.New("server-returned enrollment fingerprint is invalid")
	}
	return nil
}

// UnwrapEnrollmentVaultKey verifies that the returned identity is derived from
// local private keys before accepting a 256-bit vault key.
func UnwrapEnrollmentVaultKey(
	status protocol.EnrollmentStatus,
	secrets secure.DeviceSecrets,
	vaultID, deviceID string,
) ([]byte, error) {
	if status.Device.ID != deviceID || status.Envelope == nil {
		return nil, errors.New("server-returned enrollment identity is incomplete")
	}
	signingPublic, wrappingPublic, err := secure.PublicKeysFromSecrets(secrets)
	if err != nil {
		return nil, err
	}
	if err := ValidateDeviceIdentity(status.Device, signingPublic, wrappingPublic); err != nil {
		return nil, err
	}
	vaultKey, err := secure.UnwrapVaultKey(*status.Envelope, secrets.WrappingPrivate,
		vaultID, deviceID)
	if err != nil {
		return nil, err
	}
	if len(vaultKey) != 32 {
		return nil, errors.New("unwrapped vault key has invalid length")
	}
	return vaultKey, nil
}
