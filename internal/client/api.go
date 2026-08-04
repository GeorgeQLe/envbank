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

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

type API struct {
	BaseURL    string
	HTTPClient *http.Client
	Config     *Config
	Secrets    secure.DeviceSecrets
}

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
	if authenticated {
		if a.Config == nil || a.Secrets.SigningPrivate == "" {
			return errors.New("authenticated client is not unlocked")
		}
		timestamp := time.Now().UTC().Format(time.RFC3339)
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
	res, err := a.HTTPClient.Do(req)
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
