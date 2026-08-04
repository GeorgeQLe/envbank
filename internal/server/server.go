package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

type State struct {
	Version int               `json:"version"`
	Vaults  map[string]*Vault `json:"vaults"`
	Nonces  map[string]string `json:"nonces"`
}

type Vault struct {
	ID          string                           `json:"id"`
	Name        string                           `json:"name"`
	Devices     map[string]protocol.PublicDevice `json:"devices"`
	Enrollments map[string]*Enrollment           `json:"enrollments"`
	Records     map[string]protocol.Record       `json:"records"`
	CreatedAt   string                           `json:"created_at"`
}

type Enrollment struct {
	Device   protocol.PublicDevice `json:"device"`
	Approved bool                  `json:"approved"`
	Envelope *secure.WrappedKey    `json:"envelope,omitempty"`
}

type Server struct {
	mu       sync.Mutex
	path     string
	state    State
	now      func() time.Time
	maxBytes int64
}

func Open(path string) (*Server, error) {
	s := &Server{
		path:     path,
		state:    State{Version: 1, Vaults: map[string]*Vault{}, Nonces: map[string]string{}},
		now:      time.Now,
		maxBytes: 1 << 20,
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.state); err != nil {
		return nil, fmt.Errorf("decode server state: %w", err)
	}
	if s.state.Version != 1 {
		return nil, fmt.Errorf("unsupported server state version %d", s.state.Version)
	}
	if s.state.Vaults == nil {
		s.state.Vaults = map[string]*Vault{}
	}
	if s.state.Nonces == nil {
		s.state.Nonces = map[string]string{}
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/v1/vaults" && r.Method == http.MethodPost {
		s.createVault(w, r)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "vaults" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	vaultID := parts[2]
	switch {
	case len(parts) == 4 && parts[3] == "enrollments" && r.Method == http.MethodPost:
		s.requestEnrollment(w, r, vaultID)
	case len(parts) == 4 && parts[3] == "enrollments" && r.Method == http.MethodGet:
		s.listEnrollments(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "enrollments" && r.Method == http.MethodGet:
		s.getEnrollment(w, r, vaultID, parts[4])
	case len(parts) == 5 && parts[3] == "enrollments" && parts[4] != "" && r.Method == http.MethodPost:
		s.approveEnrollment(w, r, vaultID, parts[4])
	case len(parts) == 4 && parts[3] == "records" && r.Method == http.MethodGet:
		s.listRecords(w, r, vaultID)
	case len(parts) == 5 && parts[3] == "records" && r.Method == http.MethodPut:
		s.putRecord(w, r, vaultID, parts[4])
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	var request protocol.CreateVaultRequest
	if !decodeJSON(w, r, s.maxBytes, &request) {
		return
	}
	if request.Name == "" || request.Device.Name == "" ||
		request.Device.SigningPublic == "" || request.Device.WrappingPublic == "" {
		writeError(w, http.StatusBadRequest, "vault and device fields are required")
		return
	}
	vaultID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	deviceID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	now := s.now().UTC().Format(time.RFC3339)
	request.Device.ID = deviceID
	request.Device.CreatedAt = now
	request.Device.Fingerprint = secure.PublicFingerprint(request.Device.SigningPublic, request.Device.WrappingPublic)
	vault := &Vault{
		ID: vaultID, Name: request.Name, CreatedAt: now,
		Devices:     map[string]protocol.PublicDevice{deviceID: request.Device},
		Enrollments: map[string]*Enrollment{},
		Records:     map[string]protocol.Record{},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Vaults[vaultID] = vault
	if err := s.saveLocked(); err != nil {
		delete(s.state.Vaults, vaultID)
		writeError(w, http.StatusInternalServerError, "could not persist state")
		return
	}
	writeJSON(w, http.StatusCreated, protocol.CreateVaultResponse{VaultID: vaultID, DeviceID: deviceID})
}

func (s *Server) requestEnrollment(w http.ResponseWriter, r *http.Request, vaultID string) {
	var request protocol.EnrollmentRequest
	if !decodeJSON(w, r, s.maxBytes, &request) {
		return
	}
	if request.Name == "" || request.SigningPublic == "" || request.WrappingPublic == "" {
		writeError(w, http.StatusBadRequest, "device fields are required")
		return
	}
	deviceID, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "randomness unavailable")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.state.Vaults[vaultID]
	if vault == nil {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}
	now := s.now().UTC().Format(time.RFC3339)
	device := protocol.PublicDevice{
		ID: deviceID, Name: request.Name, SigningPublic: request.SigningPublic,
		WrappingPublic: request.WrappingPublic,
		Fingerprint:    secure.PublicFingerprint(request.SigningPublic, request.WrappingPublic),
		CreatedAt:      now,
	}
	vault.Enrollments[deviceID] = &Enrollment{Device: device}
	if err := s.saveLocked(); err != nil {
		delete(vault.Enrollments, deviceID)
		writeError(w, http.StatusInternalServerError, "could not persist state")
		return
	}
	writeJSON(w, http.StatusCreated, protocol.EnrollmentStatus{Device: device})
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request, vaultID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault, ok := s.authenticateLocked(w, r, vaultID, false)
	if !ok {
		return
	}
	out := make([]protocol.EnrollmentStatus, 0, len(vault.Enrollments))
	for _, enrollment := range vault.Enrollments {
		out = append(out, protocol.EnrollmentStatus{
			Device: enrollment.Device, Approved: enrollment.Approved,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request, vaultID, enrollmentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.state.Vaults[vaultID]
	if vault == nil {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}
	enrollment := vault.Enrollments[enrollmentID]
	if enrollment == nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}
	if !s.authenticatePublicLocked(w, r, enrollment.Device, vaultID, false) {
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollmentStatus{
		Device: enrollment.Device, Approved: enrollment.Approved, Envelope: enrollment.Envelope,
	})
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request, vaultID, enrollmentID string) {
	body, ok := readBody(w, r, s.maxBytes)
	if !ok {
		return
	}
	var request protocol.EnrollmentApproval
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vault, ok := s.authenticateBodyLocked(w, r, vaultID, body, true)
	if !ok {
		return
	}
	enrollment := vault.Enrollments[enrollmentID]
	if enrollment == nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}
	if enrollment.Approved {
		writeError(w, http.StatusConflict, "enrollment already approved")
		return
	}
	enrollment.Approved = true
	enrollment.Envelope = &request.Envelope
	vault.Devices[enrollmentID] = enrollment.Device
	if err := s.saveLocked(); err != nil {
		enrollment.Approved = false
		enrollment.Envelope = nil
		delete(vault.Devices, enrollmentID)
		writeError(w, http.StatusInternalServerError, "could not persist state")
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollmentStatus{Device: enrollment.Device, Approved: true})
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, vaultID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault, ok := s.authenticateLocked(w, r, vaultID, false)
	if !ok {
		return
	}
	out := make([]protocol.Record, 0, len(vault.Records))
	for _, record := range vault.Records {
		out = append(out, record)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putRecord(w http.ResponseWriter, r *http.Request, vaultID, recordID string) {
	body, ok := readBody(w, r, s.maxBytes)
	if !ok {
		return
	}
	var request protocol.PutRecordRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vault, ok := s.authenticateBodyLocked(w, r, vaultID, body, true)
	if !ok {
		return
	}
	current := vault.Records[recordID]
	if current.Revision != request.ExpectedRevision {
		writeError(w, http.StatusConflict, fmt.Sprintf("revision conflict: current revision is %d", current.Revision))
		return
	}
	record := protocol.Record{
		ID: recordID, Revision: current.Revision + 1, Blob: request.Blob,
		ModifiedAt: s.now().UTC().Format(time.RFC3339),
	}
	vault.Records[recordID] = record
	if err := s.saveLocked(); err != nil {
		if current.Revision == 0 {
			delete(vault.Records, recordID)
		} else {
			vault.Records[recordID] = current
		}
		writeError(w, http.StatusInternalServerError, "could not persist state")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) authenticateLocked(w http.ResponseWriter, r *http.Request, vaultID string, persistNonce bool) (*Vault, bool) {
	return s.authenticateBodyLocked(w, r, vaultID, nil, persistNonce)
}

func (s *Server) authenticateBodyLocked(w http.ResponseWriter, r *http.Request, vaultID string, body []byte, persistNonce bool) (*Vault, bool) {
	vault := s.state.Vaults[vaultID]
	if vault == nil {
		writeError(w, http.StatusNotFound, "vault not found")
		return nil, false
	}
	device := vault.Devices[r.Header.Get(protocol.HeaderDevice)]
	if device.ID == "" {
		writeError(w, http.StatusUnauthorized, "unknown device")
		return nil, false
	}
	if !s.authenticatePublicLockedWithBody(w, r, device, vaultID, body, persistNonce) {
		return nil, false
	}
	return vault, true
}

func (s *Server) authenticatePublicLocked(w http.ResponseWriter, r *http.Request, device protocol.PublicDevice, vaultID string, persistNonce bool) bool {
	return s.authenticatePublicLockedWithBody(w, r, device, vaultID, nil, persistNonce)
}

func (s *Server) authenticatePublicLockedWithBody(w http.ResponseWriter, r *http.Request, device protocol.PublicDevice, vaultID string, body []byte, persistNonce bool) bool {
	if r.Header.Get(protocol.HeaderDevice) != device.ID {
		writeError(w, http.StatusUnauthorized, "device mismatch")
		return false
	}
	timestamp := r.Header.Get(protocol.HeaderTimestamp)
	nonce := r.Header.Get(protocol.HeaderNonce)
	signature := r.Header.Get(protocol.HeaderSignature)
	if nonce == "" || signature == "" || protocol.ValidateTimestamp(timestamp, s.now()) != nil {
		writeError(w, http.StatusUnauthorized, "invalid authentication headers")
		return false
	}
	nonceKey := vaultID + "\x00" + device.ID + "\x00" + nonce
	if _, exists := s.state.Nonces[nonceKey]; exists {
		writeError(w, http.StatusUnauthorized, "replayed request")
		return false
	}
	message := protocol.SignatureMessage(r.Method, r.URL.RequestURI(), timestamp, nonce, body)
	if !secure.Verify(device.SigningPublic, message, signature) {
		writeError(w, http.StatusUnauthorized, "invalid request signature")
		return false
	}
	if persistNonce {
		s.state.Nonces[nonceKey] = timestamp
		s.pruneNoncesLocked()
	}
	return true
}

func (s *Server) pruneNoncesLocked() {
	cutoff := s.now().Add(-10 * time.Minute)
	for key, value := range s.state.Nonces {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || parsed.Before(cutoff) {
			delete(s.state.Nonces, key)
		}
	}
}

func (s *Server) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randomID() (string, error) {
	raw, err := secure.RandomBytes(18)
	if err != nil {
		return "", err
	}
	return secure.Encode(raw), nil
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		writeError(w, http.StatusBadRequest, "request body is too large")
		return nil, false
	}
	return raw, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, destination any) bool {
	raw, ok := readBody(w, r, limit)
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
