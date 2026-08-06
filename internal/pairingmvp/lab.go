package pairingmvp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/server"
)

type Phase string

const (
	PhaseIdle      Phase = "idle"
	PhaseRequested Phase = "requested"
	PhaseImported  Phase = "imported"
	PhaseApproved  Phase = "approved"
	PhaseAccepted  Phase = "accepted"
	PhaseCancelled Phase = "cancelled"
	PhaseRejected  Phase = "rejected"
	PhaseExpired   Phase = "expired"
	PhaseExhausted Phase = "attempts_exhausted"
)

type State struct {
	Phase             Phase  `json:"phase"`
	Server            string `json:"server"`
	VaultID           string `json:"vault_id"`
	PairingPayload    string `json:"pairing_payload,omitempty"`
	DeviceID          string `json:"device_id,omitempty"`
	DeviceName        string `json:"device_name,omitempty"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	Imported          bool   `json:"imported"`
	SameVaultKey      bool   `json:"same_vault_key"`
	InvitationState   string `json:"invitation_state,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	AttemptsRemaining int    `json:"attempts_remaining"`
	TerminalAt        string `json:"terminal_at,omitempty"`
}

type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string { return e.Message }

func conflict(message string) error {
	return &StatusError{Status: http.StatusConflict, Message: message}
}

func actionAllowed(phase Phase, action string) bool {
	if action == "reset" {
		return true
	}
	return (phase == PhaseIdle && action == "request") ||
		(phase == PhaseRequested && action == "import") ||
		(phase == PhaseImported && action == "approve") ||
		(phase == PhaseApproved && action == "accept") ||
		((phase == PhaseRequested || phase == PhaseImported) && action == "cancel") ||
		(phase == PhaseImported && action == "reject")
}

func badRequest(message string) error {
	return &StatusError{Status: http.StatusBadRequest, Message: message}
}

// Lab owns a real EnvBank service and disposable SQLite database. It never
// calls config, Keychain, recovery, or production-vault loading code.
type Lab struct {
	mu              sync.Mutex
	tempDir         string
	service         *server.Server
	serviceHTTP     *http.Server
	serviceListener net.Listener
	serverURL       string
	phase           Phase
	vaultID         string
	approvedKeys    secure.DeviceKeys
	vaultKey        []byte
	approvedAPI     *client.API
	newKeys         secure.DeviceKeys
	pending         protocol.InvitationStatus
	imported        protocol.InvitationStatus
	payload         string
	sameVaultKey    bool
}

func NewLab() (*Lab, error) {
	dir, err := os.MkdirTemp("", "envbank-pairing-mvp-")
	if err != nil {
		return nil, err
	}
	databasePath := filepath.Join(dir, "disposable.sqlite")
	service, err := server.Open(databasePath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		service.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	lab := &Lab{tempDir: dir, service: service, serviceListener: listener,
		serverURL: "http://" + listener.Addr().String(), phase: PhaseIdle}
	lab.serviceHTTP = &http.Server{Handler: service, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = lab.serviceHTTP.Serve(listener) }()
	if err := lab.initializeVault(); err != nil {
		lab.Close()
		return nil, err
	}
	return lab, nil
}

func (l *Lab) initializeVault() error {
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		return err
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		return err
	}
	api := client.NewAPI(l.serverURL)
	created, err := api.CreateVault("Disposable pairing lab", protocol.PublicDevice{
		Name: "Approved lab device", SigningPublic: keys.SigningPublic,
		WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		return err
	}
	api.Config = &client.Config{Version: 1, Server: l.serverURL, VaultID: created.VaultID,
		DeviceID: created.DeviceID, DeviceName: "Approved lab device",
		SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic}
	api.Secrets = keys.Secrets
	l.vaultID, l.approvedKeys, l.vaultKey, l.approvedAPI = created.VaultID, keys, vaultKey, api
	return nil
}

func (l *Lab) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.vaultKey {
		l.vaultKey[i] = 0
	}
	l.approvedKeys, l.newKeys = secure.DeviceKeys{}, secure.DeviceKeys{}
	if l.serviceHTTP != nil {
		_ = l.serviceHTTP.Close()
	}
	var closeErr error
	if l.service != nil {
		closeErr = l.service.Close()
	}
	removeErr := os.RemoveAll(l.tempDir)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

func (l *Lab) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refreshLocked()
	return l.stateLocked()
}

func (l *Lab) stateLocked() State {
	state := State{Phase: l.phase, Server: l.serverURL, VaultID: l.vaultID,
		Imported:     l.phase == PhaseImported || l.phase == PhaseApproved || l.phase == PhaseAccepted,
		SameVaultKey: l.sameVaultKey}
	if !actionAllowed(l.phase, "request") {
		state.PairingPayload, state.DeviceID, state.DeviceName = l.payload, l.pending.Device.ID, l.pending.Device.Name
		state.Fingerprint = groupedFingerprint(l.pending.Device.Fingerprint)
		state.InvitationState = l.pending.State
		state.ExpiresAt = l.pending.ExpiresAt
		state.AttemptsRemaining = l.pending.AttemptsRemaining
		state.TerminalAt = l.pending.TerminalAt
	}
	return state
}

func (l *Lab) Request(name string) (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "request") {
		return State{}, conflict("request is only valid from idle")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return State{}, badRequest("device name must be 1-64 printable characters")
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		return State{}, err
	}
	status, err := client.NewAPI(l.serverURL).CreateInvitation(l.vaultID, protocol.InvitationRequest{
		Version: protocol.InvitationProtocolVersion, Name: name,
		SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic})
	if err != nil {
		return State{}, err
	}
	payload, err := EncodePayload(Payload{Server: l.serverURL, VaultID: l.vaultID,
		DeviceID: status.Device.ID, Fingerprint: status.Device.Fingerprint,
		CreatedAt: status.Device.CreatedAt})
	if err != nil {
		return State{}, err
	}
	l.newKeys, l.pending, l.payload, l.phase = keys, status, payload, PhaseRequested
	return l.stateLocked(), nil
}

func (l *Lab) Import(encoded string) (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "import") {
		return State{}, conflict("import is only valid after a request")
	}
	payload, err := DecodePayload(encoded)
	if err != nil {
		return State{}, badRequest(err.Error())
	}
	if payload.Server != l.serverURL || payload.VaultID != l.vaultID {
		return State{}, badRequest("payload server or vault does not match the approved device")
	}
	invitations, err := l.approvedAPI.ListInvitations()
	if err != nil {
		return State{}, err
	}
	var selected *protocol.InvitationStatus
	for i := range invitations {
		if invitations[i].Device.ID == payload.DeviceID {
			selected = &invitations[i]
			break
		}
	}
	if selected == nil || selected.State != protocol.InvitationPending {
		return State{}, badRequest("payload does not identify a pending invitation")
	}
	recomputed := secure.PublicFingerprint(selected.Device.SigningPublic, selected.Device.WrappingPublic)
	if recomputed != selected.Device.Fingerprint || payload.Fingerprint != recomputed ||
		payload.CreatedAt != selected.Device.CreatedAt {
		return State{}, badRequest("payload does not match the server-returned enrollment identity")
	}
	l.imported, l.phase = *selected, PhaseImported
	return l.stateLocked(), nil
}

func (l *Lab) Approve(fingerprint string) (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "approve") {
		return State{}, conflict("approval is only valid after import")
	}
	fingerprint = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(fingerprint, " ", "")))
	if !fingerprintPattern.MatchString(fingerprint) || fingerprint != l.imported.Device.Fingerprint {
		return State{}, badRequest("the complete 16-hex-character fingerprint does not match")
	}
	fresh, err := l.approvedAPI.GetInvitation(l.imported.Device.ID)
	if err != nil {
		return State{}, err
	}
	if fresh.State != protocol.InvitationPending || fresh.Device != l.imported.Device {
		return State{}, conflict("pending invitation changed; approval stopped")
	}
	envelope, err := secure.WrapVaultKey(l.vaultKey, fresh.Device.WrappingPublic, l.vaultID, fresh.Device.ID)
	if err != nil {
		return State{}, err
	}
	status, err := l.approvedAPI.ApproveInvitation(fresh.Device.ID, protocol.InvitationApproval{
		Version: fresh.Version, DeviceID: fresh.Device.ID,
		Fingerprint: fresh.Device.Fingerprint, Envelope: envelope,
	})
	if err != nil {
		return State{}, err
	}
	l.pending, l.imported = status, status
	l.phase = PhaseApproved
	return l.stateLocked(), nil
}

func (l *Lab) Accept() (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "accept") {
		return State{}, conflict("accept is only valid after approval")
	}
	api := client.NewAPI(l.serverURL)
	api.Config = &client.Config{Version: 1, Server: l.serverURL, VaultID: l.vaultID,
		DeviceID: l.pending.Device.ID, DeviceName: l.pending.Device.Name,
		SigningPublic: l.newKeys.SigningPublic, WrappingPublic: l.newKeys.WrappingPublic}
	api.Secrets = l.newKeys.Secrets
	status, err := api.GetInvitation(l.pending.Device.ID)
	if err != nil {
		return State{}, err
	}
	if status.State != protocol.InvitationApproved || status.Envelope == nil {
		return State{}, conflict("invitation is not approved")
	}
	if status.Device != l.pending.Device || secure.PublicFingerprint(status.Device.SigningPublic,
		status.Device.WrappingPublic) != l.pending.Device.Fingerprint {
		return State{}, errors.New("server-returned enrollment identity changed")
	}
	unwrapped, err := secure.UnwrapVaultKey(*status.Envelope, l.newKeys.Secrets.WrappingPrivate,
		l.vaultID, l.pending.Device.ID)
	if err != nil {
		return State{}, fmt.Errorf("could not unwrap enrollment envelope: %w", err)
	}
	l.sameVaultKey = len(unwrapped) == len(l.vaultKey) && subtle.ConstantTimeCompare(unwrapped, l.vaultKey) == 1
	for i := range unwrapped {
		unwrapped[i] = 0
	}
	if !l.sameVaultKey {
		return State{}, errors.New("unwrapped vault key did not match")
	}
	l.phase = PhaseAccepted
	l.pending = status
	return l.stateLocked(), nil
}

func (l *Lab) Cancel() (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "cancel") {
		return State{}, conflict("cancellation is only valid while the invitation is pending")
	}
	api := l.pendingAPI()
	status, err := api.CancelInvitation(l.pending.Device.ID, invitationTransition(l.pending))
	if err != nil {
		return State{}, err
	}
	l.pending = status
	l.phase = phaseForInvitation(status.State)
	return l.stateLocked(), nil
}

func (l *Lab) Reject() (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !actionAllowed(l.phase, "reject") {
		return State{}, conflict("rejection is only valid after import")
	}
	status, err := l.approvedAPI.RejectInvitation(l.pending.Device.ID,
		invitationTransition(l.pending))
	if err != nil {
		return State{}, err
	}
	l.pending, l.imported = status, status
	l.phase = phaseForInvitation(status.State)
	return l.stateLocked(), nil
}

func (l *Lab) Refresh() (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending.Device.ID == "" {
		return l.stateLocked(), nil
	}
	status, err := l.pendingAPI().GetInvitation(l.pending.Device.ID)
	if err != nil {
		return State{}, err
	}
	l.pending = status
	if status.State != protocol.InvitationPending && l.phase != PhaseAccepted {
		l.phase = phaseForInvitation(status.State)
	}
	return l.stateLocked(), nil
}

func (l *Lab) refreshLocked() {
	if l.pending.Device.ID == "" {
		return
	}
	status, err := l.pendingAPI().GetInvitation(l.pending.Device.ID)
	if err != nil {
		return
	}
	l.pending = status
	if status.State != protocol.InvitationPending && l.phase != PhaseAccepted {
		l.phase = phaseForInvitation(status.State)
	}
}

func (l *Lab) pendingAPI() *client.API {
	api := client.NewAPI(l.serverURL)
	api.Config = &client.Config{Version: 1, Server: l.serverURL, VaultID: l.vaultID,
		DeviceID: l.pending.Device.ID, DeviceName: l.pending.Device.Name,
		SigningPublic: l.newKeys.SigningPublic, WrappingPublic: l.newKeys.WrappingPublic}
	api.Secrets = l.newKeys.Secrets
	return api
}

func invitationTransition(status protocol.InvitationStatus) protocol.InvitationTransition {
	return protocol.InvitationTransition{Version: status.Version, DeviceID: status.Device.ID,
		Fingerprint: status.Device.Fingerprint}
}

func phaseForInvitation(state string) Phase {
	switch state {
	case protocol.InvitationApproved:
		return PhaseApproved
	case protocol.InvitationCancelled:
		return PhaseCancelled
	case protocol.InvitationRejected:
		return PhaseRejected
	case protocol.InvitationExpired:
		return PhaseExpired
	case protocol.InvitationAttemptsExhausted:
		return PhaseExhausted
	default:
		return PhaseRequested
	}
}

func (l *Lab) Reset() (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.vaultKey {
		l.vaultKey[i] = 0
	}
	l.phase, l.vaultID, l.payload = PhaseIdle, "", ""
	l.approvedKeys, l.newKeys = secure.DeviceKeys{}, secure.DeviceKeys{}
	l.pending, l.imported = protocol.InvitationStatus{}, protocol.InvitationStatus{}
	l.sameVaultKey = false
	if err := l.initializeVault(); err != nil {
		return State{}, err
	}
	return l.stateLocked(), nil
}

func groupedFingerprint(value string) string {
	if len(value) != 16 {
		return value
	}
	return value[0:4] + " " + value[4:8] + " " + value[8:12] + " " + value[12:16]
}
