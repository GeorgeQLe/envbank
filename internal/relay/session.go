package relay

import (
	"context"
	"errors"
	"time"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

// TargetAPI is the sync-service surface the target broker uses.
type TargetAPI interface {
	ListDevices() ([]protocol.DeviceStatus, error)
	CreateRelay(protocol.RelayCreateRequest) (protocol.RelayRequest, error)
	ConsumeRelay(id string) (protocol.RelayConsumeResponse, error)
	CancelRelay(id string) error
}

// SenderAPI is the sync-service surface `envbank relay send` uses.
type SenderAPI interface {
	ListDevices() ([]protocol.DeviceStatus, error)
	ListRelays() ([]protocol.RelayRequest, error)
	SealRelay(id string, request protocol.RelaySealRequest) error
}

// Target creates relay requests and receives envelopes for one unlocked device.
type Target struct {
	API             TargetAPI
	VaultID         string
	VaultKey        []byte
	Self            Device
	SigningPrivate  string
	WrappingPrivate string
	TTL             time.Duration // default and maximum protocol.RelayMaxTTL
	Poll            time.Duration // default 2s
	Now             func() time.Time
}

func (t *Target) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Peers returns the vault's other active devices whose listed fingerprints
// match their keys.
func (t *Target) Peers() ([]Device, error) {
	devices, err := t.API.ListDevices()
	if err != nil {
		return nil, err
	}
	var peers []Device
	for _, status := range devices {
		dev := Device{ID: status.Device.ID, Name: status.Device.Name,
			SigningPublic: status.Device.SigningPublic, WrappingPublic: status.Device.WrappingPublic}
		if dev.ID == t.Self.ID || VerifyEnrolled(dev, devices) != nil {
			continue
		}
		peers = append(peers, dev)
	}
	return peers, nil
}

// Session is one outstanding request on the target.
type Session struct {
	target  *Target
	request *Request
}

// Begin creates a request for sender to fill sink.
func (t *Target) Begin(sender Device, sink Sink, reason string) (*Session, error) {
	ttl := t.TTL
	if ttl <= 0 || ttl > protocol.RelayMaxTTL {
		ttl = protocol.RelayMaxTTL
	}
	create, request, err := NewRequest(t.VaultID, t.VaultKey, t.Self, t.SigningPrivate, sender, sink, reason, t.now(), ttl)
	if err != nil {
		return nil, err
	}
	created, err := t.API.CreateRelay(create)
	if err != nil {
		return nil, err
	}
	if created.ID != create.ID || created.TargetDeviceID != t.Self.ID || created.SenderDeviceID != sender.ID ||
		created.ExpiresAt != create.ExpiresAt {
		_ = t.API.CancelRelay(create.ID)
		return nil, ErrAuth
	}
	return &Session{target: t, request: request}, nil
}

// Request is the verified request (for its SAS, sender and expiry).
func (s *Session) Request() *Request { return s.request }

// Wait polls until a valid envelope arrives, the request expires (ErrExpired)
// or ctx ends. The returned value must be wiped by the caller.
func (s *Session) Wait(ctx context.Context) ([]byte, error) {
	poll := s.target.Poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Cancel()
			return nil, ctx.Err()
		case <-timer.C:
		}
		if !s.target.now().Before(s.request.expires) {
			s.Cancel()
			return nil, ErrExpired
		}
		response, err := s.target.API.ConsumeRelay(s.request.RequestID)
		if err != nil {
			if errors.Is(err, ErrExpired) {
				return nil, ErrExpired
			}
			// Transient service errors are retried until expiry.
			timer.Reset(poll)
			continue
		}
		switch response.State {
		case protocol.RelayPending:
			timer.Reset(poll)
			continue
		case protocol.RelayConsumed:
		default:
			return nil, ErrExpired
		}
		if response.Envelope == nil {
			return nil, ErrInvalid
		}
		// The sender must still be an active device with the same keys.
		devices, err := s.target.API.ListDevices()
		if err != nil {
			return nil, err
		}
		if err := VerifyEnrolled(s.request.Sender, devices); err != nil {
			return nil, err
		}
		return Open(s.request, s.target.VaultKey, s.target.WrappingPrivate, *response.Envelope, s.target.now())
	}
}

// Cancel withdraws the request from the service (best effort).
func (s *Session) Cancel() { _ = s.target.API.CancelRelay(s.request.RequestID) }

// Pending returns verified pending requests addressed to self whose target is
// an active device of the vault. Invalid requests are skipped and counted.
func Pending(api SenderAPI, vaultID string, vaultKey []byte, self Device, now time.Time) ([]*Request, int, error) {
	listed, err := api.ListRelays()
	if err != nil {
		return nil, 0, err
	}
	devices, err := api.ListDevices()
	if err != nil {
		return nil, 0, err
	}
	if VerifyEnrolled(self, devices) != nil {
		return nil, 0, ErrNotEnrolled
	}
	var out []*Request
	skipped := 0
	for _, server := range listed {
		if server.SenderDeviceID != self.ID || server.State != protocol.RelayPending {
			continue
		}
		request, err := OpenRequest(vaultID, vaultKey, server, self, now)
		if err != nil || VerifyEnrolled(request.Target, devices) != nil {
			skipped++
			continue
		}
		out = append(out, request)
	}
	return out, skipped, nil
}

// Send seals value for request and posts it.
func Send(api SenderAPI, request *Request, vaultKey []byte, senderSigningPrivate string, value []byte, now time.Time) error {
	env, err := Seal(request, vaultKey, senderSigningPrivate, value, now)
	if err != nil {
		return err
	}
	return api.SealRelay(request.RequestID, protocol.RelaySealRequest{Version: protocol.RelayProtocolVersion, Envelope: env})
}

// SelfDevice builds the public identity of the local device from its
// unlocked secrets, failing if the configured public keys disagree.
func SelfDevice(id, name, signingPublic, wrappingPublic string, secrets secure.DeviceSecrets) (Device, error) {
	sign, wrap, err := secure.PublicKeysFromSecrets(secrets)
	if err != nil || sign != signingPublic || wrap != wrappingPublic {
		return Device{}, ErrInvalid
	}
	return Device{ID: id, Name: name, SigningPublic: sign, WrappingPublic: wrap}, nil
}
