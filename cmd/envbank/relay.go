package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/relay"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"golang.org/x/term"
)

// lockedRelayAPI serializes relay calls with the broker's other vault calls.
type lockedRelayAPI struct{ v *brokerVault }

func (a lockedRelayAPI) ListDevices() ([]protocol.DeviceStatus, error) {
	a.v.mu.Lock()
	defer a.v.mu.Unlock()
	return a.v.api.ListDevices()
}

func (a lockedRelayAPI) CreateRelay(r protocol.RelayCreateRequest) (protocol.RelayRequest, error) {
	a.v.mu.Lock()
	defer a.v.mu.Unlock()
	return a.v.api.CreateRelay(r)
}

func (a lockedRelayAPI) ConsumeRelay(id string) (protocol.RelayConsumeResponse, error) {
	a.v.mu.Lock()
	defer a.v.mu.Unlock()
	response, err := a.v.api.ConsumeRelay(id)
	if errors.Is(err, client.ErrRelayGone) {
		err = relay.ErrExpired
	}
	return response, err
}

func (a lockedRelayAPI) CancelRelay(id string) error {
	a.v.mu.Lock()
	defer a.v.mu.Unlock()
	return a.v.api.CancelRelay(id)
}

// brokerRelay adapts relay.Target to the broker's Relay interface.
type brokerRelay struct{ target *relay.Target }

func newBrokerRelay(v *brokerVault, cfg *client.Config, secrets secure.DeviceSecrets) (*brokerRelay, error) {
	self, err := relay.SelfDevice(cfg.DeviceID, cfg.DeviceName, cfg.SigningPublic, cfg.WrappingPublic, secrets)
	if err != nil {
		return nil, errors.New("local device keys do not match the device config")
	}
	return &brokerRelay{target: &relay.Target{
		API: lockedRelayAPI{v}, VaultID: cfg.VaultID, VaultKey: v.vaultKey, Self: self,
		SigningPrivate: secrets.SigningPrivate, WrappingPrivate: secrets.WrappingPrivate,
	}}, nil
}

func (b *brokerRelay) Peers(context.Context) ([]agentbroker.RelayPeer, error) {
	peers, err := b.target.Peers()
	if err != nil {
		return nil, err
	}
	out := make([]agentbroker.RelayPeer, 0, len(peers))
	for _, p := range peers {
		out = append(out, agentbroker.RelayPeer{ID: p.ID, Name: p.Name, Fingerprint: p.Fingerprint()})
	}
	return out, nil
}

func (b *brokerRelay) Begin(_ context.Context, sender agentbroker.RelayPeer, name, reason string) (agentbroker.RelaySession, error) {
	// Re-read the device list: the sender must still be the exact identity the
	// owner chose (same id and fingerprint).
	peers, err := b.target.Peers()
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.ID == sender.ID && p.Fingerprint() == sender.Fingerprint {
			session, err := b.target.Begin(p, relay.Sink{Kind: relay.SinkIngest, Name: name}, reason)
			if err != nil {
				return nil, err
			}
			return brokerRelaySession{session}, nil
		}
	}
	return nil, relay.ErrNotEnrolled
}

type brokerRelaySession struct{ s *relay.Session }

func (s brokerRelaySession) SAS() string        { return s.s.Request().SAS() }
func (s brokerRelaySession) Expires() time.Time { return s.s.Request().Expires() }
func (s brokerRelaySession) Cancel()            { s.s.Cancel() }
func (s brokerRelaySession) Wait(ctx context.Context) ([]byte, error) {
	value, err := s.s.Wait(ctx)
	if errors.Is(err, relay.ErrExpired) {
		return nil, agentbroker.ErrRelayExpired
	}
	return value, err
}

// relayCommand implements `envbank relay send`, run by the owner on the
// sending device in their own terminal.
func relayCommand(args []string) error {
	if len(args) == 0 || args[0] != "send" {
		return errors.New("usage: envbank relay send [auth flags]")
	}
	fs := flag.NewFlagSet("relay send", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New("usage: envbank relay send [auth flags]")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("relay send must run in your own interactive terminal (the value is typed there)")
	}
	state, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), state) // never leave echo off
	terminal, err := agentbroker.NewTerminalPrompter(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	cfg, err := client.LoadConfig(auth.configPath)
	if err != nil {
		return err
	}
	passphrase, err := brokerPassphrase(auth)
	if err != nil {
		return err
	}
	secrets, err := cfg.Unlock(passphrase)
	wipeBytes(passphrase)
	if err != nil {
		return err
	}
	api := client.NewAPI(cfg.Server)
	api.Config, api.Secrets, api.Access = cfg, secrets, cfg.AccessCredentials()
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	defer wipeBytes(vaultKey)
	self, err := relay.SelfDevice(cfg.DeviceID, cfg.DeviceName, cfg.SigningPublic, cfg.WrappingPublic, secrets)
	if err != nil {
		return errors.New("local device keys do not match the device config")
	}
	ctx, stop := shutdownSignalContext()
	defer stop()
	return relaySend(ctx, terminal, os.Stdout, api, cfg.VaultID, vaultKey, self, secrets.SigningPrivate, time.Now)
}

func relaySend(ctx context.Context, owner *agentbroker.TerminalPrompter, out io.Writer, api relay.SenderAPI,
	vaultID string, vaultKey []byte, self relay.Device, signingPrivate string, now func() time.Time,
) error {
	pending, skipped, err := relay.Pending(api, vaultID, vaultKey, self, now())
	if err != nil {
		return relaySafeError(err)
	}
	if skipped > 0 {
		fmt.Fprintf(out, "warning: ignored %d relay request(s) that failed verification\n", skipped)
	}
	if len(pending) == 0 {
		return errors.New("no pending relay request for this device; start one on the target device first")
	}
	selected := pending[0]
	if len(pending) > 1 {
		fmt.Fprintln(out, "Pending relay requests for this device:")
		for i, r := range pending {
			fmt.Fprintf(out, "  [%d] %s for %s (expires %s)\n", i+1, agentbroker.Sanitize(r.Target.Name, 128), r.Sink.Name,
				r.Expires().Local().Format("15:04:05"))
		}
		answer, err := owner.Ask(ctx, fmt.Sprintf("Which one? [1-%d, empty to cancel]: ", len(pending)))
		if err != nil {
			return err
		}
		n, convErr := strconv.Atoi(answer)
		if convErr != nil || n < 1 || n > len(pending) {
			return errors.New("cancelled; nothing sent")
		}
		selected = pending[n-1]
	}
	fmt.Fprintf(out, "\n── EnvBank relay: send a secret to another device ──\n")
	fmt.Fprintf(out, "  to:       %s  (device %s, fingerprint %s)\n", agentbroker.Sanitize(selected.Target.Name, 128),
		agentbroker.Sanitize(selected.Target.ID, 128), selected.Target.Fingerprint())
	fmt.Fprintf(out, "  store as: %s\n", selected.Sink.Name)
	fmt.Fprintf(out, "  reason:   %s\n", agentbroker.Sanitize(selected.Reason, relay.MaxReasonLen))
	fmt.Fprintf(out, "  expires:  %s\n", selected.Expires().Local().Format("15:04:05"))
	fmt.Fprintf(out, "  code:     %s\n", selected.SAS())
	fmt.Fprintf(out, "  The value is sealed to that device; the sync service cannot read it.\n")
	answer, err := owner.Ask(ctx, "Does the target device show exactly this code? [y/N]: ")
	if err != nil {
		return err
	}
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return errors.New("code not confirmed; nothing sent")
	}
	value, ok, err := owner.ReadValue(ctx)
	defer wipeBytes(value)
	if err != nil || !ok {
		return errors.New("cancelled; nothing sent")
	}
	if len(value) < relay.MinValueBytes || len(value) > relay.MaxValueBytes {
		return errors.New("value must be 8 bytes to 64 KiB; nothing sent")
	}
	if err := relay.Send(api, selected, vaultKey, signingPrivate, value, now()); err != nil {
		return relaySafeError(err)
	}
	fmt.Fprintf(out, "sent sealed to %s; confirm storing it on that device\n", agentbroker.Sanitize(selected.Target.Name, 128))
	return nil
}

// relaySafeError maps failures to fixed messages (never values or keys).
func relaySafeError(err error) error {
	switch {
	case errors.Is(err, client.ErrRelayGone), errors.Is(err, relay.ErrExpired):
		return errors.New("relay request expired or was already used; nothing sent")
	case errors.Is(err, relay.ErrNotEnrolled):
		return errors.New("this device is not an active enrolled device of the vault")
	case errors.Is(err, relay.ErrValueSize):
		return errors.New("value must be 8 bytes to 64 KiB of text; nothing sent")
	}
	var serverError *client.ServerError
	if errors.As(err, &serverError) {
		return fmt.Errorf("relay failed: server returned %d; nothing sent", serverError.Status)
	}
	return errors.New("relay failed; nothing sent")
}
