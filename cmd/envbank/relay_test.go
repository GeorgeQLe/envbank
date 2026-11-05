package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/relay"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"github.com/GeorgeQLe/envbank/internal/server"
)

type relayDevice struct {
	api     *client.API
	cfg     *client.Config
	secrets secure.DeviceSecrets
	self    relay.Device
}

// twoDevices creates a vault with two active devices on a loopback test server.
func twoDevices(t *testing.T) (vaultKey []byte, target, sender relayDevice) {
	t.Helper()
	service, err := server.Open("")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(service)
	t.Cleanup(func() { httpServer.Close(); service.Close() })
	vaultKey, _ = secure.RandomBytes(32)
	make := func(name string) (secure.DeviceKeys, *client.API) {
		keys, err := secure.NewDeviceKeys()
		if err != nil {
			t.Fatal(err)
		}
		keys.Secrets.VaultKey = secure.Encode(vaultKey)
		return keys, client.NewAPI(httpServer.URL)
	}
	firstKeys, firstAPI := make("laptop")
	created, err := firstAPI.CreateVault("relay", protocol.PublicDevice{Name: "laptop", SigningPublic: firstKeys.SigningPublic, WrappingPublic: firstKeys.WrappingPublic})
	if err != nil {
		t.Fatal(err)
	}
	firstAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID, DeviceName: "laptop",
		SigningPublic: firstKeys.SigningPublic, WrappingPublic: firstKeys.WrappingPublic}
	firstAPI.Secrets = firstKeys.Secrets
	secondKeys, secondAPI := make("phone")
	enrollment, err := secondAPI.RequestEnrollment(created.VaultID, protocol.EnrollmentRequest{Name: "phone",
		SigningPublic: secondKeys.SigningPublic, WrappingPublic: secondKeys.WrappingPublic})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := secure.WrapVaultKey(vaultKey, secondKeys.WrappingPublic, created.VaultID, enrollment.Device.ID)
	if err := firstAPI.ApproveEnrollment(enrollment.Device.ID, envelope); err != nil {
		t.Fatal(err)
	}
	secondAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: enrollment.Device.ID, DeviceName: "phone",
		SigningPublic: secondKeys.SigningPublic, WrappingPublic: secondKeys.WrappingPublic}
	secondAPI.Secrets = secondKeys.Secrets
	device := func(api *client.API, keys secure.DeviceKeys) relayDevice {
		self, err := relay.SelfDevice(api.Config.DeviceID, api.Config.DeviceName, keys.SigningPublic, keys.WrappingPublic, keys.Secrets)
		if err != nil {
			t.Fatal(err)
		}
		return relayDevice{api: api, cfg: api.Config, secrets: keys.Secrets, self: self}
	}
	return vaultKey, device(firstAPI, firstKeys), device(secondAPI, secondKeys)
}

// ownerB is the target owner's channel: it reports the SAS and confirms.
type ownerB struct {
	mu      sync.Mutex
	sas     chan string
	confirm bool
	text    strings.Builder
}

func (o *ownerB) ApproveRun(context.Context, agentbroker.Command) (agentbroker.Decision, error) {
	return agentbroker.Deny, nil
}
func (o *ownerB) ReadSecret(context.Context, agentbroker.Ingest) ([]byte, bool, error) {
	return nil, false, nil
}
func (o *ownerB) Notify(line string) { o.mu.Lock(); o.text.WriteString(line + "\n"); o.mu.Unlock() }
func (o *ownerB) ChooseRelaySender(_ context.Context, p agentbroker.RelayPrompt, peers []agentbroker.RelayPeer) (int, bool, error) {
	o.Notify("choose " + peers[0].Name + " " + peers[0].Fingerprint)
	return 0, len(peers) == 1, nil
}
func (o *ownerB) ShowRelayCode(p agentbroker.RelayPrompt) { o.Notify("code " + p.SAS); o.sas <- p.SAS }
func (o *ownerB) ConfirmRelay(_ context.Context, p agentbroker.RelayPrompt) (bool, error) {
	o.Notify("confirm from " + p.Sender.Name + " code " + p.SAS)
	return o.confirm, nil
}

// ownerA is a scripted sender terminal: answers on a pipe, hidden reads injected.
func ownerA(t *testing.T, answers string, hidden ...string) (*agentbroker.TerminalPrompter, *bytes.Buffer) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	if _, err := w.Write([]byte(answers)); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return agentbroker.NewTestTerminalPrompter(r, out, func(int) ([]byte, error) {
		next := hidden[0]
		hidden = hidden[1:]
		return []byte(next), nil
	}), out
}

func startRelayBroker(t *testing.T, vaultKey []byte, target relayDevice, owner *ownerB) (*brokerVault, chan agentbroker.Response, context.CancelFunc) {
	t.Helper()
	vault := &brokerVault{api: target.api, vaultKey: append([]byte(nil), vaultKey...)}
	relayer, err := newBrokerRelay(vault, target.cfg, target.secrets)
	if err != nil {
		t.Fatal(err)
	}
	relayer.target.Poll = 20 * time.Millisecond
	broker, err := agentbroker.New(agentbroker.Options{Vault: vault, Relay: relayer, Prompter: owner, Runner: agentbroker.ExecRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan agentbroker.Response, 1)
	go func() {
		done <- broker.Handle(ctx, agentbroker.Request{V: agentbroker.ProtocolVersion, Op: agentbroker.OpRelayRequest,
			Name: "RELAYED_TOKEN", Reason: "deploy from the laptop"})
	}()
	t.Cleanup(cancel)
	return vault, done, cancel
}

func TestRelaySendDeliversIntoTargetBrokerVaultOnly(t *testing.T) {
	vaultKey, target, sender := twoDevices(t)
	value := "relay-cli-marker-" + base64.RawURLEncoding.EncodeToString(vaultKey[:9])
	owner := &ownerB{sas: make(chan string, 1), confirm: true}
	vault, done, _ := startRelayBroker(t, vaultKey, target, owner)
	sas := <-owner.sas
	prompter, out := ownerA(t, "y\n", value, value)
	if err := relaySend(context.Background(), prompter, out, sender.api, sender.cfg.VaultID, vaultKey, sender.self,
		sender.secrets.SigningPrivate, time.Now); err != nil {
		t.Fatal(err)
	}
	resp := <-done
	if resp.State != agentbroker.StateStored {
		t.Fatalf("resp %+v\n%s", resp, owner.text.String())
	}
	if !strings.Contains(out.String(), "code:     "+sas) || !strings.Contains(out.String(), "laptop") {
		t.Fatalf("sender did not show the target and code:\n%s", out.String())
	}
	values, err := vault.Values(context.Background(), []string{"RELAYED_TOKEN"})
	if err != nil || values["RELAYED_TOKEN"] != value {
		t.Fatalf("stored value mismatch: %v", err)
	}
	raw, _ := json.Marshal(resp)
	for name, text := range map[string]string{"agent response": string(raw), "sender terminal": out.String(), "target terminal": owner.text.String()} {
		if strings.Contains(text, value) {
			t.Fatalf("value appeared in %s", name)
		}
	}
	if !strings.Contains(owner.text.String(), "confirm from phone code "+sas) {
		t.Fatalf("target owner was not shown the sender and code:\n%s", owner.text.String())
	}
	// Nothing is left to send: the request was consumed.
	prompter, out = ownerA(t, "y\n", value, value)
	if err := relaySend(context.Background(), prompter, out, sender.api, sender.cfg.VaultID, vaultKey, sender.self,
		sender.secrets.SigningPrivate, time.Now); err == nil || !strings.Contains(err.Error(), "no pending relay request") {
		t.Fatalf("second send: %v", err)
	}
}

func TestRelaySendRefusesUnconfirmedCodeMismatchedEntryAndWrongVault(t *testing.T) {
	vaultKey, target, sender := twoDevices(t)
	value := "relay-cli-marker-not-sent-000001"
	owner := &ownerB{sas: make(chan string, 1), confirm: true}
	vault, done, cancel := startRelayBroker(t, vaultKey, target, owner)
	<-owner.sas
	send := func(answers string, key []byte, hidden ...string) (string, error) {
		prompter, out := ownerA(t, answers, hidden...)
		err := relaySend(context.Background(), prompter, out, sender.api, sender.cfg.VaultID, key, sender.self,
			sender.secrets.SigningPrivate, time.Now)
		return out.String(), err
	}
	if _, err := send("n\n", vaultKey, value, value); err == nil || !strings.Contains(err.Error(), "code not confirmed") {
		t.Fatalf("unconfirmed code: %v", err)
	}
	if _, err := send("y\n", vaultKey, value, value+"x"); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("mismatched entry: %v", err)
	}
	if _, err := send("y\n", vaultKey, "short", "short"); err == nil {
		t.Fatal("short value sent")
	}
	otherKey, _ := secure.RandomBytes(32)
	text, err := send("y\n", otherKey, value, value)
	if err == nil || !strings.Contains(text, "failed verification") {
		t.Fatalf("request opened with another vault key: %v\n%s", err, text)
	}
	cancel()
	if resp := <-done; resp.State != agentbroker.StateDenied {
		t.Fatalf("resp %+v", resp)
	}
	if names, _ := vault.Names(context.Background()); len(names) != 0 {
		t.Fatalf("stored %v", names)
	}
	// The broker withdrew its request when the agent went away.
	if listed, _ := sender.api.ListRelays(); len(listed) != 0 {
		t.Fatalf("request still pending after cancel: %d", len(listed))
	}
}

func TestRelayTargetDeclineStoresNothing(t *testing.T) {
	vaultKey, target, sender := twoDevices(t)
	value := "relay-cli-marker-declined-00001"
	owner := &ownerB{sas: make(chan string, 1), confirm: false}
	vault, done, _ := startRelayBroker(t, vaultKey, target, owner)
	<-owner.sas
	prompter, out := ownerA(t, "y\n", value, value)
	if err := relaySend(context.Background(), prompter, out, sender.api, sender.cfg.VaultID, vaultKey, sender.self,
		sender.secrets.SigningPrivate, time.Now); err != nil {
		t.Fatal(err)
	}
	if resp := <-done; resp.State != agentbroker.StateDenied {
		t.Fatalf("resp %+v", resp)
	}
	if names, _ := vault.Names(context.Background()); len(names) != 0 {
		t.Fatalf("stored %v", names)
	}
}

func TestAgentRelayRequestUsage(t *testing.T) {
	for _, args := range [][]string{{"relay-request"}, {"relay-request", "--name", "X"}, {"relay-request", "--reason", "r"}, {"relay-request", "--name", "X", "--reason", "r", "extra"}} {
		if err := agentCommand(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := relayCommand([]string{"receive"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatal("unknown relay subcommand accepted")
	}
}
