package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/authz"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/live"
	"github.com/GeorgeQLe/envbank/internal/setup"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"golang.org/x/term"
)

// brokerVault adapts the unlocked EnvBank client. Calls are serialized: the
// client signs requests with replay protection.
//
// Memory hygiene, honestly: Names and Values (agent run injection) decrypt
// every record into protocol.SecretRecord, whose Value is a Go string that
// cannot be wiped. The provider-action paths avoid that where the client API
// allows: Exists and Revision find the record by its keyed ID without
// decrypting anything; Latest and ReadSecret decrypt only the one record,
// into byte buffers that are wiped after the callback. StoreSecret (through
// putSecretValue) still decrypts every record to preserve the record's
// metadata, and encrypts the new value from a string; those strings stay
// in memory until the garbage collector reuses them.
type brokerVault struct {
	mu       sync.Mutex
	api      *client.API
	vaultKey []byte
}

func (v *brokerVault) records() ([]protocol.SecretRecord, error) {
	encrypted, err := v.api.ListRecords()
	if err != nil {
		return nil, err
	}
	return client.DecryptRecords(v.api.Config.VaultID, v.vaultKey, encrypted)
}

func (v *brokerVault) Names(context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	records, err := v.records()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names, nil
}

func (v *brokerVault) Values(_ context.Context, names []string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	records, err := v.records()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]string, len(records))
	for _, r := range records {
		byName[r.Name] = r.Value
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		value, ok := byName[n]
		if !ok {
			return nil, agentbroker.ErrMissing
		}
		out[n] = value
	}
	return out, nil
}

// find returns name's encrypted record by keyed ID; nothing is decrypted.
func (v *brokerVault) find(name string) (protocol.Record, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	encrypted, err := v.api.ListRecords()
	if err != nil {
		return protocol.Record{}, false, err
	}
	record, ok := client.FindRecord(v.vaultKey, encrypted, name)
	return record, ok, nil
}

// Exists finds the record by keyed ID without decrypting any record.
func (v *brokerVault) Exists(_ context.Context, name string) (bool, error) {
	_, ok, err := v.find(name)
	return ok, err
}

// Revision implements provideraction.Vault: the revision the sync service
// reports for name, without decrypting any record. It is advisory: every
// read of a value (ReadSecret) authenticates the revision inside the
// ciphertext.
func (v *brokerVault) Revision(_ context.Context, name string) (int64, error) {
	record, ok, err := v.find(name)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, provideraction.ErrMissing
	}
	return record.Revision, nil
}

func (v *brokerVault) Store(_ context.Context, name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := putSecretValue(v.api, v.vaultKey, name, value, -1)
	return err
}

// StoreSecret implements provideraction.Vault (lifecycle.RecordWriter): it
// durably stores the value fill supplies and returns the new revision.
func (v *brokerVault) StoreSecret(_ context.Context, name string, fill func(func([]byte) error) error) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var revision int64
	err := fill(func(value []byte) error {
		record, err := putSecretValue(v.api, v.vaultKey, name, string(value), -1)
		if err != nil {
			return err
		}
		revision = record.Revision
		return nil
	})
	if err != nil || revision < 1 {
		return 0, errors.New("record could not be stored")
	}
	return revision, nil
}

// latest decrypts only name's record and returns its value (a buffer the
// caller wipes) and authenticated revision.
func (v *brokerVault) latest(name string) ([]byte, int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	encrypted, err := v.api.ListRecords()
	if err != nil {
		return nil, 0, err
	}
	record, ok := client.FindRecord(v.vaultKey, encrypted, name)
	if !ok {
		return nil, 0, provideraction.ErrMissing
	}
	value, err := client.DecryptRecordValue(v.api.Config.VaultID, v.vaultKey, record, name)
	if err != nil {
		return nil, 0, err
	}
	return value, record.Revision, nil
}

// Latest implements provideraction.Vault: consume sees the current value
// (outside the vault lock); the buffer is wiped afterwards. Only this
// record is decrypted.
func (v *brokerVault) Latest(_ context.Context, name string, consume func([]byte) error) (int64, error) {
	value, revision, err := v.latest(name)
	if err != nil {
		return 0, err
	}
	defer wipeBytes(value)
	if err := consume(value); err != nil {
		return 0, err
	}
	return revision, nil
}

// ReadSecret implements lifecycle.RecordReader: only the exact revision.
func (v *brokerVault) ReadSecret(_ context.Context, name string, revision int64, consume func([]byte) error) error {
	value, current, err := v.latest(name)
	if err != nil {
		return err
	}
	defer wipeBytes(value)
	if current != revision {
		return errors.New("record revision changed")
	}
	return consume(value)
}

// objectErr maps an absent vault object (HTTP 404) to ErrMissing.
func objectErr(err error) error {
	var status client.HTTPStatusError
	if errors.As(err, &status) && status.Status == http.StatusNotFound {
		return provideraction.ErrMissing
	}
	return err
}

// LoadBinding implements provideraction.BindingStore: bindings are
// encrypted vault objects (never records), keyed by record name.
func (v *brokerVault) LoadBinding(_ context.Context, record string) (provideraction.Binding, int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	object, err := v.api.GetObject(v.vaultKey, vaultobject.KindProviderBinding, record)
	if err != nil {
		return provideraction.Binding{}, 0, objectErr(err)
	}
	b, err := provideraction.DecodeBinding(object.Payload)
	if err != nil || b.Record != record {
		return provideraction.Binding{}, 0, errors.New("provider binding is invalid")
	}
	return b, object.Revision, nil
}

// SaveBinding implements provideraction.BindingStore (optimistic revision).
func (v *brokerVault) SaveBinding(_ context.Context, b provideraction.Binding, expected int64) (int64, error) {
	if !b.Valid() {
		return 0, errors.New("provider binding is invalid")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	object, err := v.api.PutObject(v.vaultKey, vaultobject.KindProviderBinding, b.Record, b, expected)
	if err != nil {
		return 0, err
	}
	return object.Revision, nil
}

// ListBindings implements provideraction.BindingStore. An invalid binding
// fails the whole list: revocation must not skip one silently.
func (v *brokerVault) ListBindings(context.Context) ([]provideraction.StoredBinding, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	objects, err := v.api.ListObjects(v.vaultKey)
	if err != nil {
		return nil, err
	}
	var out []provideraction.StoredBinding
	for _, object := range objects {
		if object.Kind != vaultobject.KindProviderBinding {
			continue
		}
		b, err := provideraction.DecodeBinding(object.Payload)
		if err != nil || b.Record != object.Key {
			return nil, errors.New("provider binding is invalid")
		}
		out = append(out, provideraction.StoredBinding{Binding: b, Revision: object.Revision})
	}
	return out, nil
}

// LoadVercelProject implements provideraction.BindingStore.
func (v *brokerVault) LoadVercelProject(_ context.Context, teamID, projectID string) (provideraction.VercelProject, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := provideraction.VercelProjectKey(teamID, projectID)
	object, err := v.api.GetObject(v.vaultKey, vaultobject.KindProviderVercelProject, key)
	if err != nil {
		return provideraction.VercelProject{}, objectErr(err)
	}
	p, err := provideraction.DecodeVercelProject(object.Payload)
	if err != nil || provideraction.VercelProjectKey(p.TeamID, p.ProjectID) != key {
		return provideraction.VercelProject{}, errors.New("vercel project provenance is invalid")
	}
	return p, nil
}

// SaveVercelProject implements provideraction.BindingStore (create only:
// project IDs are never reused).
func (v *brokerVault) SaveVercelProject(_ context.Context, p provideraction.VercelProject) error {
	if !p.Valid() {
		return errors.New("vercel project provenance is invalid")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.api.PutObject(v.vaultKey, vaultobject.KindProviderVercelProject, provideraction.VercelProjectKey(p.TeamID, p.ProjectID), p, 0)
	return err
}

// LoadNeonProject implements provideraction.BindingStore.
func (v *brokerVault) LoadNeonProject(_ context.Context, projectID string) (provideraction.NeonProjectProvenance, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	object, err := v.api.GetObject(v.vaultKey, vaultobject.KindProviderNeonProject, projectID)
	if err != nil {
		return provideraction.NeonProjectProvenance{}, objectErr(err)
	}
	p, err := provideraction.DecodeNeonProject(object.Payload)
	if err != nil || p.ProjectID != projectID {
		return provideraction.NeonProjectProvenance{}, errors.New("neon project provenance is invalid")
	}
	return p, nil
}

// SaveNeonProject implements provideraction.BindingStore (create only).
func (v *brokerVault) SaveNeonProject(_ context.Context, p provideraction.NeonProjectProvenance) error {
	if !p.Valid() {
		return errors.New("neon project provenance is invalid")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.api.PutObject(v.vaultKey, vaultobject.KindProviderNeonProject, p.ProjectID, p, 0)
	return err
}

// LoadStripeEndpoint implements provideraction.BindingStore.
func (v *brokerVault) LoadStripeEndpoint(_ context.Context, endpointID string) (provideraction.StripeEndpointProvenance, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	object, err := v.api.GetObject(v.vaultKey, vaultobject.KindProviderStripeEndpoint, endpointID)
	if err != nil {
		return provideraction.StripeEndpointProvenance{}, objectErr(err)
	}
	p, err := provideraction.DecodeStripeEndpoint(object.Payload)
	if err != nil || p.EndpointID != endpointID {
		return provideraction.StripeEndpointProvenance{}, errors.New("stripe endpoint provenance is invalid")
	}
	return p, nil
}

// SaveStripeEndpoint implements provideraction.BindingStore (create only:
// endpoint IDs are never reused).
func (v *brokerVault) SaveStripeEndpoint(_ context.Context, p provideraction.StripeEndpointProvenance) error {
	if !p.Valid() {
		return errors.New("stripe endpoint provenance is invalid")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.api.PutObject(v.vaultKey, vaultobject.KindProviderStripeEndpoint, p.EndpointID, p, 0)
	return err
}

// providerActionFactory is the seam where the concrete Neon, Vercel and
// Stripe adapters plug in (docs/provider-actions.md). Unless the owner
// starts the broker with --provider-actions it returns nil, and every
// provider_action answers PROVIDER_UNAVAILABLE. The live factory always uses
// the providers' fixed production endpoints.
func providerActionFactory(enabled bool, neonOrgID string) (provideraction.Factory, error) {
	if !enabled {
		if neonOrgID != "" {
			return nil, errors.New("--neon-org-id needs --provider-actions")
		}
		return nil, nil
	}
	f, err := live.New(live.Config{NeonOrgID: neonOrgID})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// newProviderService builds the broker's provider-action service. vault is
// nil in setup mode (no vault unlocked): actions are then unavailable.
func newProviderService(vault *brokerVault, factory provideraction.Factory) *provideraction.Service {
	opts := provideraction.Options{Factory: factory}
	if vault != nil {
		opts.Vault = vault
	}
	return provideraction.New(opts)
}

func (v *brokerVault) wipe() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.vaultKey {
		v.vaultKey[i] = 0
	}
}

// agentBrokerCommand runs the owner-held broker in the owner's terminal.
func agentBrokerCommand(args []string) error {
	fs := flag.NewFlagSet("agent-broker", flag.ContinueOnError)
	legacySocket := fs.Bool("legacy-socket", false, "DEVELOPMENT ONLY, unqualified: also serve the unauthenticated Unix-socket agent API (envbank agent, envbank mcp serve)")
	socket := fs.String("socket", agentbroker.DefaultSocketPath(), "Unix socket for --legacy-socket")
	allowPassword := fs.Bool("allow-password-fallback", false, "let approvals fall back to the login password when Touch ID fails (default: biometrics only)")
	testApprover := registerTestApprover(fs)
	idle := fs.Duration("idle-lock", 30*time.Minute, "lock (exit) after this long without requests")
	lifetime := fs.Duration("max-lifetime", 12*time.Hour, "lock (exit) after this long regardless of activity")
	setupMode := fs.Bool("setup", false, "allow agent-proposed setup when this device has no vault yet")
	useExisting := fs.Bool("use-existing-server", false, "setup: allow reusing an EnvBank server you already started on the plan's address")
	ownerInput := fs.String("owner-input", "terminal", "where the owner types secrets: terminal or chromux (verified, paired desktop provider)")
	oiTeam := fs.String("owner-input-team", "NC56VXK48K", "Apple Team ID the desktop owner-input service must be signed by (Developer ID)")
	oiIdent := fs.String("owner-input-identifier", ownerInputIdentifier, "code-signing identifier of the owner-input XPC service")
	oiService := fs.String("owner-input-service", ownerinput.BrokerServiceName, "Mach service name of the owner-input XPC service")
	oiUnqualified := fs.Bool("owner-input-unqualified", false, "use the Chromux XPC owner input before its installed-build no-leak qualification has passed")
	providerActions := fs.Bool("provider-actions", false, "let authorized agents request provider actions (Neon, Vercel, Stripe test mode) with CONTROL_* credentials from the vault; each needs a provider grant and its own Touch ID (default off: PROVIDER_UNAVAILABLE)")
	neonOrgID := fs.String("neon-org-id", "", "with --provider-actions: Neon organization (org-…) to create projects in")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *idle < time.Minute || *lifetime < *idle {
		return errors.New("usage: envbank agent-broker [--owner-input chromux --owner-input-unqualified] [--legacy-socket [--socket PATH]] [--allow-password-fallback] [--provider-actions [--neon-org-id org-…]] [--idle-lock 30m] [--max-lifetime 12h] [auth flags]")
	}
	factory, err := providerActionFactory(*providerActions, *neonOrgID)
	if err != nil {
		return err
	}
	// A test-approver build never reaches Chromux or a real vault.
	if err := testBuildGuard(*ownerInput, *oiIdent, auth.configPath); err != nil {
		return err
	}
	// The config is read (not unlocked) first: a broken one fails before any
	// prompt, and its vault and device name the broker in the pairing.
	cfg, cfgErr := client.LoadConfig(auth.configPath)
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		return cfgErr
	}
	label := ownerinput.PairingLabel{VaultFingerprint: ownerinput.SetupVaultFingerprint}
	if cfgErr == nil {
		label = ownerinput.PairingLabel{VaultFingerprint: ownerinput.VaultFingerprint(cfg.VaultID), DeviceName: cfg.DeviceName}
	}
	terminal, err := agentbroker.NewTerminalPrompter(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	// Every grant and approval is a Touch ID check; typing in this terminal
	// approves nothing.
	// The enrollment state is recorded now: approvals are refused if the
	// enrolled fingerprints change while this broker runs.
	var approver approval.Approver
	if t := testApprover(); t != nil {
		approver = t
	} else {
		approver = approval.NewLocalAuth(*allowPassword)
	}
	if *allowPassword {
		fmt.Println("WARNING: --allow-password-fallback: an approval can also be made with the login password, which a process that has seen you type it could enter.")
	}
	if !approver.Available() {
		fmt.Println("WARNING: Touch ID is unavailable on this Mac (no enrolled biometry or no sensor): every grant and approval will be refused (APPROVAL_UNAVAILABLE).")
	}
	prompter := &ownerSurface{TerminalPrompter: terminal, approver: approver}
	var channel *ownerinput.AgentChannel
	// Once the broker exists, a re-pairing's Touch ID waits its turn on the
	// owner channel like every other approval.
	var ownerChannel atomic.Pointer[agentbroker.Broker]
	switch *ownerInput {
	case "terminal":
	case "chromux":
		// XPC transport: macOS checks the service's code signature on every
		// message (Developer ID, pinned team and identifier, not debuggable);
		// after pairing, the exact service build is pinned by cdhash.
		if !*oiUnqualified {
			return errors.New("--owner-input chromux has not passed its installed-build no-leak qualification yet; add --owner-input-unqualified to use it anyway (or use the terminal)")
		}
		p := &ownerinput.XPCProvider{Service: *oiService, TeamID: *oiTeam, Identifier: *oiIdent, Label: label}
		ch := &ownerinput.AgentChannel{Provider: p, Notify: prompter.Notify}
		// Pairing happens on the connection the agent channel registers on,
		// and needs the owner's Touch ID in Chromux (the service replies
		// "confirmed") and then here. Allow time to compare the codes.
		pctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err := pairProvider(pctx, channelPairer{ch: ch, serialize: &ownerChannel}, terminal, approver, label)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stdout, "Chromux secure input not paired (%v); secrets will be typed in this terminal.\n", err)
		} else {
			prompter.provider = ch // entry only on the paired agent-channel connection
			channel = ch
			fmt.Println("Chromux secure input paired for this session (UNQUALIFIED: installed-build no-leak qualification pending).")
		}
	default:
		return errors.New("--owner-input must be terminal or chromux")
	}
	if channel == nil && !*legacySocket {
		return errors.New("no agent channel: authorized agents reach the broker only through a paired Chromux (--owner-input chromux --owner-input-unqualified); --legacy-socket is for development only")
	}
	state, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), state) // never leave echo off
	var broker *agentbroker.Broker
	var vault *brokerVault
	defer func() {
		if vault != nil {
			vault.wipe()
		}
	}()
	switch err := cfgErr; {
	case errors.Is(err, os.ErrNotExist) && !*setupMode:
		return fmt.Errorf("no EnvBank device config at %s: run `envbank init` or `envbank enroll-request`, or start `envbank agent-broker --setup` to let an agent propose a setup", auth.configPath)
	case errors.Is(err, os.ErrNotExist):
		// Setup mode: no vault on this device yet. Agents may propose a setup;
		// every secret and persistent change is collected/confirmed here.
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		applier := &setupApplier{allowExistingServer: *useExisting, owner: prompter, inspector: setup.SystemInspector{}, service: launchdService{executable: exe, home: home, uid: os.Getuid()}, now: time.Now}
		if broker, err = agentbroker.New(agentbroker.Options{Setup: applier, Prompter: prompter, Approver: approver, Runner: agentbroker.ExecRunner{}, Path: os.Getenv("PATH"), BaseEnv: agentbroker.BaseEnv()}); err != nil {
			return err
		}
		defer func() {
			if applier.created != nil {
				applier.created.wipe()
			}
		}()
		fmt.Printf("No EnvBank vault on this device (%s): starting in SETUP MODE.\n", auth.configPath)
		fmt.Println("An agent can propose a setup (`envbank setup apply`); you will confirm it and type passphrases here.")
	case err != nil:
		return err
	default:
		passphrase, err := brokerPassphrase(auth)
		if err != nil {
			return err
		}
		secrets, err := cfg.Unlock(passphrase)
		for i := range passphrase {
			passphrase[i] = 0
		}
		if err != nil {
			return err
		}
		api := client.NewAPI(cfg.Server)
		api.Config, api.Secrets, api.Access = cfg, secrets, cfg.AccessCredentials()
		vaultKey, err := requireVaultKey(secrets)
		if err != nil {
			return err
		}
		vault = &brokerVault{api: api, vaultKey: vaultKey}
		if _, err := vault.Names(context.Background()); err != nil {
			return fmt.Errorf("vault check failed: %w", err)
		}
		if broker, err = agentbroker.New(agentbroker.Options{Vault: vault, Prompter: prompter, Approver: approver, Runner: agentbroker.ExecRunner{}, Path: os.Getenv("PATH"), BaseEnv: agentbroker.BaseEnv()}); err != nil {
			return err
		}
	}
	defer broker.Close()
	ownerChannel.Store(broker)
	gate := authz.NewGate(broker, prompter, nil)
	// Provider actions run only on the host channel, behind a provider grant;
	// with no factory configured they answer PROVIDER_UNAVAILABLE.
	gate.Provider = newProviderService(vault, factory)
	if factory != nil {
		fmt.Println("Provider actions ON (--provider-actions): granted agents may request Neon, Vercel and Stripe (test mode) actions; each shows its plan and needs Touch ID.")
	}
	defer gate.Close() // grants and provider operations are memory-only and end when the broker locks
	var listener net.Listener
	if *legacySocket {
		if listener, err = agentbroker.Listen(*socket); err != nil {
			return err
		}
		defer os.Remove(*socket)
	}
	ctx, stop := shutdownSignalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *lifetime)
	defer cancel()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	activity := func() { last.Store(time.Now().UnixNano()) }
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > *idle {
					prompter.Notify("idle lock reached; stopping")
					cancel()
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	var serveErr error
	if channel != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := channel
			ch.Handler, ch.Activity = gate, activity
			if err := ch.Run(ctx); err != nil {
				prompter.Notify("authorized-agent channel stopped: " + err.Error())
			}
		}()
		fmt.Println("EnvBank agent broker unlocked. Authorized agents reach it through Chromux; each needs a grant you approve with Touch ID.")
	}
	if listener != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveErr = agentbroker.Serve(ctx, listener, broker, activity)
			if serveErr != nil {
				cancel()
			}
		}()
		fmt.Printf("WARNING: --legacy-socket (DEVELOPMENT ONLY, UNQUALIFIED): any process running as you can make requests via %s, without a grant. Approvals still need Touch ID.\n", *socket)
	}
	fmt.Println("Approvals and grants need Touch ID; typing in this terminal approves nothing. Secret entry happens in Chromux or here. Ctrl-C locks.")
	<-ctx.Done()
	wg.Wait()
	fmt.Println("EnvBank agent broker locked.")
	return serveErr
}

// channelPairer pairs the agent channel's own connection (pairer for
// pairProvider). Its confirmation is kept for re-pairing after a service
// restart or reconnect, serialized on the owner channel once the broker runs.
type channelPairer struct {
	ch        *ownerinput.AgentChannel
	serialize *atomic.Pointer[agentbroker.Broker]
}

func (c channelPairer) Pair(ctx context.Context, confirm func(ownerinput.Identity, string) bool) error {
	c.ch.Confirm = func(id ownerinput.Identity, code string) bool {
		b := c.serialize.Load()
		if b == nil {
			return confirm(id, code)
		}
		qctx, cancel := context.WithTimeout(context.Background(), 2*approval.DefaultTimeout)
		defer cancel()
		return b.WithOwnerPrompt(qctx, func() agentbroker.Response {
			return agentbroker.Response{OK: confirm(id, code)}
		}).OK
	}
	return c.ch.Open(ctx)
}

// brokerPassphrase prefers typing the passphrase into the broker terminal: a
// passphrase file or environment variable readable by agents would let them
// unlock the vault themselves and defeat the broker.
func brokerPassphrase(auth *authFlags) ([]byte, error) {
	if auth.passphraseFile != "" || os.Getenv("ENVBANK_PASSPHRASE") != "" {
		fmt.Fprintln(os.Stderr, "warning: a passphrase file or ENVBANK_PASSPHRASE that agents can read lets them bypass the broker")
		return readPassphrase(auth.passphraseFile)
	}
	raw, err := agentbroker.ReadHidden(os.Stdin, os.Stdout, "EnvBank passphrase (hidden): ")
	fmt.Println()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	return raw, nil
}

// agentCommand is the agent-side client: no vault access, no passphrase.
func agentCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("agent subcommand is required (supported: names, request, run)")
	}
	fs := flag.NewFlagSet("agent "+args[0], flag.ContinueOnError)
	socket := fs.String("socket", agentbroker.DefaultSocketPath(), "agent broker socket")
	ctx := context.Background()
	var req agentbroker.Request
	switch args[0] {
	case "names":
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: envbank agent names [--socket PATH]")
		}
		req.Op = agentbroker.OpNames
	case "request":
		reason := fs.String("reason", "", "why the agent needs this secret (shown to the owner)")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 || *reason == "" {
			return errors.New("usage: envbank agent request --reason TEXT [--socket PATH] NAME")
		}
		req = agentbroker.Request{Op: agentbroker.OpRequest, Name: fs.Arg(0), Reason: *reason}
	case "run":
		var secrets stringList
		fs.Var(&secrets, "secret", "secret NAME to inject (repeatable)")
		always := fs.Bool("always", false, "ask the owner to approve this exact command until the broker locks (fixed programs only)")
		dir := fs.String("dir", "", "absolute working directory (default: current directory)")
		timeout := fs.Int("timeout", 0, "seconds (default 120, max 1800)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		argv := fs.Args()
		if len(argv) > 0 && argv[0] == "--" {
			argv = argv[1:]
		}
		if len(secrets) == 0 || len(argv) == 0 {
			return errors.New("usage: envbank agent run --secret NAME [--secret NAME] [--dir DIR] [--timeout S] -- COMMAND [ARGS...]")
		}
		if *dir == "" {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			*dir = wd
		}
		req = agentbroker.Request{Op: agentbroker.OpRun, Secrets: secrets, Argv: argv, Dir: *dir, TimeoutSeconds: *timeout, Always: *always}
	default:
		return fmt.Errorf("unknown agent subcommand %q (supported: names, request, run)", args[0])
	}
	resp, err := agentbroker.Call(ctx, *socket, req)
	if err != nil {
		return fmt.Errorf("%v: `envbank agent` reaches only a development broker started with --legacy-socket (authorized agents use the desktop host's EnvBank tools)", err)
	}
	if !resp.OK {
		return errors.New(resp.Code)
	}
	switch req.Op {
	case agentbroker.OpNames:
		for _, n := range resp.Names {
			fmt.Println(n)
		}
	case agentbroker.OpRequest:
		fmt.Println(resp.State)
		if resp.State != agentbroker.StateStored {
			return exitCodeError{code: 3}
		}
	case agentbroker.OpRun:
		fmt.Fprint(os.Stdout, resp.Stdout)
		fmt.Fprint(os.Stderr, resp.Stderr)
		if resp.Redactions > 0 || resp.Truncated || resp.TimedOut {
			fmt.Fprintf(os.Stderr, "envbank: %d redaction(s), truncated=%v, timed_out=%v\n", resp.Redactions, resp.Truncated, resp.TimedOut)
		}
		if resp.ExitCode != nil && *resp.ExitCode != 0 {
			code := *resp.ExitCode
			if code < 0 || code > 255 {
				code = 1
			}
			return exitCodeError{code: code}
		}
	}
	return nil
}

type stringList []string

func (s *stringList) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// mcpServe serves MCP on stdio with the agent secret tools forwarded to the broker.
func mcpServe(args []string) error {
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	socket := fs.String("agent-broker-socket", agentbroker.DefaultSocketPath(), "development broker socket (--legacy-socket brokers only) for the envbank_secret_* tools")
	disable := fs.Bool("no-agent-broker", false, "omit the envbank_secret_* tools")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: envbank mcp serve [--agent-broker-socket PATH] [--no-agent-broker]")
	}
	server := mcpserver.Server{}
	if !*disable {
		server.Extension = agentbroker.MCPExtension{Socket: *socket}
	}
	return server.Serve(context.Background(), os.Stdin, os.Stdout)
}
