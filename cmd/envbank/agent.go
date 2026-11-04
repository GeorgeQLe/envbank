package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/setup"
	"golang.org/x/term"
)

// brokerVault adapts the unlocked EnvBank client. Calls are serialized: the
// client signs requests with replay protection.
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

func (v *brokerVault) Exists(ctx context.Context, name string) (bool, error) {
	names, err := v.Names(ctx)
	if err != nil {
		return false, err
	}
	i := sort.SearchStrings(names, name)
	return i < len(names) && names[i] == name, nil
}

func (v *brokerVault) Store(_ context.Context, name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := putSecretValue(v.api, v.vaultKey, name, value, -1)
	return err
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
	socket := fs.String("socket", agentbroker.DefaultSocketPath(), "Unix socket agents connect to")
	idle := fs.Duration("idle-lock", 30*time.Minute, "lock (exit) after this long without requests")
	lifetime := fs.Duration("max-lifetime", 12*time.Hour, "lock (exit) after this long regardless of activity")
	ownerInput := fs.String("owner-input", "terminal", "where the owner types secrets: terminal or chromux (verified, paired desktop provider)")
	oiTeam := fs.String("owner-input-team", "NC56VXK48K", "Apple Team ID the desktop provider must be signed by")
	oiIdent := fs.String("owner-input-identifier", "party.gblock.chromux.v2.desktop", "code-signing identifier of the desktop provider")
	oiSocket := fs.String("owner-input-socket", ownerinput.DefaultSocketPath(), "desktop provider socket")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *idle < time.Minute || *lifetime < *idle {
		return errors.New("usage: envbank agent-broker [--socket PATH] [--idle-lock 30m] [--max-lifetime 12h] [auth flags]")
	}
	terminal, err := agentbroker.NewTerminalPrompter(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	prompter := &ownerSurface{TerminalPrompter: terminal}
	switch *ownerInput {
	case "terminal":
	case "chromux":
		p := &ownerinput.Provider{Socket: *oiSocket, TeamID: *oiTeam, Identifier: *oiIdent}
		pctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := pairProvider(pctx, p, terminal)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stdout, "Chromux secure input not paired (%v); secrets will be typed in this terminal.\n", err)
		} else {
			prompter.provider = p
			fmt.Println("Chromux secure input paired for this session.")
		}
	default:
		return errors.New("--owner-input must be terminal or chromux")
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
	cfg, err := client.LoadConfig(auth.configPath)
	switch {
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
		applier := &setupApplier{owner: prompter, inspector: setup.SystemInspector{}, service: launchdService{executable: exe, home: home, uid: os.Getuid()}, now: time.Now}
		if broker, err = agentbroker.New(agentbroker.Options{Setup: applier, Prompter: prompter, Runner: agentbroker.ExecRunner{}, Path: os.Getenv("PATH"), BaseEnv: agentbroker.BaseEnv()}); err != nil {
			return err
		}
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
		if broker, err = agentbroker.New(agentbroker.Options{Vault: vault, Prompter: prompter, Runner: agentbroker.ExecRunner{}, Path: os.Getenv("PATH"), BaseEnv: agentbroker.BaseEnv()}); err != nil {
			return err
		}
	}
	defer broker.Close()
	listener, err := agentbroker.Listen(*socket)
	if err != nil {
		return err
	}
	defer os.Remove(*socket)
	ctx, stop := shutdownSignalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *lifetime)
	defer cancel()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
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
	fmt.Printf("EnvBank agent broker unlocked. Agents connect via %s\n", *socket)
	fmt.Println("Approvals and secret entry happen here. Keep this terminal to yourself; Ctrl-C locks.")
	err = agentbroker.Serve(ctx, listener, broker, func() { last.Store(time.Now().UnixNano()) })
	fmt.Println("EnvBank agent broker locked.")
	return err
}

// brokerPassphrase prefers typing the passphrase into the broker terminal: a
// passphrase file or environment variable readable by agents would let them
// unlock the vault themselves and defeat the broker.
func brokerPassphrase(auth *authFlags) ([]byte, error) {
	if auth.passphraseFile != "" || os.Getenv("ENVBANK_PASSPHRASE") != "" {
		fmt.Fprintln(os.Stderr, "warning: a passphrase file or ENVBANK_PASSPHRASE that agents can read lets them bypass the broker")
		return readPassphrase(auth.passphraseFile)
	}
	fmt.Print("EnvBank passphrase (hidden): ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
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
		req = agentbroker.Request{Op: agentbroker.OpRun, Secrets: secrets, Argv: argv, Dir: *dir, TimeoutSeconds: *timeout}
	default:
		return fmt.Errorf("unknown agent subcommand %q (supported: names, request, run)", args[0])
	}
	resp, err := agentbroker.Call(ctx, *socket, req)
	if err != nil {
		return fmt.Errorf("%v: start `envbank agent-broker` in your own terminal", err)
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
	socket := fs.String("agent-broker-socket", agentbroker.DefaultSocketPath(), "agent broker socket for the envbank_secret_* tools")
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
