package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/setup"
)

// setupCommand is agent-operable and read-only: it plans and reports. Applying a
// plan (owner secrets, persistent services) happens through the owner-held
// broker, never from the agent's own terminal.
func setupCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("setup subcommand is required (supported: plan, status)")
	}
	switch args[0] {
	case "plan":
		return setupPlan(args[1:])
	case "status":
		return setupStatus(args[1:])
	default:
		return fmt.Errorf("unknown setup subcommand %q (supported: plan, status)", args[0])
	}
}

func setupRequestFlags(fs *flag.FlagSet) *setup.Request {
	r := &setup.Request{}
	fs.StringVar(&r.Sync, "sync", setup.SyncLocalServer, "local_server, hosted or local_only")
	fs.StringVar(&r.ServerURL, "server", "", "hosted: https URL of the EnvBank service")
	fs.StringVar(&r.VaultName, "vault-name", "personal", "vault name")
	fs.StringVar(&r.DeviceName, "device-name", "", "this device's name")
	fs.StringVar(&r.ConfigPath, "config", defaultConfigPath(), "device identity path (internal volume)")
	fs.StringVar(&r.VaultDir, "vault-dir", "", "local_server: private vault directory on an ownership-enforcing volume")
	fs.StringVar(&r.BackupDir, "backup-dir", "", "private directory for recovery artifacts on a separate volume")
	return r
}

func setupPlan(args []string) error {
	fs := flag.NewFlagSet("setup plan", flag.ContinueOnError)
	req := setupRequestFlags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: envbank setup plan --sync local_server|hosted --device-name NAME --backup-dir DIR [--vault-dir DIR] [--server URL] [--vault-name NAME] [--config PATH]")
	}
	plan, err := setup.PlanFor(*req, setup.SystemInspector{})
	if err != nil {
		return err
	}
	return printJSON(plan)
}

// LayoutPath is the non-secret layout manifest next to the device identity.
func layoutPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "layout.json")
}

type setupStatusReport struct {
	ConfigPath      string        `json:"config_path"`
	DeviceIdentity  bool          `json:"device_identity_present"`
	Layout          *setup.Layout `json:"layout,omitempty"`
	LayoutProblem   string        `json:"layout_problem,omitempty"`
	VaultVolumeOK   *bool         `json:"vault_volume_mounted_and_matching,omitempty"`
	BackupVolumeOK  *bool         `json:"backup_volume_mounted_and_matching,omitempty"`
	ServerReachable *bool         `json:"server_reachable,omitempty"`
	BrokerRunning   bool          `json:"broker_running"`
	Next            string        `json:"next"`
}

func setupStatus(args []string) error {
	fs := flag.NewFlagSet("setup status", flag.ContinueOnError)
	cfg := fs.String("config", defaultConfigPath(), "device identity path")
	socket := fs.String("socket", agentbroker.DefaultSocketPath(), "agent broker socket")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: envbank setup status [--config PATH] [--socket PATH]")
	}
	r := setupStatusReport{ConfigPath: *cfg}
	// Existence only: the identity file is never opened here.
	if _, err := os.Lstat(*cfg); err == nil {
		r.DeviceIdentity = true
	}
	if raw, err := os.ReadFile(layoutPath(*cfg)); err == nil {
		var l setup.Layout
		if json.Unmarshal(raw, &l) != nil || l.V != setup.LayoutVersion {
			r.LayoutProblem = "layout manifest unreadable or unknown version"
		} else {
			r.Layout = &l
			check := func(dir, uuid string) *bool {
				ok := false
				if v, err := (setup.SystemInspector{}).VolumeOf(dir); err == nil {
					ok = v.UUID == uuid && v.OwnersEnabled
				}
				return &ok
			}
			if l.VaultDir != "" {
				r.VaultVolumeOK = check(l.VaultDir, l.VaultVolumeUUID)
			}
			if l.BackupDir != "" {
				r.BackupVolumeOK = check(l.BackupDir, l.BackupVolumeUUID)
			}
			reach := serverReachable(l.ServerURL)
			r.ServerReachable = &reach
		}
	}
	if conn, err := net.DialTimeout("unix", *socket, 500*time.Millisecond); err == nil {
		conn.Close()
		r.BrokerRunning = true
	}
	switch {
	case !r.DeviceIdentity && !r.BrokerRunning:
		r.Next = "ask the owner to start `envbank agent-broker` (or the desktop host) so setup can collect secrets; then propose a layout with `envbank setup plan`"
	case !r.DeviceIdentity:
		r.Next = "propose a layout with `envbank setup plan`; applying it through the broker is the next release"
	case !r.BrokerRunning:
		r.Next = "ask the owner to start `envbank agent-broker` to unlock the vault for agent use"
	default:
		r.Next = "ready: use envbank agent names/request/run"
	}
	return printJSON(r)
}

func serverReachable(base string) bool {
	if base == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
