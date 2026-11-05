package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/recovery"
	"github.com/GeorgeQLe/envbank/internal/setup"
)

// setupOwner is the owner surface for setup (the broker terminal for display,
// Touch ID for every confirmation, and the desktop host or terminal for
// secret entry).
type setupOwner interface {
	// Confirm shows lines for reference and asks for Touch ID with reason.
	Confirm(ctx context.Context, title string, lines []string, reason string) approval.Outcome
	AskVisible(ctx context.Context, prompt string) (string, error)
	NewPassphrase(ctx context.Context, title string, minBytes int, differentFrom []byte) ([]byte, bool, error)
	Notify(line string)
}

// serviceManager runs the local_server mode's `envbank serve`.
type serviceManager interface {
	Healthy(url string) bool
	Install(layout setup.Layout) error
}

// setupRefusal carries a fixed code back to the agent.
type setupRefusal struct{ code string }

func (r setupRefusal) Error() string        { return r.code }
func (r setupRefusal) SetupRefusal() string { return r.code }

const minPassphrase = 12

// setupApplier implements agentbroker.Setup.
type setupApplier struct {
	// allowExistingServer is the owner's own broker flag (--use-existing-server);
	// an agent request cannot choose to reuse whatever answers on the port.
	allowExistingServer bool
	created             *brokerVault
	owner               setupOwner
	inspector           setup.Inspector
	service             serviceManager
	now                 func() time.Time
}

func (a *setupApplier) Apply(ctx context.Context, raw json.RawMessage) (agentbroker.Vault, []string, error) {
	var req setup.Request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return nil, nil, setupRefusal{"INVALID_SETUP_REQUEST"}
	}
	// Re-plan here: never trust a plan object from the agent.
	plan, err := setup.PlanFor(req, a.inspector)
	if err != nil {
		var r setup.Refusal
		if errors.As(err, &r) {
			a.owner.Notify("setup refused: " + r.Reason)
		}
		return nil, nil, setupRefusal{"SETUP_PLAN_REFUSED"}
	}
	if plan.Layout.Sync != setup.SyncLocalServer && plan.Layout.Sync != setup.SyncHosted {
		return nil, nil, setupRefusal{"SETUP_MODE_UNAVAILABLE"}
	}
	lines := []string{"An agent asked to set up EnvBank on this device:", "sync: " + plan.Layout.Sync + "  server: " + plan.Layout.ServerURL,
		"device identity: " + plan.Layout.ConfigPath}
	if plan.Layout.VaultDir != "" {
		lines = append(lines, "vault data: "+plan.Layout.VaultDir+" (volume "+plan.Layout.VaultVolumeUUID+")")
	}
	lines = append(lines, "recovery backups: "+plan.Layout.BackupDir+" (volume "+plan.Layout.BackupVolumeUUID+")", "steps:")
	for i, s := range plan.Steps {
		tag := ""
		if s.Persistent {
			tag = "  [persistent]"
		}
		if s.OwnerSecret {
			tag = "  [you will type a secret here]"
		}
		lines = append(lines, fmt.Sprintf("  %d. %s%s", i+1, s.Description, tag))
	}
	for _, w := range plan.Warnings {
		lines = append(lines, "WARNING: "+w)
	}
	who, label := "an agent", ""
	if c, ok := agentbroker.CallerFrom(ctx); ok {
		who, label = c.Who, c.Label
	}
	where := plan.Layout.VaultDir
	if where == "" {
		where = plan.Layout.ServerURL
	}
	// The plan's terms come first, the session label last. A plan too long
	// for the prompt is shown clipped; the terminal shows it in full.
	terms := fmt.Sprintf("apply an EnvBank %s setup for %s: vault %s, identity %s, backups %s (%d steps; full plan in the broker terminal)",
		plan.Layout.Sync, who, where, plan.Layout.ConfigPath, plan.Layout.BackupDir, len(plan.Steps))
	reason, fits := approval.WithLabel(approval.Clean(terms, 1<<12), label)
	if !fits {
		reason = approval.Reason("%s", terms)
	}
	if out := a.owner.Confirm(ctx, "EnvBank setup request", lines, reason); out != approval.Approved || ctx.Err() != nil {
		if out == approval.Unavailable {
			return nil, nil, setupRefusal{agentbroker.CodeApprovalUnavailable}
		}
		if out == approval.EnrollmentChanged {
			return nil, nil, setupRefusal{agentbroker.CodeEnrollmentChanged}
		}
		return nil, nil, setupRefusal{CodeDeniedSetup}
	}
	l := plan.Layout
	var done []string
	recheck := func(dir, uuid string) error {
		if dir == "" {
			return nil
		}
		if _, err := os.Lstat(dir); err == nil {
			if setup.OnVolume(dir, uuid, a.inspector) != nil {
				return setupRefusal{"SETUP_VOLUME_CHANGED"}
			}
			return nil
		}
		if setup.Recheck(dir, uuid, a.inspector, false) != nil {
			return setupRefusal{"SETUP_VOLUME_CHANGED"}
		}
		return nil
	}
	mkdir := func(dir, uuid string) error {
		if err := recheck(dir, uuid); err != nil {
			return err
		}
		if setup.MkdirPrivate(dir) != nil {
			return setupRefusal{"SETUP_DIR_FAILED"}
		}
		if setup.OnVolume(dir, uuid, a.inspector) != nil {
			return setupRefusal{"SETUP_VOLUME_CHANGED"}
		}
		return nil
	}
	step := func(id string, fn func() error) error {
		if err := fn(); err != nil {
			a.owner.Notify("setup step failed: " + id)
			return err
		}
		done = append(done, id)
		a.owner.Notify("done: " + id)
		return nil
	}
	var access *client.AccessCredentials
	defer func() {
		if access != nil {
			access.ClientSecret = ""
		}
	}()
	if l.Access {
		if err := step("access_credentials", func() error {
			id, err := a.owner.AskVisible(ctx, "Cloudflare Access client ID (ends in .access): ")
			if err != nil || !accessClientIDRe.MatchString(id) {
				return setupRefusal{"SETUP_ACCESS_INVALID"}
			}
			secret, ok, err := a.owner.NewPassphrase(ctx, "Cloudflare Access client secret", 16, nil)
			if err != nil || !ok {
				return setupRefusal{CodeDeniedSetup}
			}
			access = &client.AccessCredentials{ClientID: id, ClientSecret: string(secret)}
			wipeBytes(secret)
			return nil
		}); err != nil {
			return nil, done, err
		}
	}
	if l.Sync == setup.SyncLocalServer {
		if err := step("prepare_vault_dir", func() error { return mkdir(l.VaultDir, l.VaultVolumeUUID) }); err != nil {
			return nil, done, err
		}
		if err := step("install_service", func() error {
			if a.service.Healthy(l.ServerURL) {
				// Something already answers: it could be anything (an agent can run a
				// fake server). Reuse only when the owner started the broker with
				// --use-existing-server, and confirm again.
				if !a.allowExistingServer {
					a.owner.Notify("refused: something already answers at " + l.ServerURL + " (restart the broker with --use-existing-server to reuse a server you started)")
					return setupRefusal{"SETUP_PORT_IN_USE"}
				}
				out := a.owner.Confirm(ctx, "Reuse running EnvBank server", []string{"A server already answers at " + l.ServerURL + ".", "Reuse it only if YOU started it. The vault will be stored wherever that server keeps its database, not necessarily in the vault directory above."},
					approval.Reason("reuse the EnvBank server already running at %s (only if you started it)", l.ServerURL))
				if out == approval.Unavailable {
					return setupRefusal{agentbroker.CodeApprovalUnavailable}
				}
				if out != approval.Approved {
					return setupRefusal{CodeDeniedSetup}
				}
				return nil
			}
			if err := a.service.Install(l); err != nil {
				return setupRefusal{"SETUP_SERVICE_FAILED"}
			}
			deadline := a.now().Add(20 * time.Second)
			for !a.service.Healthy(l.ServerURL) {
				if a.now().After(deadline) {
					return setupRefusal{"SETUP_SERVICE_UNHEALTHY"}
				}
				time.Sleep(250 * time.Millisecond)
			}
			return nil
		}); err != nil {
			return nil, done, err
		}
	}
	if err := step("prepare_backup_dir", func() error { return mkdir(l.BackupDir, l.BackupVolumeUUID) }); err != nil {
		return nil, done, err
	}
	var vault *brokerVault
	var passphrase []byte
	defer func() { wipeBytes(passphrase) }()
	if err := step("create_vault", func() error {
		p, ok, err := a.owner.NewPassphrase(ctx, "New vault passphrase for "+l.VaultName, minPassphrase, nil)
		if err != nil || !ok {
			return setupRefusal{CodeDeniedSetup}
		}
		passphrase = p
		// Re-validate the identity path right before writing it.
		if setup.Recheck(l.ConfigPath, l.ConfigVolumeUUID, a.inspector, true) != nil {
			return setupRefusal{"SETUP_VOLUME_CHANGED"}
		}
		cfgDir := filepath.Dir(l.ConfigPath)
		if _, err := os.Lstat(cfgDir); err != nil {
			if mkdir(cfgDir, l.ConfigVolumeUUID) != nil {
				return setupRefusal{"SETUP_CONFIG_DIR_FAILED"}
			}
		}
		api, vaultKey, _, fingerprint, err := createVaultDevice(l.ServerURL, l.VaultName, l.DeviceName, passphrase, access, l.ConfigPath)
		if err != nil {
			return setupRefusal{"SETUP_CREATE_VAULT_FAILED"}
		}
		vault = &brokerVault{api: api, vaultKey: vaultKey}
		a.created = vault
		a.owner.Notify("device fingerprint " + fingerprint)
		return nil
	}); err != nil {
		return nil, done, err
	}
	// From here the vault exists: return it even if a later step fails, so the
	// broker can serve it and the owner can finish recovery manually.
	if err := step("recovery_export", func() error {
		rp, ok, err := a.owner.NewPassphrase(ctx, "Recovery passphrase (store it separately; it must differ from the vault passphrase)", minPassphrase, passphrase)
		if err != nil || !ok {
			return setupRefusal{"SETUP_RECOVERY_SKIPPED"}
		}
		defer wipeBytes(rp)
		if err := recheck(l.BackupDir, l.BackupVolumeUUID); err != nil {
			return err
		}
		objects, err := vault.api.ListObjects(vault.vaultKey)
		if err != nil {
			return setupRefusal{"SETUP_RECOVERY_FAILED"}
		}
		vault.mu.Lock()
		records, err := vault.records()
		vault.mu.Unlock()
		if err != nil {
			return setupRefusal{"SETUP_RECOVERY_FAILED"}
		}
		sealed, err := recovery.SealSnapshot(recovery.Snapshot{Records: records, Objects: objects}, rp)
		if err != nil {
			return setupRefusal{"SETUP_RECOVERY_FAILED"}
		}
		name := fmt.Sprintf("envbank-recovery-%s-%s.ebr", l.VaultName, a.now().UTC().Format("20060102T150405Z"))
		if err := recovery.Write(filepath.Join(l.BackupDir, name), sealed); err != nil {
			return setupRefusal{"SETUP_RECOVERY_FAILED"}
		}
		return nil
	}); err != nil {
		return vault, done, err
	}
	if err := step("write_layout", func() error {
		raw, _ := json.MarshalIndent(l, "", "  ")
		return writePrivateFile(layoutPath(l.ConfigPath), append(raw, '\n'))
	}); err != nil {
		return vault, done, setupRefusal{"SETUP_LAYOUT_FAILED"}
	}
	return vault, done, nil
}

// Cloudflare Access service-token client IDs are hex labels ending in ".access".
var accessClientIDRe = regexp.MustCompile(`^[A-Za-z0-9]{8,64}\.access$`)

// CodeDeniedSetup mirrors the broker's owner-denied code.
const CodeDeniedSetup = agentbroker.CodeDenied

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// launchdService installs `envbank serve` as a per-user launchd agent.
type launchdService struct {
	executable string
	home       string
	uid        int
}

const launchdLabel = "com.envbank.serve"

func (s launchdService) Healthy(url string) bool { return serverReachable(url) }

func (s launchdService) plistPath() string {
	return filepath.Join(s.home, "Library", "LaunchAgents", launchdLabel+".plist")
}

// Plist renders the agent definition (exported for tests via the method).
func (s launchdService) Plist(l setup.Layout) string {
	esc := func(v string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		return r.Replace(v)
	}
	args := []string{s.executable, "serve", "--listen", l.Listen, "--database", filepath.Join(l.VaultDir, "server.db")}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + launchdLabel + `</string>
<key>ProgramArguments</key><array>`)
	for _, a := range args {
		b.WriteString("<string>" + esc(a) + "</string>")
	}
	b.WriteString(`</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>` + esc(filepath.Join(l.VaultDir, "server.log")) + `</string>
<key>StandardErrorPath</key><string>` + esc(filepath.Join(l.VaultDir, "server.log")) + `</string>
</dict></plist>
`)
	return b.String()
}

func (s launchdService) Install(l setup.Layout) error {
	path := s.plistPath()
	want := s.Plist(l)
	if existing, err := os.ReadFile(path); err == nil && string(existing) != want {
		return errors.New("a different EnvBank launchd agent already exists")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target := fmt.Sprintf("gui/%d", s.uid)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", target+"/"+launchdLabel).Run()
	return exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", target, path).Run()
}
