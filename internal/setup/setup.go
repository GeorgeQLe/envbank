// Package setup plans and validates agent-operated EnvBank installation.
//
// Agents may inspect status, propose a layout and ask for it to be applied.
// Every owner secret (vault passphrase, recovery passphrase) and every
// persistent system change (a background service) is collected or confirmed
// on an owner-held surface (the agent broker's terminal today; a desktop host
// provider later), never through the agent.
//
// Storage layout ("split"): vault ciphertext in a dedicated directory on an
// ownership-enforcing volume, bound to that volume's UUID; the device identity
// (passphrase-encrypted config) on an internal, non-removable volume; recovery
// exports on a separate backup volume.
package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Sync modes.
const (
	SyncLocalServer = "local_server" // `envbank serve` on loopback as an owner-approved service
	SyncHosted      = "hosted"       // the EnvBank Cloudflare service
	SyncLocalOnly   = "local_only"   // one host, no sync (desktop-host local vault mode)
)

// LayoutVersion versions the non-secret layout manifest.
const LayoutVersion = "envbank.layout/v1"

// Layout is non-secret and safe for agents to read and propose.
type Layout struct {
	V                string `json:"v"`
	Sync             string `json:"sync"`
	ServerURL        string `json:"server_url"`
	Listen           string `json:"listen,omitempty"`
	VaultName        string `json:"vault_name"`
	DeviceName       string `json:"device_name"`
	ConfigPath       string `json:"config_path"`
	ConfigVolumeUUID string `json:"config_volume_uuid"`
	VaultDir         string `json:"vault_dir,omitempty"`
	VaultVolumeUUID  string `json:"vault_volume_uuid,omitempty"`
	BackupDir        string `json:"backup_dir"`
	BackupVolumeUUID string `json:"backup_volume_uuid"`
}

// Step is one plan step. OwnerSecret / Persistent steps always involve the owner.
type Step struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	OwnerSecret bool   `json:"owner_secret,omitempty"`
	Persistent  bool   `json:"persistent,omitempty"`
	Done        bool   `json:"done,omitempty"`
}

// Plan is a validated layout plus the steps needed to reach it.
type Plan struct {
	Layout   Layout   `json:"layout"`
	Steps    []Step   `json:"steps"`
	Warnings []string `json:"warnings,omitempty"`
}

// Volume describes the filesystem holding a path.
type Volume struct {
	UUID          string
	Name          string
	MountPoint    string
	OwnersEnabled bool
	Internal      bool
	Writable      bool
}

// Inspector reports volume facts (darwin: statfs + diskutil; tests inject fakes).
type Inspector interface {
	VolumeOf(path string) (Volume, error)
}

// Refusal is a fixed, caller-safe reason.
type Refusal struct{ Reason string }

func (r Refusal) Error() string { return r.Reason }

func refuse(reason string) error { return Refusal{reason} }

// Request is what an agent proposes.
type Request struct {
	Sync       string `json:"sync"`
	ServerURL  string `json:"server_url,omitempty"`
	Listen     string `json:"listen,omitempty"`
	VaultName  string `json:"vault_name"`
	DeviceName string `json:"device_name"`
	ConfigPath string `json:"config_path"`
	VaultDir   string `json:"vault_dir,omitempty"`
	BackupDir  string `json:"backup_dir"`
}

// DefaultListen is the loopback address of the local-server mode.
const DefaultListen = "127.0.0.1:7337"

// PlanFor validates a request against real volume facts and returns a plan.
// It changes nothing.
func PlanFor(req Request, inspect Inspector) (Plan, error) {
	if !validLabel(req.VaultName) || !validLabel(req.DeviceName) {
		return Plan{}, refuse("vault_name and device_name must be 1-64 letters, digits, '-', '_' or '.'")
	}
	p := Plan{Layout: Layout{V: LayoutVersion, Sync: req.Sync, VaultName: req.VaultName, DeviceName: req.DeviceName}}
	switch req.Sync {
	case SyncLocalServer:
		listen := req.Listen
		if listen == "" {
			listen = DefaultListen
		}
		if !loopbackListen(listen) {
			return Plan{}, refuse("local_server mode listens on loopback only (127.0.0.1:PORT)")
		}
		if req.ServerURL != "" && req.ServerURL != "http://"+listen {
			return Plan{}, refuse("local_server mode serves on its listen address; omit server_url")
		}
		p.Layout.Listen = listen
		p.Layout.ServerURL = "http://" + listen
	case SyncHosted:
		if !strings.HasPrefix(req.ServerURL, "https://") || strings.ContainsAny(req.ServerURL, " \t\n") {
			return Plan{}, refuse("hosted mode requires the https:// URL of your EnvBank service")
		}
		p.Layout.ServerURL = strings.TrimRight(req.ServerURL, "/")
		if req.VaultDir != "" {
			return Plan{}, refuse("hosted mode keeps vault ciphertext on the service; vault_dir is not used")
		}
	case SyncLocalOnly:
		return Plan{}, refuse("local_only mode is not available yet (it needs the desktop-host local vault adapter)")
	default:
		return Plan{}, refuse("sync must be local_server, hosted or local_only")
	}

	// Device identity: internal, non-removable, ownership-enforcing volume.
	cfg, cfgVol, err := checkedPath(req.ConfigPath, inspect, true)
	if err != nil {
		return Plan{}, err
	}
	if !cfgVol.Internal {
		return Plan{}, refuse("config_path (device identity) must be on an internal volume")
	}
	p.Layout.ConfigPath, p.Layout.ConfigVolumeUUID = cfg, cfgVol.UUID

	if req.Sync == SyncLocalServer {
		dir, vol, err := checkedPath(req.VaultDir, inspect, false)
		if err != nil {
			return Plan{}, err
		}
		if vol.UUID == cfgVol.UUID {
			p.Warnings = append(p.Warnings, "vault_dir is on the same volume as the device identity; the split layout keeps them apart")
		}
		p.Layout.VaultDir, p.Layout.VaultVolumeUUID = dir, vol.UUID
	}

	backup, bvol, err := checkedPath(req.BackupDir, inspect, false)
	if err != nil {
		return Plan{}, err
	}
	if p.Layout.VaultVolumeUUID != "" && bvol.UUID == p.Layout.VaultVolumeUUID {
		return Plan{}, refuse("backup_dir must be on a different volume than vault_dir")
	}
	if bvol.UUID == cfgVol.UUID {
		p.Warnings = append(p.Warnings, "backup_dir is on the same volume as the device identity; the split layout keeps them apart")
	}
	p.Layout.BackupDir, p.Layout.BackupVolumeUUID = backup, bvol.UUID

	p.Steps = stepsFor(p.Layout)
	return p, nil
}

func stepsFor(l Layout) []Step {
	var steps []Step
	if l.Sync == SyncLocalServer {
		steps = append(steps,
			Step{ID: "prepare_vault_dir", Description: "create the private (0700) vault directory " + l.VaultDir},
			Step{ID: "install_service", Description: "install and start a launchd user agent running `envbank serve` on " + l.Listen + " with its database in the vault directory (skipped if an EnvBank server already answers there)", Persistent: true},
		)
	}
	steps = append(steps,
		Step{ID: "prepare_backup_dir", Description: "create the private (0700) backup directory " + l.BackupDir},
		Step{ID: "create_vault", Description: "create vault " + l.VaultName + " and this device's identity at " + l.ConfigPath, OwnerSecret: true},
		Step{ID: "recovery_export", Description: "write a recovery artifact sealed with a separate recovery passphrase to " + l.BackupDir, OwnerSecret: true},
		Step{ID: "write_layout", Description: "record this non-secret layout next to the device identity"},
	)
	return steps
}

// checkedPath requires an absolute, normalized path whose existing components
// are not symlinks, on a writable volume that enforces ownership. A path that
// exists must be private (0700 directory, or for a file target its parent).
// fileTarget: the path names a file that must not exist yet.
func checkedPath(path string, inspect Inspector, fileTarget bool) (string, Volume, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\n\r") {
		return "", Volume{}, refuse("paths must be absolute and normalized")
	}
	// Every existing component, from the root, must be a real directory (no symlinks).
	existing := path
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", Volume{}, refuse("no existing parent directory")
		}
		existing = parent
	}
	if err := noSymlinks(existing); err != nil {
		return "", Volume{}, err
	}
	vol, err := inspect.VolumeOf(existing)
	if err != nil {
		return "", Volume{}, refuse("volume could not be inspected")
	}
	if !vol.OwnersEnabled {
		return "", Volume{}, refuse("volume " + vol.Name + " does not enforce file ownership")
	}
	if !vol.Writable || vol.UUID == "" {
		return "", Volume{}, refuse("volume " + vol.Name + " is not writable or has no UUID")
	}
	if existing != path {
		// The nearest existing ancestor must not let anyone else swap in a path.
		info, err := os.Lstat(existing)
		if err != nil || !info.IsDir() || !ancestorSafe(info) {
			return "", Volume{}, refuse("the nearest existing parent directory must not be writable by others")
		}
	}
	if existing == path {
		info, err := os.Lstat(path)
		if err != nil {
			return "", Volume{}, refuse("path could not be inspected")
		}
		if fileTarget {
			return "", Volume{}, refuse("config_path already exists: this device is already set up")
		}
		if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
			return "", Volume{}, refuse("existing directory must be a private (0700) directory owned by you")
		}
	}
	return path, vol, nil
}

// ancestorSafe: never world-writable; group-writable only for group wheel (gid
// 0, which holds only root by default), as volume roots often are.
func ancestorSafe(info os.FileInfo) bool {
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return false
	}
	return perm&0o020 == 0 || groupID(info) == 0
}

func noSymlinks(path string) error {
	cur := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return refuse("path could not be inspected")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return refuse("paths must not pass through symlinks")
		}
	}
	return nil
}

func loopbackListen(s string) bool {
	if !strings.HasPrefix(s, "127.0.0.1:") {
		return false
	}
	port := strings.TrimPrefix(s, "127.0.0.1:")
	if port == "" || len(port) > 5 {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1024 && n <= 65535
}

func validLabel(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// Recheck re-validates a planned path immediately before it is written: same
// rules as planning, and the same volume UUID as recorded in the plan.
func Recheck(path, wantUUID string, inspect Inspector, fileTarget bool) error {
	_, vol, err := checkedPath(path, inspect, fileTarget)
	if err != nil {
		return err
	}
	if vol.UUID != wantUUID {
		return refuse("the volume changed since the plan was approved")
	}
	return nil
}

// OnVolume verifies that an existing directory is on the expected volume.
func OnVolume(dir, wantUUID string, inspect Inspector) error {
	vol, err := inspect.VolumeOf(dir)
	if err != nil || vol.UUID != wantUUID || !vol.OwnersEnabled {
		return refuse("the created directory is not on the approved volume")
	}
	return nil
}

// MkdirPrivate creates dir (and missing parents) with 0700 and re-checks it.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByMe(info) {
		return errors.New("directory is not a private directory owned by this user")
	}
	return noSymlinks(dir)
}
