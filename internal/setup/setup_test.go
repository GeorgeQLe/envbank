package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeInspector maps path prefixes to volumes.
type fakeInspector map[string]Volume

func (f fakeInspector) VolumeOf(path string) (Volume, error) {
	best := ""
	for prefix := range f {
		if strings.HasPrefix(path+"/", prefix+"/") && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return Volume{}, errors.New("unknown")
	}
	return f[best], nil
}

func layoutDirs(t *testing.T) (internal, t9, backup string) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	for _, d := range []string{"internal", "t9", "backup"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "internal"), filepath.Join(root, "t9"), filepath.Join(root, "backup")
}

func inspectorFor(internal, t9, backup string) fakeInspector {
	return fakeInspector{
		"/":      {UUID: "ROOT", Name: "root", OwnersEnabled: true, Internal: true, Writable: true},
		internal: {UUID: "INT", Name: "Macintosh HD - Data", OwnersEnabled: true, Internal: true, Writable: true},
		t9:       {UUID: "T9DEV", Name: "T9-Developer", OwnersEnabled: true, Writable: true},
		backup:   {UUID: "T9BAK", Name: "T9-Backup", OwnersEnabled: true, Writable: true},
	}
}

func TestSplitLayoutPlanBindsVolumesAndNeedsOwnerForSecrets(t *testing.T) {
	internal, t9, backup := layoutDirs(t)
	req := Request{Sync: SyncLocalServer, VaultName: "personal", DeviceName: "macbook-air",
		ConfigPath: filepath.Join(internal, "envbank", "device.json"), VaultDir: filepath.Join(t9, "envbank-vault"), BackupDir: filepath.Join(backup, "envbank-recovery")}
	p, err := PlanFor(req, inspectorFor(internal, t9, backup))
	if err != nil {
		t.Fatal(err)
	}
	if p.Layout.VaultVolumeUUID != "T9DEV" || p.Layout.BackupVolumeUUID != "T9BAK" || p.Layout.ServerURL != "http://127.0.0.1:7337" {
		t.Fatalf("layout %+v", p.Layout)
	}
	owner := map[string]bool{}
	for _, s := range p.Steps {
		if s.OwnerSecret || s.Persistent {
			owner[s.ID] = true
		}
	}
	for _, id := range []string{"install_service", "create_vault", "recovery_export"} {
		if !owner[id] {
			t.Fatalf("%s must involve the owner", id)
		}
	}
}

func TestPlanRefusesUnsafeLayouts(t *testing.T) {
	internal, t9, backup := layoutDirs(t)
	base := Request{Sync: SyncLocalServer, VaultName: "v", DeviceName: "d", ConfigPath: filepath.Join(internal, "device.json"), VaultDir: filepath.Join(t9, "vault"), BackupDir: filepath.Join(backup, "rec")}
	ins := inspectorFor(internal, t9, backup)
	link := filepath.Join(filepath.Dir(t9), "link")
	_ = os.Symlink(t9, link)
	open := filepath.Join(t9, "open")
	_ = os.Mkdir(open, 0o700)
	_ = os.Chmod(open, 0o755)
	existing := filepath.Join(internal, "exists.json")
	_ = os.WriteFile(existing, []byte("{}"), 0o600)
	noOwners := fakeInspector{}
	for k, v := range ins {
		noOwners[k] = v
	}
	v := noOwners[t9]
	v.OwnersEnabled = false
	noOwners[t9] = v
	for name, c := range map[string]struct {
		mutate func(*Request)
		ins    Inspector
	}{
		"relative":             {func(r *Request) { r.VaultDir = "vault" }, ins},
		"unclean":              {func(r *Request) { r.VaultDir = t9 + "/x/../vault" }, ins},
		"symlink":              {func(r *Request) { r.VaultDir = filepath.Join(link, "vault") }, ins},
		"non-private":          {func(r *Request) { r.VaultDir = open }, ins},
		"owners-disabled":      {func(r *Request) {}, noOwners},
		"identity-on-T9":       {func(r *Request) { r.ConfigPath = filepath.Join(t9, "device.json") }, ins},
		"already-set-up":       {func(r *Request) { r.ConfigPath = existing }, ins},
		"backup-same-as-vault": {func(r *Request) { r.BackupDir = filepath.Join(t9, "rec") }, ins},
		"bad-mode":             {func(r *Request) { r.Sync = "cloud" }, ins},
		"local-only-not-yet":   {func(r *Request) { r.Sync = SyncLocalOnly }, ins},
		"hosted-needs-https":   {func(r *Request) { r.Sync, r.VaultDir, r.ServerURL = SyncHosted, "", "http://x" }, ins},
		"local-other-port":     {func(r *Request) { r.ServerURL = "http://0.0.0.0:7337" }, ins},
		"bad-label":            {func(r *Request) { r.VaultName = "a b" }, ins},
	} {
		r := base
		c.mutate(&r)
		if _, err := PlanFor(r, c.ins); err == nil {
			t.Fatalf("%s: accepted", name)
		} else if _, ok := err.(Refusal); !ok {
			t.Fatalf("%s: non-fixed error %v", name, err)
		}
	}
	hosted := base
	hosted.Sync, hosted.VaultDir, hosted.ServerURL = SyncHosted, "", "https://envbank.example.workers.dev/"
	p, err := PlanFor(hosted, ins)
	if err != nil || p.Layout.ServerURL != "https://envbank.example.workers.dev" || p.Steps[0].ID == "install_service" {
		t.Fatalf("hosted plan %+v %v", p, err)
	}
}

func TestMkdirPrivate(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	d := filepath.Join(root, "a", "b")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(d); info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", info.Mode())
	}
}
