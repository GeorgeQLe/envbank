package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/setup"
)

type fakeSetupOwner struct {
	confirm  bool
	prompted int
	notes    []string
}

func (o *fakeSetupOwner) ConfirmPlan(context.Context, string, []string) (bool, error) {
	o.prompted++
	return o.confirm, nil
}
func (o *fakeSetupOwner) NewPassphrase(context.Context, string, int, []byte) ([]byte, bool, error) {
	return nil, false, errors.New("must not be reached")
}
func (o *fakeSetupOwner) Notify(l string) { o.notes = append(o.notes, l) }

type swapInspector struct {
	calls int
	vols  map[string]setup.Volume
}

func (s *swapInspector) VolumeOf(path string) (setup.Volume, error) {
	s.calls++
	best := ""
	for p := range s.vols {
		if strings.HasPrefix(path+"/", p+"/") && len(p) > len(best) {
			best = p
		}
	}
	v := s.vols[best]
	if s.calls > 3 && strings.Contains(best, "t9") { // the drive is swapped after planning
		v.UUID = "OTHER"
	}
	return v, nil
}

type fakeService struct{ installed int }

func (s *fakeService) Healthy(string) bool        { return false }
func (s *fakeService) Install(setup.Layout) error { s.installed++; return nil }

func setupFixture(t *testing.T) (setup.Request, map[string]setup.Volume) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	for _, d := range []string{"internal", "t9", "backup"} {
		_ = os.Mkdir(filepath.Join(root, d), 0o700)
	}
	vols := map[string]setup.Volume{
		"/":                             {UUID: "R", OwnersEnabled: true, Internal: true, Writable: true},
		filepath.Join(root, "internal"): {UUID: "INT", OwnersEnabled: true, Internal: true, Writable: true},
		filepath.Join(root, "t9"):       {UUID: "T9", OwnersEnabled: true, Writable: true},
		filepath.Join(root, "backup"):   {UUID: "BAK", OwnersEnabled: true, Writable: true},
	}
	return setup.Request{Sync: setup.SyncLocalServer, VaultName: "v", DeviceName: "d", ConfigPath: filepath.Join(root, "internal", "device.json"),
		VaultDir: filepath.Join(root, "t9", "vault"), BackupDir: filepath.Join(root, "backup", "rec")}, vols
}

func TestSetupApplyDeniedOrSwappedVolumeChangesNothing(t *testing.T) {
	req, vols := setupFixture(t)
	raw, _ := json.Marshal(req)
	owner := &fakeSetupOwner{confirm: false}
	svc := &fakeService{}
	a := &setupApplier{owner: owner, inspector: &swapInspector{vols: vols}, service: svc, now: time.Now}
	if v, done, err := a.Apply(context.Background(), raw); err == nil || v != nil || len(done) != 0 || owner.prompted != 1 {
		t.Fatalf("denied plan applied: %v %v %v", v, done, err)
	}
	if _, err := os.Stat(req.VaultDir); err == nil || svc.installed != 0 {
		t.Fatal("a denied plan touched the filesystem or installed a service")
	}
	owner.confirm = true
	a.inspector = &swapInspector{vols: vols}
	_, done, err := a.Apply(context.Background(), raw)
	var r setupRefusal
	if !errors.As(err, &r) || r.code != "SETUP_VOLUME_CHANGED" || len(done) != 0 || svc.installed != 0 {
		t.Fatalf("volume swap not caught before acting: %v %v", done, err)
	}
	if _, _, err := a.Apply(context.Background(), json.RawMessage(`{"sync":"local_server","extra":1}`)); err == nil {
		t.Fatal("unknown setup field accepted")
	}
}

func TestLaunchdPlistIsLoopbackAndEscaped(t *testing.T) {
	s := launchdService{executable: "/Users/x/bin/envbank", home: "/Users/x", uid: 501}
	p := s.Plist(setup.Layout{Listen: "127.0.0.1:7337", VaultDir: "/Volumes/T9/a&b<c>"})
	for _, want := range []string{"<string>serve</string>", "<string>127.0.0.1:7337</string>", "a&amp;b&lt;c&gt;/server.db", "<key>RunAtLoad</key><true/>"} {
		if !strings.Contains(p, want) {
			t.Fatalf("plist missing %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "a&b<c>") {
		t.Fatal("unescaped path in plist")
	}
}

func TestBrokerSetupModeGatesOperations(t *testing.T) {
	b, err := agentbroker.New(agentbroker.Options{Setup: &setupApplier{}, Prompter: &noopPrompter{}, Runner: agentbroker.ExecRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{agentbroker.OpNames, agentbroker.OpRequest, agentbroker.OpRun} {
		if r := b.Handle(context.Background(), agentbroker.Request{V: 1, Op: op, Name: "X", Reason: "r"}); r.OK || (r.Code != agentbroker.CodeNotSetUp && r.Code != agentbroker.CodeInvalidRequest) {
			t.Fatalf("%s in setup mode: %+v", op, r)
		}
	}
	if r := b.Handle(context.Background(), agentbroker.Request{V: 1, Op: agentbroker.OpSetup, Name: "x", Setup: json.RawMessage(`{}`)}); r.OK || r.Code != agentbroker.CodeInvalidRequest {
		t.Fatalf("setup with extra fields: %+v", r)
	}
}

type noopPrompter struct{}

func (noopPrompter) ApproveRun(context.Context, agentbroker.Command) (agentbroker.Decision, error) {
	return agentbroker.Deny, nil
}
func (noopPrompter) ReadSecret(context.Context, agentbroker.Ingest) ([]byte, bool, error) {
	return nil, false, nil
}
func (noopPrompter) Notify(string) {}
