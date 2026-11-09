package protectedfill

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The probe observes the single durable latch; it never creates, clears or
// locks state, so it cannot open a gate or start a second authority.
func TestProbeReadsTheSameLatchWithoutMutatingIt(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "never-created")
	if ProbeGate(missing) != GateUnknown {
		t.Fatal("missing directory accepted")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("probe created state")
	}
	g, _, c := setup(t)
	dir := filepath.Dir(g.latch)
	if ProbeGate(dir) != GateReady {
		t.Fatal("initialized gate not ready")
	}
	d := c.Driver.(*testDriver)
	d.fill = func(context.Context, Target, []byte) (bool, error) {
		if ProbeGate(dir) != GateBlocked {
			t.Fatal("probe missed the active phase")
		}
		return true, nil
	}
	if c.Run(context.Background(), target(), func() ([]byte, error) { return []byte("synthetic"), nil }).Status != "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED" {
		t.Fatal("operation failed")
	}
	if ProbeGate(dir) != GateReady || g.Blocked() {
		t.Fatal("probe changed authority state")
	}
	if err := os.Mkdir(filepath.Join(dir, gateLatchName), 0700); err != nil {
		t.Fatal(err)
	}
	if ProbeGate(dir) != GateBlocked {
		t.Fatal("non-file latch entry not treated as blocked")
	}
	if second, err := OpenGate(dir); err == nil {
		second.Close()
		t.Fatal("probe released the authority lock")
	}
}
