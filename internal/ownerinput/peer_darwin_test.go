//go:build darwin && cgo

package ownerinput

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// acceptFrom listens, runs `bin agent names --socket sock` as the connecting
// peer, and returns the server-side verdict for that peer under requirement.
func acceptFrom(t *testing.T, bin, requirement string) (Identity, error) {
	t.Helper()
	dir, err := os.MkdirTemp("", "oi")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd := exec.Command(bin, "agent", "names", "--socket", sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = l.(*net.UnixListener).SetDeadline(time.Now().Add(15 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return peerIdentity(c.(*net.UnixConn), requirement)
}

func TestPeerSignatureIsVerifiedAgainstRealProcesses(t *testing.T) {
	signed := os.Getenv("ENVBANK_SIGNED_BINARY")
	if signed == "" {
		t.Skip("set ENVBANK_SIGNED_BINARY to a Developer ID signed envbank to run")
	}
	team, ident := os.Getenv("ENVBANK_SIGNED_TEAM"), "com.georgeqle.envbank"
	p := Provider{TeamID: team, Identifier: ident}
	req, err := p.Requirement()
	if err != nil {
		t.Fatal(err)
	}
	id, err := acceptFrom(t, signed, req)
	if err != nil || id.TeamID != team || id.Identifier != ident || len(id.CDHash) != 40 || !id.HardenedRuntime {
		t.Fatalf("signed peer: %+v %v", id, err)
	}
	wrong := Provider{TeamID: "AAAAAAAAAA", Identifier: ident}
	wreq, _ := wrong.Requirement()
	if _, err := acceptFrom(t, signed, wreq); err == nil {
		t.Fatal("wrong team accepted")
	}
	otherID := Provider{TeamID: team, Identifier: "com.example.impostor"}
	oreq, _ := otherID.Requirement()
	if _, err := acceptFrom(t, signed, oreq); err == nil {
		t.Fatal("wrong identifier accepted")
	}
	unsigned := os.Getenv("ENVBANK_UNSIGNED_BINARY")
	if unsigned != "" {
		if _, err := acceptFrom(t, unsigned, req); err == nil {
			t.Fatal("unsigned peer accepted")
		}
	}
}
