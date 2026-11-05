//go:build darwin

// Package relay_test is a disposable end-to-end run of the cross-device relay:
// the real envbank binary, a loopback `envbank serve` on a throwaway database,
// two devices enrolled into one throwaway vault, the target's agent broker and
// the sender's `envbank relay send` driven through pseudo-terminals, and an
// agent calling `envbank agent relay-request`.
//
// It runs only when ENVBANK_E2E_RELAY=1. Every file lives in a fresh
// directory under $TMPDIR and HOME points there, so no real EnvBank config,
// vault or keychain is touched.
package relay_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/GeorgeQLe/envbank/internal/secure"
	"golang.org/x/sys/unix"
)

type harness struct {
	t    *testing.T
	dir  string
	bin  string
	url  string
	env  []string
	logs map[string]*bytes.Buffer
}

func TestCrossDeviceRelayEndToEnd(t *testing.T) {
	if os.Getenv("ENVBANK_E2E_RELAY") != "1" {
		t.Skip("set ENVBANK_E2E_RELAY=1 to run the disposable relay end-to-end test")
	}
	h := newHarness(t)
	value := "relay-e2e-" + random(t, 18)
	passA, passB := "pass-a-"+random(t, 12), "pass-b-"+random(t, 12)
	checks := 0
	check := func(ok bool, format string, args ...any) {
		t.Helper()
		if !ok {
			t.Fatalf("check failed: "+format, args...)
		}
		checks++
	}

	// Sync service and two devices in one vault.
	server := h.start("server", nil, "serve", "--listen", strings.TrimPrefix(h.url, "http://"), "--database", filepath.Join(h.dir, "server.db"))
	defer stop(server)
	h.waitHealthy()
	aConfig, bConfig := filepath.Join(h.dir, "a.json"), filepath.Join(h.dir, "b.json")
	h.run([]string{"ENVBANK_PASSPHRASE=" + passA}, "init", "--server", h.url, "--vault", "relay-e2e", "--device", "phone", "--config", aConfig)
	var a struct {
		VaultID string `json:"vault_id"`
	}
	readJSON(t, aConfig, &a)
	h.run([]string{"ENVBANK_PASSPHRASE=" + passB}, "enroll-request", "--server", h.url, "--vault-id", a.VaultID, "--device", "laptop", "--config", bConfig)
	var b struct {
		DeviceID       string `json:"device_id"`
		SigningPublic  string `json:"signing_public"`
		WrappingPublic string `json:"wrapping_public"`
	}
	readJSON(t, bConfig, &b)
	fingerprint := secure.PublicFingerprint(b.SigningPublic, b.WrappingPublic)
	h.run([]string{"ENVBANK_PASSPHRASE=" + passA}, "enroll-approve", "--fingerprint", fingerprint, "--config", aConfig, b.DeviceID)
	h.run([]string{"ENVBANK_PASSPHRASE=" + passB}, "enroll-accept", "--config", bConfig)

	// Target owner: the broker on B, unlocked by typing into its terminal.
	socket := filepath.Join(h.dir, "b.sock")
	broker := h.startPTY("broker-b", "agent-broker", "--config", bConfig, "--socket", socket)
	defer broker.close()
	broker.expect(`EnvBank passphrase \(hidden\): `)
	broker.send(passB + "\n")
	broker.expect(`Agents connect via`)

	// Agent: asks for a relayed secret; learns only the outcome.
	agent := h.start("agent", nil, "agent", "relay-request", "--name", "RELAYED_E2E", "--reason", "e2e relay check", "--socket", socket)
	broker.expect(`Which device will send it\? \[1-1, empty to deny\]: `)
	check(strings.Contains(broker.transcript(), "phone") && strings.Contains(broker.transcript(), "e2e relay check"), "broker shows sender choice and reason")
	broker.send("1\n")
	sas := broker.expect(`Relay code:  (\d{3} \d{3})`)[1]
	checks++

	// Sender owner: `envbank relay send` on A in its own terminal.
	sender := h.startPTY("sender-a", "relay", "send", "--config", aConfig)
	defer sender.close()
	sender.expect(`EnvBank passphrase \(hidden\): `)
	sender.send(passA + "\n")
	shown := sender.expect(`code:     (\d{3} \d{3})`)[1]
	check(shown == sas, "sender shows the same code as the target (%s vs %s)", shown, sas)
	check(strings.Contains(sender.transcript(), "laptop") && strings.Contains(sender.transcript(), fingerprint), "sender shows target name and fingerprint")
	sender.expect(`Does the target device show exactly this code\? \[y/N\]: `)
	sender.send("y\n")
	sender.expect(`Enter value \(hidden; empty to cancel\): `)
	sender.send(value + "\n")
	sender.expect(`Re-enter value: `)
	sender.send(value + "\n")
	sender.expect(`sent sealed to laptop`)
	check(sender.wait() == nil, "relay send exits successfully")

	// Target owner confirms storing, seeing sender and code again.
	broker.expect(`Store it as RELAYED_E2E\? \[y/N\]: `)
	check(regexp.MustCompile(`from:   phone .*\n  code:   `+sas).MatchString(broker.transcript()), "broker shows sender and code before storing")
	broker.send("y\n")
	broker.expect(`stored RELAYED_E2E \(relayed from phone\)`)
	check(agent.Wait() == nil, "agent command exits successfully")
	check(strings.TrimSpace(h.logs["agent.out"].String()) == "stored", "agent learns only 'stored' (got %q)", h.logs["agent.out"].String())

	// The value is in B's vault.
	got := h.run([]string{"ENVBANK_PASSPHRASE=" + passB}, "get", "--config", bConfig, "RELAYED_E2E")
	check(got == value, "value stored on B")

	// Second send: nothing pending (single use).
	again := h.startPTY("sender-a-again", "relay", "send", "--config", aConfig)
	again.expect(`EnvBank passphrase \(hidden\): `)
	again.send(passA + "\n")
	again.expect(`no pending relay request`)
	check(again.wait() != nil, "second send finds nothing to fill")
	again.close()

	// Ctrl-C locks the broker.
	broker.send("\x03")
	broker.expect(`EnvBank agent broker locked`)
	_ = broker.wait()
	_, err := os.Stat(socket)
	check(os.IsNotExist(err), "broker socket removed after lock")
	stop(server)

	// No plaintext anywhere outside B's vault read-back.
	leaks := map[string][]byte{
		"agent stdout":      h.logs["agent.out"].Bytes(),
		"agent stderr":      h.logs["agent.err"].Bytes(),
		"server log":        append(h.logs["server.out"].Bytes(), h.logs["server.err"].Bytes()...),
		"broker transcript": []byte(broker.transcript()),
		"sender transcript": []byte(sender.transcript()),
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, err := os.ReadFile(filepath.Join(h.dir, "server.db"+suffix))
		if err == nil {
			leaks["server database"+suffix] = raw
		}
	}
	for where, raw := range leaks {
		for _, secret := range []string{value, base64.StdEncoding.EncodeToString([]byte(value)), passA, passB} {
			check(!bytes.Contains(raw, []byte(secret)), "no value or passphrase in %s", where)
		}
	}
	check(!bytes.Contains(leaks["server database"], []byte("RELAYED_E2E")), "secret name not in server database")
	t.Logf("relay end-to-end: %d checks passed", checks)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// A short path keeps the Unix socket under the platform's path limit.
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "envbank")
	build := exec.Command("go", "build", "-o", bin, "./cmd/envbank")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, dir: dir, bin: bin, url: "http://" + addr, logs: map[string]*bytes.Buffer{},
		env: []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "TMPDIR=" + dir,
			"PATH=/usr/bin:/bin", "LANG=C", "TERM=xterm"}}
}

func repoRoot(t *testing.T) string {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

func (h *harness) command(extraEnv []string, args ...string) *exec.Cmd {
	cmd := exec.Command(h.bin, args...)
	cmd.Dir = h.dir
	cmd.Env = append(append([]string(nil), h.env...), extraEnv...)
	return cmd
}

func (h *harness) run(extraEnv []string, args ...string) string {
	h.t.Helper()
	cmd := h.command(extraEnv, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("envbank %s: %v\n%s", args[0], err, stderr.String())
	}
	return stdout.String()
}

func (h *harness) start(name string, extraEnv []string, args ...string) *exec.Cmd {
	h.t.Helper()
	cmd := h.command(extraEnv, args...)
	out, errOut := &lockedBuffer{}, &lockedBuffer{}
	h.logs[name+".out"], h.logs[name+".err"] = &out.Buffer, &errOut.Buffer
	cmd.Stdout, cmd.Stderr = out, errOut
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	return cmd
}

func (h *harness) waitHealthy() {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if res, err := http.Get(h.url + "/healthz"); err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatal("server did not become healthy")
}

func stop(cmd *exec.Cmd) {
	if cmd.Process != nil && cmd.ProcessState == nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

// ptyProc is a child whose controlling terminal is a pseudo-terminal the test
// drives as the owner.
type ptyProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File
	mu     sync.Mutex
	buf    bytes.Buffer
	offset int
	done   chan error
}

func (h *harness) startPTY(name string, args ...string) *ptyProc {
	h.t.Helper()
	master, slave := openPTY(h.t)
	cmd := h.command(nil, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	slave.Close()
	p := &ptyProc{t: h.t, cmd: cmd, master: master, done: make(chan error, 1)}
	go func() {
		chunk := make([]byte, 4096)
		for {
			n, err := master.Read(chunk)
			p.mu.Lock()
			p.buf.Write(chunk[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() { p.done <- cmd.Wait() }()
	return p
}

func (p *ptyProc) transcript() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

func (p *ptyProc) send(s string) {
	if _, err := p.master.Write([]byte(s)); err != nil {
		p.t.Fatal(err)
	}
}

// expect waits for pattern after the last match and returns its submatches.
func (p *ptyProc) expect(pattern string) []string {
	p.t.Helper()
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		text := p.buf.String()[p.offset:]
		if loc := re.FindStringSubmatchIndex(text); loc != nil {
			match := re.FindStringSubmatch(text)
			p.offset += loc[1]
			p.mu.Unlock()
			return match
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("timed out waiting for %q", pattern)
	return nil
}

func (p *ptyProc) wait() error {
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(20 * time.Second):
		p.t.Fatal("process did not exit")
		return nil
	}
}

func (p *ptyProc) close() {
	if p.cmd.ProcessState == nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.master.Close()
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd := master.Fd()
	for _, req := range []uintptr{unix.TIOCPTYGRANT, unix.TIOCPTYUNLK} {
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, 0); errno != 0 {
			t.Fatal(errno)
		}
	}
	var name [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		t.Fatal(errno)
	}
	path := string(name[:bytes.IndexByte(name[:], 0)])
	slave, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return master, slave
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func random(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
