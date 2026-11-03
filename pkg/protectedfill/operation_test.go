package protectedfill

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testDriver struct {
	gate               *Gate
	validate           func(context.Context, Target) error
	fill               func(context.Context, Target, []byte) (bool, error)
	destroyErr         error
	destroyPanic       bool
	orphanErr          error
	destroyed, orphans bool
}

func (d *testDriver) Validate(ctx context.Context, t Target) error {
	if d.validate != nil {
		return d.validate(ctx, t)
	}
	return nil
}
func (d *testDriver) FillAndSubmit(ctx context.Context, t Target, v []byte) (bool, error) {
	if d.fill != nil {
		return d.fill(ctx, t, v)
	}
	return true, nil
}
func (d *testDriver) Destroy(context.Context, Target) error {
	d.destroyed = true
	if d.destroyPanic {
		panic("private driver error")
	}
	return d.destroyErr
}
func (d *testDriver) DestroyOrphans(context.Context) error { d.orphans = true; return d.orphanErr }
func target() Target {
	return Target{Record: "PASSWORD", Context: "owned_context", Document: "document_1", Field: "field_1", Submit: "submit_1", Origin: "https://example.com"}
}
func setup(t *testing.T) (*Gate, *testDriver, *Coordinator) {
	t.Helper()
	g, err := OpenGate(filepath.Join(t.TempDir(), "gate"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	d := &testDriver{gate: g}
	return g, d, &Coordinator{Gate: g, Driver: d}
}

func TestGateBeforeSecretAndNoRawValueOrErrorInReceipts(t *testing.T) {
	g, d, c := setup(t)
	sentinel := []byte("UNIQUE_DISPOSABLE_PROTECTED_SENTINEL_abc123")
	read := false
	d.fill = func(ctx context.Context, _ Target, value []byte) (bool, error) {
		if !g.Blocked() || !read || !bytes.Equal(value, sentinel) {
			t.Fatal("value released outside protection")
		}
		for _, channel := range []string{"screenshot", "AX", "DOM", "clipboard", "debug", "ordinary_input", "other_tab"} {
			called := false
			got, err := g.Observe(ctx, func(context.Context) ([]byte, error) { called = true; return sentinel, nil })
			if !errors.Is(err, ErrBlocked) || got != nil || called {
				t.Fatalf("capture not blocked: %s", channel)
			}
		}
		return false, errors.New(string(sentinel))
	}
	var returned []byte
	r := c.Run(context.Background(), target(), func() ([]byte, error) {
		read = true
		if !g.Blocked() {
			t.Fatal("decrypted before gate")
		}
		returned = bytes.Clone(sentinel)
		return returned, nil
	})
	if r.Status != "FAILED_CONTEXT_CLOSED" || !d.destroyed || g.Blocked() {
		t.Fatalf("unsafe completion: %+v", r)
	}
	if !bytes.Equal(returned, make([]byte, len(returned))) {
		t.Fatal("mutable value not wiped")
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, sentinel) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(sentinel))) {
		t.Fatal("receipt leaked marker")
	}
	if value, err := g.Observe(context.Background(), func(context.Context) ([]byte, error) { return []byte("safe"), nil }); err != nil || string(value) != "safe" {
		t.Fatal("did not resume after context destruction")
	}
}

func TestLateCaptureDiscardedEvenAfterResume(t *testing.T) {
	g, _, c := setup(t)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	sentinel := []byte("late-synthetic-sentinel")
	go func() {
		_, err := g.Observe(context.Background(), func(ctx context.Context) ([]byte, error) { close(started); <-release; return sentinel, nil })
		done <- err
	}()
	<-started
	r := c.Run(context.Background(), target(), func() ([]byte, error) { return []byte("disposable"), nil })
	if r.Status != "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED" {
		t.Fatal(r)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrBlocked) {
		t.Fatal("late capture accepted")
	}
	if !bytes.Equal(sentinel, make([]byte, len(sentinel))) {
		t.Fatal("late capture bytes not erased")
	}
}

func TestFailureCrashAndRecoveryLatch(t *testing.T) {
	for _, mode := range []string{"close-failure", "close-panic", "fill-panic"} {
		t.Run(mode, func(t *testing.T) {
			g, d, c := setup(t)
			if mode == "close-failure" {
				d.destroyErr = errors.New("secret-bearing cleanup diagnostics")
			}
			if mode == "close-panic" {
				d.destroyPanic = true
			}
			if mode == "fill-panic" {
				d.fill = func(context.Context, Target, []byte) (bool, error) { panic("secret-bearing diagnostics") }
			}
			r := c.Run(context.Background(), target(), func() ([]byte, error) { return []byte("synthetic"), nil })
			if mode == "fill-panic" {
				if g.Blocked() || r.Status != "FAILED_CONTEXT_CLOSED" {
					t.Fatal("successful cleanup did not recover panic")
				}
				return
			}
			if !g.Blocked() || r.Status != "RECOVERY_REQUIRED" {
				t.Fatal("failed cleanup resumed observations")
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := OpenGate(strings.TrimSuffix(g.latch, "/blocked"))
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if !restarted.Blocked() {
				t.Fatal("restart lost protected latch")
			}
			d.orphanErr = errors.New("unknown context")
			c.Gate = restarted
			if c.Recover(context.Background()) == nil || !restarted.Blocked() {
				t.Fatal("failed recovery opened gate")
			}
			d.orphanErr = nil
			if c.Recover(context.Background()) != nil || restarted.Blocked() || !d.orphans {
				t.Fatal("verified context destruction did not recover")
			}
		})
	}
}

func TestCrashDuringOperationRetainsLatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gate")
	g, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if g.begin() != nil {
		t.Fatal("cannot start")
	}
	g.Close()
	next, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if !next.Blocked() {
		t.Fatal("crashed operation resumed")
	}
}

func TestMissingControllerAndInvalidBindingsNeverRead(t *testing.T) {
	_, _, c := setup(t)
	read := func() ([]byte, error) { t.Fatal("unexpected decryption"); return nil, nil }
	if (&Coordinator{}).Run(context.Background(), target(), read).Status != "HOST_PROTECTION_UNAVAILABLE" {
		t.Fatal("missing host accepted")
	}
	for _, mutate := range []func(*Target){func(x *Target) { x.Document = "" },
		func(x *Target) { x.Origin = "http://localhost" }, func(x *Target) { x.Origin = "https://evil.example/path" }, func(x *Target) { x.Field = "value with spaces" }} {
		x := target()
		mutate(&x)
		if c.Run(context.Background(), x, read).Status != "TARGET_REJECTED" {
			t.Fatal("bad binding accepted")
		}
	}
	d := c.Driver.(*testDriver)
	d.validate = func(context.Context, Target) error { return errors.New("unowned tab") }
	if c.Run(context.Background(), target(), read).Status != "TARGET_REJECTED" || d.destroyed || c.Gate.Blocked() {
		t.Fatal("unowned tab destroyed or secret read")
	}
}

func TestRecoveryAndParallelOperationCannotResumeActiveFill(t *testing.T) {
	g, d, c := setup(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan Receipt, 1)
	d.fill = func(context.Context, Target, []byte) (bool, error) { close(entered); <-release; return true, nil }
	go func() {
		done <- c.Run(context.Background(), target(), func() ([]byte, error) { return []byte("disposable"), nil })
	}()
	<-entered
	if c.Recover(context.Background()) == nil || d.orphans {
		t.Fatal("recovery interrupted active operation")
	}
	r := c.Run(context.Background(), target(), func() ([]byte, error) { t.Fatal("parallel value read"); return nil, nil })
	if r.Status != "PROTECTED_OPERATION_BUSY" || !g.Blocked() {
		t.Fatal("concurrent operation admitted")
	}
	close(release)
	if (<-done).Status != "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED" {
		t.Fatal("first operation did not complete")
	}
}

func TestGateAuthorityExclusiveAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gate")
	g, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if second, err := OpenGate(dir); err == nil {
		second.Close()
		t.Fatal("duplicate authority accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if next, err := OpenGate(dir); err == nil {
		next.Close()
		t.Fatal("non-private state directory accepted")
	}
}

// This child never loads a vault. SIGKILL prevents defer/Close from running,
// demonstrating that recovery relies on durable state rather than shutdown.
func TestGateKilledProcess(t *testing.T) {
	if dir := os.Getenv("ENVBANK_TEST_GATE_CHILD_DIRECTORY"); dir != "" {
		g, err := OpenGate(dir)
		if err != nil {
			os.Exit(2)
		}
		if g.begin() != nil {
			os.Exit(3)
		}
		_, _ = os.Stdout.WriteString("GATE_BLOCKED\n")
		select {}
	}
	dir := filepath.Join(t.TempDir(), "gate")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGateKilledProcess$")
	command.Env = append(os.Environ(), "ENVBANK_TEST_GATE_CHILD_DIRECTORY="+dir)
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	scanner := bufio.NewScanner(pipe)
	if !scanner.Scan() || scanner.Text() != "GATE_BLOCKED" {
		t.Fatal("child did not persist protected state")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	next, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if !next.Blocked() {
		t.Fatal("SIGKILL lost blocked state")
	}
}

func TestCloseRetainsAuthorityAndCancelsPrivateRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gate")
	g, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	d := &testDriver{}
	filled := false
	d.fill = func(context.Context, Target, []byte) (bool, error) { filled = true; return true, nil }
	c := &Coordinator{Gate: g, Driver: d}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan Receipt, 1)
	go func() {
		done <- c.Run(context.Background(), target(), func() ([]byte, error) { close(entered); <-release; return []byte("disposable-close-test"), nil })
	}()
	<-entered
	closeErr := g.Close()
	next, openErr := OpenGate(dir)
	if next != nil {
		next.Close()
	}
	close(release)
	result := <-done
	if closeErr == nil || openErr == nil {
		t.Fatal("authority released while private work was active")
	}
	if filled || !d.destroyed || result.Status != "RECOVERY_REQUIRED" {
		t.Fatal("closed controller released value or failed cleanup")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenGate(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if !restarted.Blocked() {
		t.Fatal("replacement authority resumed without trusted recovery")
	}
}
