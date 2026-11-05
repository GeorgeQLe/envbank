package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/approval"
	"github.com/GeorgeQLe/envbank/internal/ownerinput"
)

type fakeSource struct {
	values   [][]byte
	outcome  string
	err      error
	requests int
}

func (f *fakeSource) Entry(context.Context, string, string, string, string, int, int, bool, func(string)) ([]byte, string, error) {
	f.requests++
	if f.err != nil {
		return nil, "", f.err
	}
	if f.outcome != "" && f.outcome != "entered" {
		return nil, f.outcome, nil
	}
	v := f.values[0]
	f.values = f.values[1:]
	return append([]byte(nil), v...), "entered", nil
}

func newSurface(t *testing.T, src secretSource) *ownerSurface {
	t.Helper()
	r, w, _ := os.Pipe()
	t.Cleanup(func() { r.Close(); w.Close() })
	tp := agentbroker.NewTestTerminalPrompter(r, &discard{}, func(int) ([]byte, error) { return []byte("terminal-typed-passphrase"), nil })
	return &ownerSurface{TerminalPrompter: tp, provider: src}
}

type discard struct{}

func (*discard) Write(p []byte) (int, error) { return len(p), nil }

func TestOwnerSurfaceRouting(t *testing.T) {
	ctx := context.Background()
	// Provider entered: value comes from the provider.
	s := newSurface(t, &fakeSource{values: [][]byte{[]byte("provider-passphrase-1")}})
	if v, ok, _ := s.NewPassphrase(ctx, "t", 12, nil); !ok || string(v) != "provider-passphrase-1" {
		t.Fatalf("provider entry: %q %v", v, ok)
	}
	// Explicit decline is a decline, not a fallback to the terminal.
	s = newSurface(t, &fakeSource{outcome: "cancelled"})
	if v, ok, _ := s.NewPassphrase(ctx, "t", 12, nil); ok || v != nil {
		t.Fatal("decline fell back to the terminal")
	}
	// Provider unavailable/unverified: falls back to the terminal.
	s = newSurface(t, &fakeSource{err: errors.New("OWNER_INPUT_PEER_UNVERIFIED")})
	if v, ok, _ := s.NewPassphrase(ctx, "t", 12, nil); !ok || string(v) != "terminal-typed-passphrase" {
		t.Fatalf("no terminal fallback: %q %v", v, ok)
	}
	// Recovery passphrase equal to the vault passphrase is asked again.
	src := &fakeSource{values: [][]byte{[]byte("same-passphrase-x"), []byte("different-passphrase")}}
	s = newSurface(t, src)
	if v, ok, _ := s.NewPassphrase(ctx, "t", 12, []byte("same-passphrase-x")); !ok || string(v) != "different-passphrase" || src.requests != 2 {
		t.Fatalf("recovery reuse: %q %v %d", v, ok, src.requests)
	}
}

type recordingApprover struct {
	outcome     approval.Outcome
	unavailable bool
	reasons     []string
}

func (a *recordingApprover) Available() bool { return !a.unavailable }
func (a *recordingApprover) Approve(_ context.Context, reason string) approval.Outcome {
	a.reasons = append(a.reasons, reason)
	return a.outcome
}

// Typing "y" in the broker terminal confirms nothing: setup plans and
// pairing are decided by the approver alone, and the typed bytes stay unread.
func TestTerminalTypingCannotConfirmSetupOrPairing(t *testing.T) {
	r, w, _ := os.Pipe()
	t.Cleanup(func() { r.Close(); w.Close() })
	typed := "y\nyes\n"
	_, _ = w.Write([]byte(typed))
	tp := agentbroker.NewTestTerminalPrompter(r, &discard{}, nil)
	deny := &recordingApprover{outcome: approval.Denied}
	s := &ownerSurface{TerminalPrompter: tp, approver: deny}
	if out := s.Confirm(context.Background(), "EnvBank setup request", []string{"plan"}, "apply a setup"); out != approval.Denied || len(deny.reasons) != 1 {
		t.Fatalf("setup confirmed without Touch ID: %v", out)
	}
	if out := (&ownerSurface{TerminalPrompter: tp}).Confirm(context.Background(), "t", nil, "x"); out != approval.Unavailable {
		t.Fatal("no approver must be unavailable")
	}
	if out := (&ownerSurface{TerminalPrompter: tp, approver: &recordingApprover{unavailable: true, outcome: approval.Approved}}).Confirm(context.Background(), "t", nil, "x"); out != approval.Unavailable {
		t.Fatal("unavailable biometry approved")
	}
	p := &fakePairer{}
	if err := pairProvider(context.Background(), p, tp, deny); err == nil || p.confirmed {
		t.Fatal("paired without Touch ID")
	}
	ok := &recordingApprover{outcome: approval.Approved}
	if err := pairProvider(context.Background(), p, tp, ok); err != nil || !p.confirmed || !strings.Contains(ok.reasons[0], "code 123456") {
		t.Fatalf("pairing: %v %v", err, ok.reasons)
	}
	_ = r.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	n, _ := io.ReadAtLeast(r, buf, len(typed))
	if string(buf[:n]) != typed {
		t.Fatalf("typed input consumed: %q", buf[:n])
	}
}

type fakePairer struct{ confirmed bool }

func (f *fakePairer) Pair(_ context.Context, confirm func(ownerinput.Identity, string) bool) error {
	f.confirmed = confirm(ownerinput.Identity{TeamID: "NC56VXK48K", Identifier: ownerinput.ServiceIdentifier, CDHash: strings.Repeat("ab", 20)}, "123456")
	if !f.confirmed {
		return errors.New(ownerinput.CodeNotPaired)
	}
	return nil
}
