package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
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
