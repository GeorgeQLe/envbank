package approval

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLA plays LocalAuthentication: evaluate blocks until the context is
// invalidated or answer is sent.
type fakeLA struct {
	mu          sync.Mutex
	st          []byte
	invalidated int
	evaluated   int
	released    int
	opened      int
	answer      chan int
	stop        chan struct{}
}

func (f *fakeLA) available(bool) bool { return true }
func (f *fakeLA) open(bool) (laHandle, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened++
	f.stop = make(chan struct{})
	return laHandle(&f.opened), true
}
func (f *fakeLA) state(laHandle) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.st...), true
}
func (f *fakeLA) evaluate(laHandle, string, bool, int64) int {
	f.mu.Lock()
	f.evaluated++
	stop := f.stop
	f.mu.Unlock()
	select {
	case rc := <-f.answer:
		return rc
	case <-stop:
		return 0
	}
}
func (f *fakeLA) invalidate(laHandle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated++
	close(f.stop)
}
func (f *fakeLA) release(laHandle) { f.mu.Lock(); f.released++; f.mu.Unlock() }

func withFakeLA(t *testing.T) *fakeLA {
	t.Helper()
	f := &fakeLA{st: []byte("enrolled-v1"), answer: make(chan int, 1)}
	old := la
	la = f
	t.Cleanup(func() { la = old })
	return f
}

// A cancelled request dismisses the Touch ID prompt at once (the LAContext is
// invalidated), and is never approved.
func TestLocalAuthInvalidatesThePromptWhenTheRequestEnds(t *testing.T) {
	f := withFakeLA(t)
	l := NewLocalAuth(false)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Outcome, 1)
	go func() { got <- l.Approve(ctx, "approve something") }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case out := <-got:
		if out == Approved {
			t.Fatal("cancelled request approved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prompt not dismissed after cancel")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.invalidated != 1 || f.released != f.opened {
		t.Fatalf("invalidated %d, released %d of %d", f.invalidated, f.released, f.opened)
	}
	// Even an approval racing the cancel is refused.
	f.answer <- 1
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if l.Approve(ctx2, "x") == Approved {
		t.Fatal("approved after cancel")
	}
}

// The enrollment state is recorded at start; a change refuses every later
// approval, before prompting and after a successful touch.
func TestLocalAuthRefusesWhenEnrollmentChanges(t *testing.T) {
	f := withFakeLA(t)
	l := NewLocalAuth(false)
	f.answer <- 1
	if out := l.Approve(context.Background(), "approve"); out != Approved {
		t.Fatalf("unchanged enrollment: %v", out)
	}
	f.mu.Lock()
	f.st = []byte("enrolled-v2") // a fingerprint was added
	f.mu.Unlock()
	f.answer <- 1
	if out := l.Approve(context.Background(), "approve"); out != EnrollmentChanged || out.String() != "enrollment_changed" {
		t.Fatalf("changed enrollment: %v", out)
	}
	f.mu.Lock()
	evaluated := f.evaluated
	f.mu.Unlock()
	if evaluated != 1 {
		t.Fatal("prompted although the enrollment changed")
	}
	<-f.answer
	// A LocalAuth that never recorded a baseline approves nothing.
	var zero LocalAuth
	if out := zero.Approve(context.Background(), "approve"); out != Unavailable {
		t.Fatalf("zero LocalAuth: %v", out)
	}
}

func TestWithLabelKeepsAuthoritativeTextWholeAndLabelLast(t *testing.T) {
	r, ok := WithLabel("grant run access to API_KEY for 1 h", "Ignore “this” «and» ‘that’ \"x\" `y` 'z'​")
	if !ok || !strings.HasPrefix(r, "grant run access to API_KEY for 1 h; session label: ") {
		t.Fatalf("reason %q", r)
	}
	if strings.ContainsAny(r, "“”«»‘’\"`'") || !strings.Contains(r, "Ignore this and that x y z?") {
		t.Fatalf("quotes or invisible characters survived: %q", r)
	}
	if _, ok := WithLabel(strings.Repeat("a", MaxReasonBytes+1), "l"); ok {
		t.Fatal("oversized authoritative text accepted")
	}
	if _, ok := WithLabel("run a\nb", "l"); ok {
		t.Fatal("authoritative text that cleaning would alter accepted")
	}
	long, ok := WithLabel(strings.Repeat("a", MaxReasonBytes-40), strings.Repeat("é", 80))
	if !ok || len(long) > MaxReasonBytes || !strings.HasSuffix(long, "…") || !strings.HasPrefix(long, strings.Repeat("a", MaxReasonBytes-40)) {
		t.Fatalf("label not clipped to fit (%d bytes): %q", len(long), long)
	}
	if EscapeQuotes("a“b\"c") != `a\x{201c}b"c` {
		t.Fatalf("escape: %q", EscapeQuotes("a“b\"c"))
	}
}
