// Package protectedfill is embedded by a trusted computer-use controller.
// An extension cannot enforce this boundary. Every observation and ordinary
// input route in every controller session must share the same Gate.
package protectedfill

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var ErrBlocked = errors.New("OBSERVATION_BLOCKED")

// Gate holds an exclusive process lock and a durable blocked latch. A restarted
// authority cannot observe until trusted recovery has destroyed orphan contexts.
// It does not sandbox tools that bypass it or malicious same-user processes.
type Gate struct {
	mu        sync.Mutex
	operation sync.Mutex
	blocked   bool
	closed    bool
	epoch     uint64
	next      uint64
	pending   map[uint64]context.CancelFunc
	lock      *os.File
	latch     string
}

func OpenGate(directory string) (*Gate, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("GATE_DIRECTORY_REQUIRED")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("GATE_STORAGE_UNAVAILABLE")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("GATE_PRIVATE_DIRECTORY_REQUIRED")
	}
	lock, err := os.OpenFile(filepath.Join(directory, "authority.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("GATE_STORAGE_UNAVAILABLE")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("GATE_AUTHORITY_ALREADY_RUNNING")
	}
	g := &Gate{lock: lock, latch: filepath.Join(directory, "blocked"), pending: make(map[uint64]context.CancelFunc)}
	if _, err := os.Lstat(g.latch); err == nil {
		g.blocked = true
	} else if !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, errors.New("GATE_STORAGE_UNAVAILABLE")
	}
	return g, nil
}

func (g *Gate) Blocked() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.blocked || g.closed }

// Observe wraps capture AND ordinary input tools. Callback results/errors must
// not be published separately, logged, streamed or delivered through callbacks.
// A late result from a capture begun before the barrier is erased and discarded.
func (g *Gate) Observe(ctx context.Context, capture func(context.Context) ([]byte, error)) ([]byte, error) {
	g.mu.Lock()
	if g.blocked || g.closed {
		g.mu.Unlock()
		return nil, ErrBlocked
	}
	epoch := g.epoch
	g.next++
	id := g.next
	child, cancel := context.WithCancel(ctx)
	g.pending[id] = cancel
	g.mu.Unlock()
	defer cancel()
	var value []byte
	var err error
	func() {
		defer func() {
			if recover() != nil {
				err = errors.New("CAPTURE_FAILED")
			}
		}()
		value, err = capture(child)
	}()
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.pending, id)
	if g.blocked || g.closed || epoch != g.epoch {
		wipe(value)
		return nil, ErrBlocked
	}
	if err != nil || child.Err() != nil {
		wipe(value)
		return nil, errors.New("CAPTURE_FAILED")
	}
	return value, nil
}

func (g *Gate) begin() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked || g.closed {
		return ErrBlocked
	}
	g.blocked = true
	g.epoch++
	for _, cancel := range g.pending {
		cancel()
	}
	f, err := os.OpenFile(g.latch, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrBlocked
	}
	_, err = f.WriteString("protected-fill-v1\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncDirectory(filepath.Dir(g.latch)) != nil {
		return ErrBlocked
	}
	return nil
}

// Only trusted context destruction/recovery may call this. No native message,
// extension receipt, timer or agent-supplied "cleared" boolean can open the gate.
func (g *Gate) resume() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || !g.blocked {
		return ErrBlocked
	}
	if err := os.Remove(g.latch); err != nil {
		return ErrBlocked
	}
	if err := syncDirectory(filepath.Dir(g.latch)); err != nil {
		// Restore the latch when durability cannot be established.
		_ = os.WriteFile(g.latch, []byte("protected-fill-v1\n"), 0600)
		return ErrBlocked
	}
	g.epoch++
	g.blocked = false
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Close never clears a blocked latch. Existing observations become stale.
func (g *Gate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	g.epoch++
	for _, cancel := range g.pending {
		cancel()
	}
	return g.lock.Close()
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
