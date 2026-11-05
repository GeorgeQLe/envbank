package provideraction

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
)

// Operation states.
const (
	StateStarted   = "started"
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
)

// Executor bounds.
const (
	DefaultMaxRunning = 2
	DefaultMaxJournal = 64
	// DefaultOperationTimeout bounds one operation end to end.
	DefaultOperationTimeout = 30 * time.Minute
)

var operationIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidOperationID reports whether id has the operation_id shape.
func ValidOperationID(id string) bool { return operationIDRe.MatchString(id) }

// Cancellation causes, mapped to fixed failure codes.
var (
	errScopeEnded = errors.New("grant ended")
	errClosed     = errors.New("broker closed")
)

// Status is one operation's value-free status, for its owning session only.
type Status struct {
	OperationID string
	Action      string
	State       string
	Step        string   // current step, or the step a failed operation stopped in
	Code        string   // failed only
	Steps       []string // completed steps, in order
	Result      *Result  // value-free; partial for a failed operation
}

type operation struct {
	id, action, owner, scope string
	state, step, code        string
	steps                    []string
	result                   Result
	cancel                   context.CancelCauseFunc
	finished                 bool
}

// slot is a reserved place to run one operation (taken before the owner
// is prompted, so an approved action never finds the executor full).
type slot struct {
	e     *Executor
	used  bool
	once  sync.Once
	lease *lease // resource keys, held until the operation ends
}

// Executor runs operations asynchronously with bounded concurrency and a
// bounded in-memory journal. Operations end when the executor closes.
type Executor struct {
	maxRunning, maxJournal int
	timeout                time.Duration

	mu      sync.Mutex
	running int // reserved or running
	ops     map[string]*operation
	order   []*operation    // oldest first, for eviction
	locks   map[string]bool // resource keys held by reserved or running operations
	closed  bool
	base    context.Context
	stop    context.CancelCauseFunc
	wg      sync.WaitGroup
}

// NewExecutor returns an executor; zero bounds take the defaults.
func NewExecutor(maxRunning, maxJournal int, timeout time.Duration) *Executor {
	if maxRunning <= 0 {
		maxRunning = DefaultMaxRunning
	}
	if maxJournal < maxRunning {
		maxJournal = max(DefaultMaxJournal, maxRunning)
	}
	if timeout <= 0 {
		timeout = DefaultOperationTimeout
	}
	base, stop := context.WithCancelCause(context.Background())
	return &Executor{maxRunning: maxRunning, maxJournal: maxJournal, timeout: timeout, ops: map[string]*operation{}, locks: map[string]bool{}, base: base, stop: stop}
}

// reserve takes a run slot, or returns a fixed refusal code. The slot owns
// l (which may be nil) from then on: it is released with the slot, or when
// the started operation finishes.
func (e *Executor) reserve(l *lease) (*slot, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, agentbroker.CodeBrokerClosed
	}
	if e.running >= e.maxRunning {
		return nil, agentbroker.CodeBusy
	}
	e.running++
	return &slot{e: e, lease: l}, ""
}

// release frees an unused slot (the owner declined, or the start failed).
func (s *slot) release() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		if s.used {
			return
		}
		s.e.mu.Lock()
		s.e.running--
		s.lease.releaseLocked()
		s.e.mu.Unlock()
	})
}

// evictLocked drops the oldest finished operations until one more fits.
func (e *Executor) evictLocked() {
	for len(e.ops) >= e.maxJournal {
		idx := -1
		for i, op := range e.order {
			if op.finished {
				idx = i
				break
			}
		}
		if idx < 0 {
			return
		}
		delete(e.ops, e.order[idx].id)
		e.order = append(e.order[:idx], e.order[idx+1:]...)
	}
}

// start runs fn in the background on a reserved slot and returns the new
// operation's ID.
func (e *Executor) start(s *slot, action, owner, scope string, fn func(ctx context.Context, op *opHandle) (Result, error)) (string, string) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		s.release()
		return "", agentbroker.CodeBusy
	}
	id := hex.EncodeToString(raw[:])
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		s.release()
		return "", agentbroker.CodeBrokerClosed
	}
	e.evictLocked()
	if len(e.ops) >= e.maxJournal {
		e.mu.Unlock()
		s.release()
		return "", agentbroker.CodeBusy
	}
	ctx, cancel := context.WithCancelCause(e.base)
	op := &operation{id: id, action: action, owner: owner, scope: scope, state: StateStarted, cancel: cancel}
	e.ops[id] = op
	e.order = append(e.order, op)
	s.once.Do(func() { s.used = true })
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		tctx, tcancel := context.WithTimeout(ctx, e.timeout)
		defer tcancel()
		defer cancel(nil)
		h := &opHandle{e: e, op: op}
		h.set(func(op *operation) { op.state = StateRunning })
		res, err := fn(tctx, h)
		e.finish(op, s.lease, res, err, tctx)
	}()
	return id, ""
}

func (e *Executor) finish(op *operation, l *lease, res Result, err error, ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l.releaseLocked()
	op.result = res.clone()
	op.finished = true
	e.running--
	if err == nil {
		op.state, op.code = StateSucceeded, ""
		return
	}
	op.state = StateFailed
	var f *failure
	if errors.As(err, &f) {
		if f.step != "" {
			op.step = f.step
		}
		op.code = f.code
	} else {
		op.code = CodeProviderFailed
	}
	if c := cancelCode(ctx); c != "" {
		op.code = c
	}
}

// cancelCode maps a cancelled operation context to its fixed code.
func cancelCode(ctx context.Context) string {
	if ctx.Err() == nil {
		return ""
	}
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errScopeEnded):
		return agentbroker.CodeNotAuthorized
	case errors.Is(cause, errClosed):
		return agentbroker.CodeBrokerClosed
	case errors.Is(cause, context.DeadlineExceeded):
		return CodeTimedOut
	default:
		return CodeCancelled
	}
}

// status returns a copy of id's status if owner started it. An unknown ID
// and another session's ID look the same.
func (e *Executor) status(owner, id string) (Status, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	op, ok := e.ops[id]
	if !ok || op.owner != owner {
		return Status{}, false
	}
	st := Status{OperationID: op.id, Action: op.action, State: op.state, Step: op.step, Code: op.code, Steps: append([]string{}, op.steps...)}
	if op.finished {
		r := op.result.clone()
		st.Result = &r
	}
	return st, true
}

// endScope cancels every running operation started under scope.
func (e *Executor) endScope(scope string) {
	e.mu.Lock()
	var cancels []context.CancelCauseFunc
	for _, op := range e.ops {
		if op.scope == scope && !op.finished {
			cancels = append(cancels, op.cancel)
		}
	}
	e.mu.Unlock()
	for _, c := range cancels {
		c(errScopeEnded)
	}
}

// close refuses new operations, cancels the running ones and waits up to
// wait for them to stop.
func (e *Executor) close(wait time.Duration) {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.stop(errClosed)
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(wait):
	}
}

// opHandle lets a running operation report its progress.
type opHandle struct {
	e  *Executor
	op *operation
}

func (h *opHandle) set(fn func(*operation)) {
	h.e.mu.Lock()
	fn(h.op)
	h.e.mu.Unlock()
}

func (h *opHandle) begin(step string) { h.set(func(op *operation) { op.step = step }) }
func (h *opHandle) done(step string) {
	h.set(func(op *operation) { op.steps = append(op.steps, step) })
}
