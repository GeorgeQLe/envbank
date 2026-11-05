package provideraction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/agentbroker"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// Health policy minimums (lifecycle.HealthEvidence): at least 3 successful
// checks spanning at least 30 s. Only the clock and the interval between
// checks can be changed; the minimums cannot be lowered.
const (
	MinHealthChecks       = 3
	MinHealthWindow       = 30 * time.Second
	DefaultHealthInterval = 15 * time.Second
	maxHealthChecks       = 64
)

// Clock is the time source for health checks (injectable for tests).
type Clock interface {
	Now() time.Time
	// Sleep waits d or until ctx ends.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Options configure a Service.
type Options struct {
	// Vault is nil when no vault is unlocked (setup mode): every action is
	// then PROVIDER_UNAVAILABLE.
	Vault Vault
	// Factory is nil by default: every action is PROVIDER_UNAVAILABLE.
	Factory Factory
	// Clock and HealthInterval default to the wall clock and 15 s.
	Clock          Clock
	HealthInterval time.Duration
	// PromotionInterval is the wait between production alias reads after a
	// promote or rollback (default 5 s; at most maxPromotionPolls reads).
	PromotionInterval time.Duration
	// Executor bounds (defaults: 2 running, 64 journal entries, 30 min).
	MaxRunning       int
	MaxJournal       int
	OperationTimeout time.Duration
	// CloseWait bounds how long Close waits for cancelled operations.
	CloseWait time.Duration
}

// Service validates, plans and runs provider actions.
type Service struct {
	vault     Vault
	factory   Factory
	clock     Clock
	interval  time.Duration
	promoteIn time.Duration
	exec      *Executor
	closeWait time.Duration
	closeOnce sync.Once
}

// New returns a service. It is always usable for status; actions need a
// vault and a factory.
func New(o Options) *Service {
	s := &Service{vault: o.Vault, factory: o.Factory, clock: o.Clock, interval: o.HealthInterval, promoteIn: o.PromotionInterval, closeWait: o.CloseWait,
		exec: NewExecutor(o.MaxRunning, o.MaxJournal, o.OperationTimeout)}
	if s.clock == nil {
		s.clock = realClock{}
	}
	if s.interval <= 0 {
		s.interval = DefaultHealthInterval
	}
	if s.promoteIn <= 0 {
		s.promoteIn = DefaultPromotionInterval
	}
	if s.closeWait <= 0 {
		s.closeWait = 5 * time.Second
	}
	return s
}

// Available reports whether actions can run (a vault and a factory).
func (s *Service) Available() bool { return s != nil && s.vault != nil && s.factory != nil }

// Prepared is a validated, planned action holding a reserved run slot.
// Release it when it is not started.
type Prepared struct {
	action string
	plan   plan
	slot   *slot
}

// Action is the action ID.
func (p *Prepared) Action() string { return p.action }

// Summary is the deterministic, value-free plan text for the approval.
func (p *Prepared) Summary() string { return p.plan.summary() }

// Prepare validates params strictly, checks what can be checked without
// side effects (control credentials present, record preconditions, then
// read-only provider prechecks) and reserves a run slot. It returns a fixed
// code on refusal. Nothing it does prompts the owner or changes a provider.
func (s *Service) Prepare(ctx context.Context, action string, params json.RawMessage) (*Prepared, string) {
	p, code, _ := s.PrepareDetail(ctx, action, params)
	return p, code
}

// PrepareDetail is Prepare, and on some refusals also a value-free detail
// for the agent (STRIPE_ORPHAN_ENDPOINT: orphan_endpoint_id).
func (s *Service) PrepareDetail(ctx context.Context, action string, params json.RawMessage) (*Prepared, string, *Result) {
	if !s.Available() {
		return nil, CodeUnavailable, nil
	}
	pl, ok := parsePlan(action, params)
	if !ok {
		return nil, agentbroker.CodeInvalidRequest, nil
	}
	for _, c := range pl.controls() {
		ok, err := s.vault.Exists(ctx, c)
		if err != nil {
			return nil, agentbroker.CodeVaultFailed, nil
		}
		if !ok {
			return nil, CodeControlMissing, nil
		}
	}
	// The resources this action changes are locked before the record
	// prechecks, so what they found still holds when the operation runs, and
	// a second operation on the same resource is refused before its prompt.
	l, code := s.exec.lock(pl.resources(ctx, s.vault))
	if code != "" {
		return nil, code, nil
	}
	if code := pl.precheck(ctx, s.vault); code != "" {
		l.release()
		return nil, code, nil
	}
	sl, code := s.exec.reserve(l)
	if code != "" {
		l.release()
		return nil, code, nil
	}
	// Read-only provider prechecks, with ports built for this check only
	// (no operation authority: they cannot mutate), closed and wiped here.
	if lc, ok := pl.(liveChecker); ok {
		if code, detail := s.liveCheck(ctx, lc); code != "" {
			sl.release()
			return nil, code, detail
		}
	}
	return &Prepared{action: action, plan: pl, slot: sl}, "", nil
}

// liveCheckTimeout bounds a plan's read-only provider prechecks.
const liveCheckTimeout = 30 * time.Second

// liveChecker is a plan with read-only provider prechecks that must refuse
// before the prompt (the plan text may depend on them).
type liveChecker interface {
	liveControls() []string
	liveCheck(ctx context.Context, p *ports) (code string, detail *Result)
}

func (s *Service) liveCheck(ctx context.Context, lc liveChecker) (string, *Result) {
	ctx, cancel := context.WithTimeout(ctx, liveCheckTimeout)
	defer cancel()
	var bufs [][]byte
	var p ports
	defer func() {
		for _, b := range bufs {
			wipe(b)
		}
	}()
	defer p.close()
	if err := s.openPorts(ctx, lc.liveControls(), &p, &bufs); err != nil {
		var f *failure
		if errors.As(err, &f) {
			return f.code, nil
		}
		return CodeControlRefused, nil
	}
	return lc.liveCheck(ctx, &p)
}

// Release frees an unstarted preparation's slot (safe to call always).
func (p *Prepared) Release() {
	if p != nil {
		p.slot.release()
	}
}

// Start begins an approved action for owner (an opaque session key) under
// scope (its grant). valid is re-checked before every step; a revoked or
// expired grant fails the operation (NOT_AUTHORIZED) before it acts further.
func (s *Service) Start(p *Prepared, owner, scope string, valid func() bool) (string, string) {
	if p == nil || owner == "" {
		return "", agentbroker.CodeInvalidRequest
	}
	return s.exec.start(p.slot, p.action, owner, scope, func(ctx context.Context, h *opHandle) (Result, error) {
		// Provider mutations are authorized only inside this approved
		// operation, re-checked immediately before each is sent.
		ctx = withOperationAuthority(ctx, func(c context.Context) error {
			if valid != nil && !valid() {
				return errNotAuthorized
			}
			return c.Err()
		})
		r := &run{ctx: ctx, svc: s, vault: s.vault, h: h, valid: valid}
		err := s.execute(r, p.plan)
		return *r.res0(), err
	})
}

// Status returns owner's operation id, or false (unknown or not owner's).
func (s *Service) Status(owner, id string) (Status, bool) {
	if !ValidOperationID(id) {
		return Status{}, false
	}
	return s.exec.status(owner, id)
}

// EndScope cancels the operations started under scope (its grant ended).
func (s *Service) EndScope(scope string) {
	if s != nil {
		s.exec.endScope(scope)
	}
}

// Close cancels every operation and refuses new ones (the broker locked).
func (s *Service) Close() {
	if s != nil {
		s.closeOnce.Do(func() { s.exec.close(s.closeWait) })
	}
}

// ports are one operation's (or one precheck's) provider ports.
type ports struct {
	neon   NeonPort
	vercel VercelPort
	stripe StripePort
}

// close closes every port (its adapters wipe their credential copies).
func (p *ports) close() {
	if p.neon != nil {
		_ = p.neon.Close()
	}
	if p.vercel != nil {
		_ = p.vercel.Close()
	}
	if p.stripe != nil {
		_ = p.stripe.Close()
	}
}

// execute reads the control credentials, builds the ports and runs the
// action. When it returns, every port is closed (its adapters wipe their
// credential copies) and then the credential buffers are wiped.
func (s *Service) execute(r *run, pl plan) error {
	var bufs [][]byte
	defer func() {
		for _, b := range bufs {
			wipe(b)
		}
	}()
	defer r.ports.close()
	if err := r.step(StepControl, CodeControlRefused, func() error {
		return s.openPorts(r.ctx, pl.controls(), &r.ports, &bufs)
	}); err != nil {
		return err
	}
	return pl.execute(r)
}

// openPorts reads each control credential inside a vault callback into a
// buffer appended to bufs (the caller wipes them after closing p) and
// builds its port.
func (s *Service) openPorts(ctx context.Context, controls []string, p *ports, bufs *[][]byte) error {
	for _, name := range controls {
		var cred []byte
		if _, err := s.vault.Latest(ctx, name, func(v []byte) error {
			cred = append([]byte(nil), v...)
			return nil
		}); err != nil {
			wipe(cred)
			if errors.Is(err, ErrMissing) {
				return fail(CodeControlMissing)
			}
			return fail(agentbroker.CodeVaultFailed)
		}
		*bufs = append(*bufs, cred)
		if len(cred) == 0 {
			return fail(CodeControlMissing)
		}
		var err error
		switch name {
		// A port is kept only when the factory succeeded, so a nil
		// interface (never a typed nil) is what the closer skips.
		case ControlNeon:
			var port NeonPort
			if port, err = s.factory.Neon(cred); err == nil && port != nil {
				p.neon = port
			}
		case ControlVercel:
			var port VercelPort
			if port, err = s.factory.Vercel(cred); err == nil && port != nil {
				p.vercel = port
			}
		case ControlStripe:
			// v1 refuses live-mode Stripe keys.
			if !bytes.HasPrefix(cred, []byte("sk_test_")) && !bytes.HasPrefix(cred, []byte("rk_test_")) {
				return fail(CodeControlRefused)
			}
			var port StripePort
			if port, err = s.factory.Stripe(cred); err == nil && port != nil {
				p.stripe = port
			}
		}
		if err != nil {
			return fail(CodeControlRefused)
		}
	}
	if (p.neon == nil && has(controls, ControlNeon)) || (p.vercel == nil && has(controls, ControlVercel)) || (p.stripe == nil && has(controls, ControlStripe)) {
		return fail(CodeControlRefused)
	}
	return nil
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// failure is a fixed step and code; it carries no caller or provider text.
type failure struct{ step, code string }

func (f *failure) Error() string { return f.code }

func fail(code string) error { return &failure{code: code} }

// run is one executing operation.
type run struct {
	ctx   context.Context
	svc   *Service
	vault Vault
	h     *opHandle
	valid func() bool
	ports
	res  *Result
	prod *release // production release state (production.go)
}

func (r *run) res0() *Result {
	if r.res == nil {
		r.res = &Result{}
	}
	return r.res
}

// step runs one step: the grant and context are checked first; any error
// becomes a fixed failure with this step name (an explicit failure keeps its
// code, otherwise code).
func (r *run) step(name, code string, fn func() error) error {
	r.res0()
	r.h.begin(name)
	if r.valid != nil && !r.valid() {
		return &failure{step: name, code: agentbroker.CodeNotAuthorized}
	}
	if c := cancelCode(r.ctx); c != "" {
		return &failure{step: name, code: c}
	}
	if err := fn(); err != nil {
		f := &failure{step: name, code: code}
		var given *failure
		if errors.As(err, &given) {
			f.code = given.code
		}
		if c := cancelCode(r.ctx); c != "" {
			f.code = c
		}
		return f
	}
	r.h.done(name)
	return nil
}

// checkHealth makes checks until at least MinHealthChecks succeeded over at
// least MinHealthWindow. Any failed check fails the step. The summary goes
// to *into.
func (r *run) checkHealth(deploymentURL, path string, into **HealthResult) error {
	var first, last time.Time
	n := 0
	for {
		if err := r.vercel.CheckHealth(r.ctx, deploymentURL, path); err != nil {
			if errors.Is(err, ErrHealthProtected) {
				return fail(CodeHealthProtected)
			}
			return fail(CodeHealthFailed)
		}
		now := r.svc.clock.Now()
		if n == 0 {
			first = now
		}
		last = now
		n++
		if n >= MinHealthChecks && last.Sub(first) >= MinHealthWindow {
			break
		}
		if n >= maxHealthChecks {
			return fail(CodeHealthFailed)
		}
		if err := r.svc.clock.Sleep(r.ctx, r.svc.interval); err != nil {
			return fail(CodeHealthFailed)
		}
	}
	*into = &HealthResult{Checks: n, WindowSeconds: int(last.Sub(first) / time.Second)}
	return nil
}

// recorder captures the revisions an adapter's sinks stored.
type recorder struct {
	v    Vault
	mu   sync.Mutex
	revs map[string]int64
}

func (r *run) recorder() *recorder { return &recorder{v: r.vault, revs: map[string]int64{}} }

func (w *recorder) StoreSecret(ctx context.Context, name string, fill func(func([]byte) error) error) (int64, error) {
	rev, err := w.v.StoreSecret(ctx, name, fill)
	if err == nil && rev > 0 {
		w.mu.Lock()
		w.revs[name] = rev
		w.mu.Unlock()
	}
	return rev, err
}

func (w *recorder) sink(record string) *lifecycle.SecretSink {
	s, _ := lifecycle.NewSecretSink(w, record) // record is validated and non-empty
	return s
}

// require checks that every record was stored durably and records the
// revisions in res.
func (w *recorder) require(res *Result, records ...string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, rec := range records {
		rev, ok := w.revs[rec]
		if !ok || rev < 1 {
			return fail(agentbroker.CodeVaultFailed)
		}
		res.record(rec, rev)
	}
	return nil
}

// discardWriter stores nothing: it wipes what it is given (owner URIs
// returned by project create, which must never be persisted).
type discardWriter struct{}

func (discardWriter) StoreSecret(_ context.Context, _ string, fill func(func([]byte) error) error) (int64, error) {
	if err := fill(func(v []byte) error { wipe(v); return nil }); err != nil {
		return 0, err
	}
	return 1, nil
}

func discardSink() *lifecycle.SecretSink {
	s, _ := lifecycle.NewSecretSink(discardWriter{}, "discarded")
	return s
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
