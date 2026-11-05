package approval

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// LocalAuth approves with LocalAuthentication. By default it uses
// LAPolicyDeviceOwnerAuthenticationWithBiometrics (no device-passcode
// fallback). AllowPasscode is set only by the owner's own
// --allow-password-fallback flag and selects LAPolicyDeviceOwnerAuthentication.
//
// Use NewLocalAuth: it records the biometric enrollment state when the broker
// starts, and every later approval is refused (EnrollmentChanged) if a
// fingerprint was added or removed since. A LocalAuth that recorded nothing
// approves nothing.
type LocalAuth struct {
	AllowPasscode bool
	Timeout       time.Duration

	mu       sync.Mutex
	recorded bool
	baseline []byte
}

// NewLocalAuth returns an approver with the current enrollment state recorded.
func NewLocalAuth(allowPasscode bool) *LocalAuth {
	l := &LocalAuth{AllowPasscode: allowPasscode}
	if h, ok := la.open(allowPasscode); ok {
		st, ok := la.state(h)
		la.release(h)
		if ok {
			l.baseline, l.recorded = st, true
		}
	} else {
		// No usable biometry now: record "none"; enrolling later is a change.
		l.recorded = true
	}
	return l
}

// Available implements Approver (canEvaluatePolicy; never prompts).
func (l *LocalAuth) Available() bool { return la.available(l.AllowPasscode) }

func (l *LocalAuth) unchanged(h laHandle) bool {
	st, ok := la.state(h)
	l.mu.Lock()
	defer l.mu.Unlock()
	return ok && l.recorded && bytes.Equal(st, l.baseline)
}

// Approve implements Approver. The prompt is dismissed (the LAContext
// invalidated) as soon as ctx is cancelled or expires.
func (l *LocalAuth) Approve(ctx context.Context, reason string) Outcome {
	if ctx.Err() != nil {
		return Denied
	}
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	// Too little time left for the owner to read and touch: do not flash a prompt.
	if timeout < MinPromptTime || reason == "" || len(reason) > MaxReasonBytes+8 {
		return Denied
	}
	l.mu.Lock()
	recorded := l.recorded
	l.mu.Unlock()
	if !recorded {
		return Unavailable
	}
	h, ok := la.open(l.AllowPasscode)
	if !ok {
		return Unavailable
	}
	defer la.release(h)
	if !l.unchanged(h) {
		return EnrollmentChanged // checked before any prompt
	}
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			la.invalidate(h) // the requester went away: dismiss the prompt now
		case <-stop:
		}
	}()
	rc := la.evaluate(h, reason, l.AllowPasscode, timeout.Milliseconds())
	close(stop)
	<-watched
	if ctx.Err() != nil {
		return Denied // the requester went away while the owner was deciding
	}
	switch rc {
	case 1:
		if !l.unchanged(h) {
			return EnrollmentChanged
		}
		return Approved
	case 2:
		return Unavailable
	default:
		return Denied
	}
}
