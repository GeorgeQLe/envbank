package protectedfill

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/browser"
)

// Target contains public binding metadata only. Handles must resolve inside a
// dedicated controller-owned browser context, never the user's ordinary tabs.
type Target struct {
	Record   string `json:"record"`
	Context  string `json:"context"`
	Document string `json:"document"`
	Field    string `json:"field"`
	Submit   string `json:"submit"`
	Origin   string `json:"origin"`
}

// Driver is a trusted host integration, not a client/extension-reported pause.
// Validate consumes single-use human approval bound to the complete Target.
// It checks owned isolated context, document/focus, top frame, same-origin
// HTTPS POST action and the approved destination. FillAndSubmit revalidates at
// use time, never logs values, and must not retain the supplied slice.
// Destroy returns only after ALL pages/popups and queued artifacts in that
// context are gone. DestroyOrphans proves the same after a controller restart.
// All methods must honor cancellation. Implementations require separate review.
type Driver interface {
	Validate(context.Context, Target) error
	FillAndSubmit(context.Context, Target, []byte) (bool, error)
	Destroy(context.Context, Target) error
	DestroyOrphans(context.Context) error
}

type Receipt struct {
	Status string `json:"status"`
}

// Coordinator must be constructed by the observation-controlling host. The
// standalone EnvBank native host intentionally has no Driver configured.
type Coordinator struct {
	Gate   *Gate
	Driver Driver
}

func (c *Coordinator) Configured() bool { return c != nil && c.Gate != nil && c.Driver != nil }
func (c *Coordinator) Available() bool  { return c.Configured() && !c.Gate.Blocked() }

func validTarget(t Target) bool {
	origin, err := browser.NormalizeOrigin(t.Origin)
	if err != nil || origin != t.Origin || !strings.HasPrefix(origin, "https://") {
		return false
	}
	for _, s := range []string{t.Record, t.Context, t.Document, t.Field, t.Submit} {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// Run never returns values, hashes, page text or driver errors. A reported
// submission attempt does not establish authentication or provider persistence.
func (c *Coordinator) Run(ctx context.Context, t Target, read func() ([]byte, error)) (receipt Receipt) {
	receipt.Status = "HOST_PROTECTION_UNAVAILABLE"
	if c == nil || c.Gate == nil || c.Driver == nil {
		return
	}
	if !validTarget(t) || read == nil {
		receipt.Status = "TARGET_REJECTED"
		return
	}
	if !c.Gate.operation.TryLock() {
		receipt.Status = "PROTECTED_OPERATION_BUSY"
		return
	}
	defer c.Gate.operation.Unlock()
	if c.Gate.begin() != nil {
		receipt.Status = "RECOVERY_REQUIRED"
		return
	}
	receipt.Status = "FAILED_CONTEXT_CLOSED"
	var value []byte
	validated := false
	defer func() {
		if recover() != nil {
			receipt.Status = "FAILED_CONTEXT_CLOSED"
		}
		wipe(value)
		// Validation is pure: rejecting an unowned target releases no value and
		// must never cause destruction of arbitrary user windows.
		if validated {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if safeDestroy(cleanup, c.Driver, t) != nil {
				receipt.Status = "RECOVERY_REQUIRED"
				return
			}
		}
		if c.Gate.resume() != nil {
			receipt.Status = "RECOVERY_REQUIRED"
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.Driver.Validate(bounded, t); err != nil {
		receipt.Status = "TARGET_REJECTED"
		return
	}
	validated = true
	if bounded.Err() != nil {
		return
	}
	var err error
	value, err = read()
	if err != nil || len(value) == 0 || len(value) > 65536 || bounded.Err() != nil {
		return
	}
	attempted, err := c.Driver.FillAndSubmit(bounded, t, value)
	if err == nil && bounded.Err() == nil && attempted {
		receipt.Status = "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED"
	}
	return
}

func safeDestroy(ctx context.Context, d Driver, t Target) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("CLEANUP_FAILED")
		}
	}()
	return d.Destroy(ctx, t)
}

// Recover is a host-only bootstrap operation, never exposed through native RPC.
func (c *Coordinator) Recover(ctx context.Context) (err error) {
	if c == nil || c.Gate == nil || c.Driver == nil {
		return ErrBlocked
	}
	defer func() {
		if recover() != nil {
			err = ErrBlocked
		}
	}()
	if !c.Gate.operation.TryLock() {
		return ErrBlocked
	}
	defer c.Gate.operation.Unlock()
	if !c.Gate.Blocked() {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.Driver.DestroyOrphans(bounded) != nil || bounded.Err() != nil {
		return ErrBlocked
	}
	return c.Gate.resume()
}
