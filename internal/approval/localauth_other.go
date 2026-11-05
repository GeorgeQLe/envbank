//go:build !(darwin && cgo)

package approval

import (
	"context"
	"time"
)

// LocalAuth is unavailable off macOS (or without cgo): every approval is
// refused with APPROVAL_UNAVAILABLE.
type LocalAuth struct {
	AllowPasscode bool
	Timeout       time.Duration
}

// Available implements Approver.
func (LocalAuth) Available() bool { return false }

// Approve implements Approver.
func (LocalAuth) Approve(context.Context, string) Outcome { return Unavailable }
