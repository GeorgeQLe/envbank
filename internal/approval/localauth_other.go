//go:build !(darwin && cgo)

package approval

import "unsafe"

type laHandle = unsafe.Pointer

type laBackend interface {
	available(allowPasscode bool) bool
	open(allowPasscode bool) (laHandle, bool)
	state(h laHandle) ([]byte, bool)
	evaluate(h laHandle, reason string, allowPasscode bool, timeoutMS int64) int
	invalidate(h laHandle)
	release(h laHandle)
}

// noBackend: LocalAuthentication is unavailable off macOS (or without cgo),
// so every approval is refused with APPROVAL_UNAVAILABLE.
type noBackend struct{}

func (noBackend) available(bool) bool                        { return false }
func (noBackend) open(bool) (laHandle, bool)                 { return nil, false }
func (noBackend) state(laHandle) ([]byte, bool)              { return nil, false }
func (noBackend) evaluate(laHandle, string, bool, int64) int { return 2 }
func (noBackend) invalidate(laHandle)                        {}
func (noBackend) release(laHandle)                           {}

var la laBackend = noBackend{}
