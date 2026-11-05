//go:build !darwin || !cgo

package ownerapproval

// Hardware owner approval exists only on macOS builds with cgo. Every other
// build refuses; there is deliberately no software or TTY substitute.
func OpenSecureEnclave([]byte) (Signer, error) { return nil, ErrUnavailable }

func EnrollSecureEnclave() ([]byte, error) { return nil, ErrUnavailable }
