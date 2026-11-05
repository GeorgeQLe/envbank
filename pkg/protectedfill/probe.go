package protectedfill

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// GateState is the shared protected-operation state as seen by an
// out-of-process observer such as a vendor lifecycle hook command.
type GateState string

const (
	// GateReady: an initialized private gate directory with no durable latch.
	// It does NOT mean an observer may receive values; it only means no
	// protected phase is in force at the instant of the probe.
	GateReady GateState = "READY"
	// GateBlocked: a protected phase is active, or a crashed/failed phase left
	// the durable latch awaiting trusted recovery.
	GateBlocked GateState = "BLOCKED"
	// GateUnknown: the directory is missing, not private, not owned by this
	// user, uninitialized or unreadable. Observers must treat it as blocked.
	GateUnknown GateState = "UNKNOWN"
)

// ProbeGate reads the SAME durable latch an authority opened with OpenGate
// writes before any value is retrieved. It never creates, removes or locks
// gate state, so it cannot open, clear or race the authority. A probe is a
// point-in-time observation: a protected phase may begin immediately after a
// READY result. Callers that cannot also drain or invalidate work started
// before that phase (lifecycle hooks cannot) must never be used to qualify
// a host for value release.
func ProbeGate(directory string) GateState {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return GateUnknown
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return GateUnknown
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return GateUnknown
	}
	if state := probeLatch(directory); state != GateReady {
		return state
	}
	// Only a directory initialized by an authority (OpenGate) counts.
	lock, err := os.Lstat(filepath.Join(directory, gateLockName))
	if err != nil || !lock.Mode().IsRegular() {
		return GateUnknown
	}
	// Re-read the latch last so a phase that began during the probe is seen.
	return probeLatch(directory)
}

func probeLatch(directory string) GateState {
	// Any entry at the latch path (file, symlink, directory) is blocked.
	_, err := os.Lstat(filepath.Join(directory, gateLatchName))
	if err == nil {
		return GateBlocked
	}
	if errors.Is(err, os.ErrNotExist) {
		return GateReady
	}
	return GateUnknown
}
