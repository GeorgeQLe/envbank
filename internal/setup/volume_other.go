//go:build !darwin

package setup

import (
	"errors"
	"os"
	"syscall"
)

// SystemInspector is macOS-only for now; other platforms refuse planning.
type SystemInspector struct{}

func (SystemInspector) VolumeOf(string) (Volume, error) {
	return Volume{}, errors.New("agent-operated setup volume checks are macOS-only for now")
}

func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid())
}

func groupID(info os.FileInfo) int {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Gid)
}
