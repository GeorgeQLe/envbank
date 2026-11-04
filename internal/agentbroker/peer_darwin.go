//go:build darwin

package agentbroker

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerIsMe requires the connecting process to run as this user.
func peerIsMe(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		ok = err == nil && cred.Uid == uint32(os.Getuid())
	})
	return ok
}

func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid())
}
