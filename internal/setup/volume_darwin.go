//go:build darwin

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// mntIgnoreOwnership is MNT_IGNORE_OWNERSHIP (sys/mount.h).
const (
	mntReadOnly        = 0x00000001 // MNT_RDONLY
	mntIgnoreOwnership = 0x00200000 // MNT_IGNORE_OWNERSHIP
)

// SystemInspector uses statfs for the mount point and ownership flag, and
// diskutil for the volume UUID and internal/writable facts.
type SystemInspector struct{}

func (SystemInspector) VolumeOf(path string) (Volume, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Volume{}, err
	}
	mount := cString(st.Mntonname[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	plist, err := exec.CommandContext(ctx, "/usr/sbin/diskutil", "info", "-plist", mount).Output()
	if err != nil {
		return Volume{}, err
	}
	conv := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	conv.Stdin = bytes.NewReader(plist)
	raw, err := conv.Output()
	if err != nil {
		return Volume{}, err
	}
	var d struct {
		VolumeUUID               string
		VolumeName               string
		GlobalPermissionsEnabled bool
		Internal                 bool
		WritableVolume           bool
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return Volume{}, err
	}
	if d.VolumeUUID == "" {
		return Volume{}, errors.New("no volume UUID")
	}
	// The sealed system volume reports read-only; the user's data lives on the
	// writable Data volume, which statfs resolves to for home paths.
	writable := d.WritableVolume || st.Flags&mntReadOnly == 0
	return Volume{
		UUID: d.VolumeUUID, Name: d.VolumeName, MountPoint: mount,
		OwnersEnabled: d.GlobalPermissionsEnabled && st.Flags&mntIgnoreOwnership == 0,
		Internal:      d.Internal, Writable: writable,
	}, nil
}

func cString(b []int8) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(b[i])
	}
	return string(out)
}

func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid())
}
