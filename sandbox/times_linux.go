//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const noatime = syscall.O_NOATIME

// fsNames maps statfs magic numbers to names, for the run information and
// for the file systems whose name gives their time resolution.
var fsNames = map[uint32]string{
	0xEF53:     "ext4", // also ext2 and ext3
	0x9123683E: "btrfs",
	0x58465342: "xfs",
	0x01021994: "tmpfs",
	0x2FC12FC1: "zfs",
	0xF2F52010: "f2fs",
	0x4D44:     "VFAT",
	0x2011BAB0: "EXFAT",
	0x7366746E: "NTFS", // ntfs3
	0x6969:     "nfs",
	0x794C7630: "overlay",
	0x65735546: "fuse",
}

// fsNameOf names the volume holding the root, or "" for one not listed.
func fsNameOf(r *os.Root) string {
	d, err := r.Open(".")
	if err != nil {
		return ""
	}
	defer d.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(d.Fd()), &st); err != nil {
		return ""
	}
	return fsNames[uint32(st.Type)]
}

// statMeta asks statx for the four times, relative to a descriptor for the
// parent directory opened through the root, so the object can only be one
// inside it, and without following a final symlink. The birth time is only
// reported when the file system has one (statx sets STATX_BTIME in its
// mask); otherwise it stays zero, never a copy of another time.
func statMeta(r *os.Root, name string) (Meta, error) {
	dir, leaf := filepath.Split(name)
	if dir == "" {
		dir = "."
	}
	if leaf == "" {
		leaf = "."
	}
	parent, err := r.Open(dir)
	if err != nil {
		return Meta{}, err
	}
	defer parent.Close()
	var st unix.Statx_t
	if err := unix.Statx(int(parent.Fd()), leaf, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &st); err != nil {
		return Meta{}, err
	}
	ts := func(t unix.StatxTimestamp) time.Time { return time.Unix(t.Sec, int64(t.Nsec)).UTC() }
	m := Meta{
		Times: Times{Atime: ts(st.Atime), Mtime: ts(st.Mtime), Ctime: ts(st.Ctime)},
		ID:    strconv.FormatUint(st.Ino, 10),
		UID:   int(st.Uid),
		GID:   int(st.Gid),
	}
	if st.Mask&unix.STATX_BTIME != 0 {
		m.Btime = ts(st.Btime)
	}
	return m, nil
}
