//go:build !windows

package sandbox

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// Only access and modification times can be set here: Unix has no call that
// sets a change time, and none that sets a birth time on Linux (macOS's
// setattrlist is not used until it is verified on a Mac).
func timeCaps(string) TimeCaps { return TimeCaps{} }

// volumeGranularity works out how finely the volume keeps times. FAT and
// exFAT are known by name. Otherwise the root directory's change time
// decides, since only the kernel sets it: a volume that keeps nanoseconds
// (btrfs, xfs, tmpfs, ext4 with large inodes, APFS) all but never records
// one on a whole second, and one that keeps whole seconds (ext3, ext4 with
// 128-byte inodes, the default below 512 MB, HFS+) always does. Anything
// else is taken to keep microseconds.
func volumeGranularity(r *os.Root, fsName string) Granularity {
	if g, ok := namedGranularity(fsName); ok {
		return g
	}
	if m, err := statMeta(r, "."); err == nil && !m.Ctime.IsZero() && m.Ctime.Nanosecond() == 0 {
		return wholeSeconds
	}
	return Granularity{time.Microsecond, time.Microsecond, time.Microsecond, time.Microsecond}
}

func setTimes(r *os.Root, name string, t Times, _ TimeCaps) error {
	if t.Atime.IsZero() && t.Mtime.IsZero() {
		return nil
	}
	return r.Chtimes(name, t.Atime, t.Mtime)
}

func getMeta(r *os.Root, name, _ string) (Meta, error) { return statMeta(r, name) }

// lstatMeta reads the one time every Unix reports through lstat. That is all
// a platform without a stat reader can offer, and where the BSDs' richer
// statMeta starts, so it returns the FileInfo it read for them to go on with.
func lstatMeta(r *os.Root, name string) (Meta, os.FileInfo, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return Meta{}, nil, err
	}
	return Meta{Times: Times{Mtime: fi.ModTime().UTC()}}, fi, nil
}

func openQuiet(r *os.Root, name string) (*os.File, error) {
	if noatime != 0 {
		f, err := r.OpenFile(name, os.O_RDONLY|noatime, 0)
		if !errors.Is(err, syscall.EPERM) {
			return f, err
		}
		// O_NOATIME is refused on files the caller does not own.
	}
	return r.OpenFile(name, os.O_RDONLY, 0)
}
