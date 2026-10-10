//go:build linux || darwin || freebsd || netbsd

package sandbox

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// utimesNoFollow sets name's own times, relative to its parent opened
// through the root, without following a final symlink. A zero time is left
// as it is: it is read first and written back, since not every platform has
// a value that tells the call to leave one time alone.
func utimesNoFollow(r *os.Root, name string, atime, mtime time.Time) error {
	if atime.IsZero() || mtime.IsZero() {
		m, err := statMeta(r, name)
		if err != nil {
			return err
		}
		if atime.IsZero() {
			atime = m.Atime
		}
		if mtime.IsZero() {
			mtime = m.Mtime
		}
	}
	dir, leaf := filepath.Split(name)
	if dir == "" {
		dir = "."
	}
	parent, err := r.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	ts := make([]unix.Timespec, 2)
	for i, t := range []time.Time{atime, mtime} {
		if ts[i], err = unix.TimeToTimespec(t); err != nil {
			return err
		}
	}
	return unix.UtimesNanoAt(int(parent.Fd()), leaf, ts, unix.AT_SYMLINK_NOFOLLOW)
}
