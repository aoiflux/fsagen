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

var defaultGranularity = Granularity{time.Microsecond, time.Microsecond, time.Microsecond, time.Microsecond}

func setTimes(r *os.Root, name string, t Times, _ TimeCaps) error {
	if t.Atime.IsZero() && t.Mtime.IsZero() {
		return nil
	}
	return r.Chtimes(name, t.Atime, t.Mtime)
}

func getTimes(r *os.Root, name string) (Times, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return Times{}, err
	}
	t := statTimes(fi)
	t.Mtime = fi.ModTime().UTC()
	return t, nil
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
