//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package sandbox

import (
	"os"
	"time"
)

const noatime = 0

func fsNameOf(*os.Root) string { return "" }

// Only the modification time is read on platforms without a stat reader.
func statMeta(r *os.Root, name string) (Meta, error) {
	m, _, err := lstatMeta(r, name)
	return m, err
}

// setTimesNoFollow has no call that leaves a symlink alone here, so it sets
// the times through the link; the link actions refuse such a platform.
func setTimesNoFollow(r *os.Root, name string, atime, mtime time.Time) error {
	return r.Chtimes(name, atime, mtime)
}
