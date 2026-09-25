//go:build darwin || freebsd || netbsd

package sandbox

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

const noatime = 0

// fsNameOf is not implemented for the BSDs; the time resolution comes from
// the root's change time instead.
func fsNameOf(*os.Root) string { return "" }

// statMeta reads the four times from lstat; BSD-derived systems keep a
// birth time in Birthtimespec, which is negative where the file system has
// none.
func statMeta(r *os.Root, name string) (Meta, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return Meta{}, err
	}
	m := Meta{Times: Times{Mtime: fi.ModTime().UTC()}}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return m, nil
	}
	ts := func(t syscall.Timespec) time.Time { return time.Unix(t.Unix()).UTC() }
	m.Atime, m.Ctime = ts(st.Atimespec), ts(st.Ctimespec)
	if st.Birthtimespec.Sec >= 0 {
		m.Btime = ts(st.Birthtimespec)
	}
	m.ID = strconv.FormatUint(uint64(st.Ino), 10)
	m.UID, m.GID = int(st.Uid), int(st.Gid)
	return m, nil
}
