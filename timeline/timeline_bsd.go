//go:build darwin || freebsd || netbsd

package timeline

import (
	"os"
	"syscall"
	"time"
)

type fileStat struct {
	Atime time.Time
	Mtime time.Time
	Ctime time.Time
}

// The BSD-derived Stat_t names its fields Atimespec/Mtimespec/Ctimespec, not
// Atim/Mtim/Ctim as Linux does, which is why this file is separate.
func getFileTimes(info os.FileInfo) (fileStat, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStat{Atime: info.ModTime(), Mtime: info.ModTime(), Ctime: info.ModTime()}, true
	}
	return fileStat{
		Atime: timespecToTime(st.Atimespec),
		Mtime: timespecToTime(st.Mtimespec),
		Ctime: timespecToTime(st.Ctimespec), // inode change time, not birth
	}, true
}

func timespecToTime(ts syscall.Timespec) time.Time {
	return time.Unix(ts.Unix())
}
