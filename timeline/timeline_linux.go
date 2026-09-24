//go:build linux

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

func getFileTimes(info os.FileInfo) (fileStat, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStat{Atime: info.ModTime(), Mtime: info.ModTime(), Ctime: info.ModTime()}, true
	}
	return fileStat{
		Atime: timespecToTime(st.Atim),
		Mtime: timespecToTime(st.Mtim),
		Ctime: timespecToTime(st.Ctim), // inode change time, not birth
	}, true
}

func timespecToTime(ts syscall.Timespec) time.Time {
	return time.Unix(ts.Unix())
}
