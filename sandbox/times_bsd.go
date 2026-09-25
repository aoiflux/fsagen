//go:build darwin || freebsd || netbsd

package sandbox

import (
	"os"
	"syscall"
	"time"
)

const noatime = 0

func statTimes(fi os.FileInfo) Times {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Times{}
	}
	return Times{
		Atime: time.Unix(st.Atimespec.Unix()).UTC(),
		Ctime: time.Unix(st.Ctimespec.Unix()).UTC(),
		Btime: time.Unix(st.Birthtimespec.Unix()).UTC(),
	}
}
