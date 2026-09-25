//go:build linux

package sandbox

import (
	"os"
	"syscall"
	"time"
)

const noatime = syscall.O_NOATIME

func statTimes(fi os.FileInfo) Times {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Times{}
	}
	return Times{Atime: time.Unix(st.Atim.Unix()).UTC(), Ctime: time.Unix(st.Ctim.Unix()).UTC()}
}
