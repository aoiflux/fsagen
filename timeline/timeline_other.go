//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package timeline

import (
	"os"
	"time"
)

type fileStat struct {
	Atime time.Time
	Mtime time.Time
	Ctime time.Time
}

// Platforms without a dedicated stat reader report the modification time only;
// access and change times stay zero rather than being copied from mtime.
func getFileTimes(info os.FileInfo) (fileStat, bool) {
	return fileStat{Mtime: info.ModTime()}, true
}
