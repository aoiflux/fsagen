//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package sandbox

import "os"

const noatime = 0

// Only the modification time is read on platforms without a stat reader.
func statTimes(os.FileInfo) Times { return Times{} }
