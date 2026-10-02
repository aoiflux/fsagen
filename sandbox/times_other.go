//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package sandbox

import "os"

const noatime = 0

func fsNameOf(*os.Root) string { return "" }

// Only the modification time is read on platforms without a stat reader.
func statMeta(r *os.Root, name string) (Meta, error) {
	m, _, err := lstatMeta(r, name)
	return m, err
}
