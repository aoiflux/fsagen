//go:build !windows

package sandbox

import (
	"errors"
	"os"
)

// Elsewhere a file system either has no fixed cluster tail to keep (tmpfs,
// btrfs) or zeroes it when a file shrinks (ext4), so live slack is not
// offered at all; the pre-flight refuses it.
func probeCluster(string) int { return 0 }

func slackBestEffort(string) bool { return false }

func writeSlack(*os.Root, string, int64, []byte) error {
	return errors.New("slack cannot be written on this platform")
}
