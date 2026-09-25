//go:build !windows

package timeline

import (
	"os"
	"testing"
)

// lock takes every permission away from p, so nothing but root can read it
// until the returned function runs.
func lock(t *testing.T, p string) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads files whatever their permissions")
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	return func() { os.Chmod(p, 0o644) }
}
