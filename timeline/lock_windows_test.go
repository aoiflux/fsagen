//go:build windows

package timeline

import (
	"syscall"
	"testing"
)

// lock holds p open with no sharing, so nothing else can read it until the
// returned function runs.
func lock(t *testing.T, p string) func() {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return func() { syscall.CloseHandle(h) }
}
