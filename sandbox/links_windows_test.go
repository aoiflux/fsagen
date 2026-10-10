//go:build windows

package sandbox

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsLinksAsWindowsMakesThem: a symlink to a directory that is not
// there yet is still a directory link, which is what Go's own Symlink
// cannot make; a file symlink is not; and a junction reads back, through
// Windows' own reparse-point query, exactly as one mklink /J makes.
func TestWindowsLinksAsWindowsMakesThem(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	fsys, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	if !fsys.LinkCaps().Junction {
		t.Skip("this volume stores no reparse points")
	}
	if fsys.LinkCaps().Sym {
		for name, isDir := range map[string]bool{"to-dir": true, "to-file": false} {
			if err := fsys.Symlink(name, "not-yet", isDir); err != nil {
				t.Fatal(err)
			}
			attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Join(dir, name)))
			if err != nil {
				t.Fatal(err)
			}
			if got := attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0; got != isDir {
				t.Errorf("%s: directory attribute %v, want %v", name, got, isDir)
			}
		}
	}
	if err := fsys.Junction("ours", "target"); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(dir, "theirs")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", theirs, filepath.Join(dir, "target")).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if a, b := reparseData(t, filepath.Join(dir, "ours")), reparseData(t, theirs); a != b {
		t.Errorf("our junction's reparse data\n%s\ndiffers from mklink's\n%s", a, b)
	}
	if m, err := fsys.Meta("ours"); err != nil || m.Link != LinkJunction || m.Target != "target" {
		t.Errorf("Meta = %+v, %v", m, err)
	}
}

// reparseData is a reparse point's data as hex, read with FSCTL_GET_REPARSE_POINT.
func reparseData(t *testing.T, path string) string {
	t.Helper()
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, maxReparseDataBuffer)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(hex.EncodeToString(buf[:n]))
}
