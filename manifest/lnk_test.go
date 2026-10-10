package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// filetimeAt reads the FILETIME at off as a time.
func filetimeAt(b []byte, off int) time.Time {
	v := binary.LittleEndian.Uint64(b[off:])
	return time.Unix(int64(v/10_000_000)-11644473600, int64(v%10_000_000)*100).UTC()
}

// TestLNKThroughManifest: a .lnk built from a manifest records the target the
// block names, dates the target with the operation's time unless the block
// says otherwise, and fills in a machine name and volume serial from the
// seed when the block gives none; libgen's tests and the conformance suite
// read the rest of the structure.
func TestLNKThroughManifest(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: Users/u/Desktop/tool.lnk
    mtime: 2024-03-15T10:00:00Z
    lnk:
      target: 'C:\Tools\tool.exe'
      arguments: --quiet
  - action: create
    path: Users/u/Desktop/pinned.lnk
    lnk:
      target: 'E:\payload\run.bat'
      machine_id: WORKSTATION7
      volume_serial: 1A2B-3C4D
      target_crtime: 2023-01-01T00:00:00Z
      target_mtime: 2023-06-01T00:00:00Z
`, nil)

	first := readOut(t, root, "Users/u/Desktop/tool.lnk")
	if binary.LittleEndian.Uint32(first) != 0x4C {
		t.Fatalf("not a shell link: % x", first[:8])
	}
	when := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)
	for _, off := range []int{28, 36, 44} {
		if got := filetimeAt(first, off); !got.Equal(when) {
			t.Errorf("header time at %d = %v, want the operation's time %v", off, got, when)
		}
	}
	if !bytes.Contains(first, []byte(`C:\Tools\tool.exe`+"\x00")) || !bytes.Contains(first, utf16le("--quiet")) {
		t.Error("the target path or the arguments are missing")
	}
	if !bytes.Contains(first, []byte("DESKTOP-")) {
		t.Error("no machine name drawn from the seed")
	}

	second := readOut(t, root, "Users/u/Desktop/pinned.lnk")
	if got := filetimeAt(second, 28); !got.Equal(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("creation %v, want the block's target_crtime", got)
	}
	if got := filetimeAt(second, 44); !got.Equal(time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("write time %v, want the block's target_mtime", got)
	}
	if !bytes.Contains(second, []byte("WORKSTATION7\x00")) || !bytes.Contains(second, binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)) {
		t.Error("the given machine name or volume serial is missing")
	}
}
