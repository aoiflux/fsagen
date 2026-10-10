package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// TestPrefetchThroughManifest: a prefetch file built from a manifest is the
// MAM-compressed file Windows writes unless asked otherwise; it records the
// operation's time as the last run when the block gives none; and a volume
// the block does not describe gets a serial and creation time from the seed,
// drawn per drive, so describing one volume leaves the other's alone (the
// operation has an id, so adding the volumes key keeps its random key).
// libgen's tests and the conformance suite read the rest of the structure.
func TestPrefetchThroughManifest(t *testing.T) {
	const body = `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: Windows/Prefetch/MIMI.EXE-18453749.pf
    mtime: 2024-03-15T10:00:00Z
    prefetch:
      executable: 'E:\Tools\mimi.exe'
  - action: create
    id: plain
    path: plain/one.pf
    prefetch:
      executable: 'E:\Tools\mimi.exe'
      compressed: false
      referenced_files: ['C:\Windows\System32\advapi32.dll']%s
`
	root, _ := runManifest(t, fmtBody(body, ""), nil)

	packed := readOut(t, root, "Windows/Prefetch/MIMI.EXE-18453749.pf")
	if !bytes.HasPrefix(packed, []byte("MAM\x04")) {
		t.Fatalf("not MAM-compressed: % x", packed[:8])
	}

	plain := readOut(t, root, "plain/one.pf")
	if string(plain[4:8]) != "SCCA" || binary.LittleEndian.Uint32(plain) != 31 {
		t.Fatalf("not an uncompressed version 31 prefetch file: % x", plain[:8])
	}
	if got := filetimeAt(plain, 84+44); !got.Equal(time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("last run %v, want the operation's time", got)
	}
	if got := binary.LittleEndian.Uint32(plain[84+116:]); got != 1 {
		t.Errorf("run count %d, want 1 for the one run time", got)
	}
	cBefore, eBefore := volumeNames(t, plain)

	root, _ = runManifest(t, fmtBody(body, "\n      volumes: [{ drive: E, serial: 1A2B-3C4D, created: 2024-01-15T12:00:00Z }]"), nil)
	plain = readOut(t, root, "plain/one.pf")
	cAfter, eAfter := volumeNames(t, plain)
	if cAfter != cBefore {
		t.Errorf("describing E: changed C:'s volume from %s to %s", cBefore, cAfter)
	}
	if eAfter == eBefore || !bytes.Contains(plain, utf16le("-1a2b3c4d}")) {
		t.Errorf("E: is still %s; the given serial is not in its name", eAfter)
	}
}

// fmtBody puts extra into a manifest body's one %s.
func fmtBody(body, extra string) string {
	return string(bytes.Replace([]byte(body), []byte("%s"), []byte(extra), 1))
}

// volumeNames reads the device names of the C: and E: volumes an
// uncompressed prefetch file lists, telling them apart by the directories
// recorded on each: only E: holds \TOOLS.
func volumeNames(t *testing.T, b []byte) (c, e string) {
	t.Helper()
	le := binary.LittleEndian
	info := b[84:]
	volOff, n := le.Uint32(info[24:]), le.Uint32(info[28:])
	for i := range n {
		entry := b[volOff+96*i:]
		off, chars := le.Uint32(entry), le.Uint32(entry[4:])
		name := b[volOff+off : volOff+off+2*chars]
		dirs := b[volOff+le.Uint32(entry[28:]):]
		first := string(bytes.ReplaceAll(dirs[2:2+2*le.Uint16(dirs)], []byte{0}, nil))
		switch {
		case bytes.HasSuffix([]byte(first), []byte(`\TOOLS`)):
			e = string(bytes.ReplaceAll(name, []byte{0}, nil))
		default:
			c = string(bytes.ReplaceAll(name, []byte{0}, nil))
		}
	}
	if c == "" || e == "" {
		t.Fatalf("expected a volume for C: and one for E:, got %q and %q", c, e)
	}
	return c, e
}
