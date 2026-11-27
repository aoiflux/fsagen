package libgen

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestRecycleLayout(t *testing.T) {
	when := time.Date(2026, 3, 11, 9, 30, 0, 123456700, time.UTC)
	path := `C:\Users\user1\Documents\invoice.docx`
	for _, tc := range []struct {
		version string
		want    uint64
		size    int
	}{
		{"", 2, 0x1C + 2*(len(path)+1)},
		{"win10", 2, 0x1C + 2*(len(path)+1)},
		{"vista", 1, 0x18 + 520},
	} {
		b, err := BuildRecycle(RecycleSpec{Version: tc.version, OriginalPath: path, Size: 24576, Deleted: when})
		if err != nil {
			t.Fatalf("%q: %v", tc.version, err)
		}
		if len(b) != tc.size || binary.LittleEndian.Uint64(b) != tc.want {
			t.Fatalf("%q: %d bytes, version %d; want %d bytes, version %d", tc.version, len(b), binary.LittleEndian.Uint64(b), tc.size, tc.want)
		}
		got, err := ParseRecycle(b)
		if err != nil {
			t.Fatalf("%q: %v", tc.version, err)
		}
		if got.OriginalPath != path || got.Size != 24576 || !got.Deleted.Equal(when) {
			t.Fatalf("%q: read back %+v", tc.version, got)
		}
	}
}

func TestRecycleRefused(t *testing.T) {
	when := time.Date(2026, 3, 11, 9, 30, 0, 0, time.UTC)
	long := `C:\` + strings.Repeat("a", 270)
	for name, s := range map[string]RecycleSpec{
		"relative path":  {OriginalPath: `Users\x.txt`, Deleted: when},
		"negative size":  {OriginalPath: `C:\x.txt`, Size: -1, Deleted: when},
		"bad version":    {OriginalPath: `C:\x.txt`, Version: "xp", Deleted: when},
		"vista too long": {OriginalPath: long, Version: "vista", Deleted: when},
	} {
		if _, err := BuildRecycle(s); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}
