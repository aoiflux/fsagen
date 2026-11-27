package libgen

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/libntfs"
)

// A Recycle Bin index file ($I...): what Windows writes beside a file it moves
// to $Recycle.Bin\<SID>\, renamed $R... with the same six characters and
// extension. Two versions exist, both little-endian:
//
//	0x00  int64   version: 1 (Vista to 8.1) or 2 (Windows 10 and 11)
//	0x08  int64   the deleted file's size
//	0x10  FILETIME when it was deleted
//	v1: 0x18  the original path, UTF-16, in a fixed 520-byte (260-unit) field
//	v2: 0x18  uint32 the path's length in UTF-16 units, its NUL included,
//	    0x1C  the original path, UTF-16, NUL-terminated
//
// RBCmd, rifiuti2 and Autopsy's Recycle Bin module read both.

// RecycleVersions is the closed set of index formats written.
var RecycleVersions = []string{"win10", "vista"}

var recycleVersion = map[string]uint64{"win10": 2, "vista": 1}

// maxRecycleV1Path is how many UTF-16 units of the path a version 1 file
// holds, its NUL included.
const maxRecycleV1Path = 260

// RecycleSpec is what a $I file says about one deleted file.
type RecycleSpec struct {
	Version      string // one of RecycleVersions; empty is win10
	OriginalPath string // the file's Windows path before it was deleted
	Size         int64
	Deleted      time.Time
}

// BuildRecycle writes the $I file.
func BuildRecycle(spec RecycleSpec) ([]byte, error) {
	version, ok := recycleVersion[cmp.Or(spec.Version, "win10")]
	if !ok {
		return nil, fmt.Errorf("recycle version %q (want one of: %s)", spec.Version, strings.Join(RecycleVersions, ", "))
	}
	if err := CheckWindowsPath(spec.OriginalPath); err != nil {
		return nil, err
	}
	if spec.Size < 0 {
		return nil, fmt.Errorf("a deleted file's size cannot be negative, not %d", spec.Size)
	}
	if !spec.Deleted.IsZero() && (spec.Deleted.Before(MinFiletime) || spec.Deleted.After(MaxFiletime)) {
		return nil, fmt.Errorf("deleted time %s is outside what a FILETIME holds", spec.Deleted.Format(time.RFC3339))
	}
	path := utf16z(spec.OriginalPath)
	units := len(path) / 2

	b := binary.LittleEndian.AppendUint64(nil, version)
	b = binary.LittleEndian.AppendUint64(b, uint64(spec.Size))
	b = binary.LittleEndian.AppendUint64(b, libntfs.TimeToFiletime(spec.Deleted))
	if version == 1 {
		if units > maxRecycleV1Path {
			return nil, fmt.Errorf("%q is %d UTF-16 units; a vista $I file holds at most %d", spec.OriginalPath, units-1, maxRecycleV1Path-1)
		}
		field := make([]byte, 2*maxRecycleV1Path)
		copy(field, path)
		return append(b, field...), nil
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(units))
	return append(b, path...), nil
}

// ParseRecycle reads a $I file back, as a parser would: for tests, and for
// anyone checking a corpus.
func ParseRecycle(b []byte) (RecycleSpec, error) {
	if len(b) < 0x1C {
		return RecycleSpec{}, fmt.Errorf("a $I file is at least 28 bytes, not %d", len(b))
	}
	var s RecycleSpec
	var raw []byte
	switch binary.LittleEndian.Uint64(b) {
	case 1:
		s.Version, raw = "vista", b[0x18:]
	case 2:
		n := int(binary.LittleEndian.Uint32(b[0x18:]))
		if len(b) != 0x1C+2*n {
			return RecycleSpec{}, fmt.Errorf("a $I file of %d units is %d bytes, not %d", n, 0x1C+2*n, len(b))
		}
		s.Version, raw = "win10", b[0x1C:]
	default:
		return RecycleSpec{}, fmt.Errorf("unknown $I version %d", binary.LittleEndian.Uint64(b))
	}
	s.Size = int64(binary.LittleEndian.Uint64(b[8:]))
	s.Deleted = libntfs.FiletimeToTime(binary.LittleEndian.Uint64(b[0x10:]))
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	s.OriginalPath = string(utf16.Decode(u))
	return s, nil
}
