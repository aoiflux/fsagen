package libgen

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libntfs"
)

// parsedLNK is what lnkReader recovers from a link, walking it the way a
// parser does: every structure from the sizes and offsets the link itself
// gives, never from where this package happens to put things.
type parsedLNK struct {
	flags, attrs, show       uint32
	created, accessed, wrote uint64
	size                     uint32
	iconIndex                int32
	items                    [][]byte
	driveType, serial        uint32
	label, basePath          string
	basePathUnicode          string
	strs                     []string
	machine                  string
	droids                   [4]GUID
}

func readU16(t *testing.T, b []byte, off int) uint16 {
	t.Helper()
	if off+2 > len(b) {
		t.Fatalf("read u16 at %d past the end (%d bytes)", off, len(b))
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func readU32(t *testing.T, b []byte, off int) uint32 {
	t.Helper()
	if off+4 > len(b) {
		t.Fatalf("read u32 at %d past the end (%d bytes)", off, len(b))
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func wstring(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// readGUID reads a GUID in its on-disk mixed-endian layout.
func readGUID(b []byte) GUID {
	var g GUID
	binary.BigEndian.PutUint32(g[0:4], binary.LittleEndian.Uint32(b[0:4]))
	binary.BigEndian.PutUint16(g[4:6], binary.LittleEndian.Uint16(b[4:6]))
	binary.BigEndian.PutUint16(g[6:8], binary.LittleEndian.Uint16(b[6:8]))
	copy(g[8:], b[8:16])
	return g
}

func lnkReader(t *testing.T, b []byte) parsedLNK {
	t.Helper()
	var p parsedLNK
	if readU32(t, b, 0) != 0x4C {
		t.Fatalf("header size %#x, want 0x4C", readU32(t, b, 0))
	}
	if g := readGUID(b[4:]); g != lnkCLSID {
		t.Fatalf("link CLSID %s", g)
	}
	p.flags, p.attrs = readU32(t, b, 20), readU32(t, b, 24)
	p.created = binary.LittleEndian.Uint64(b[28:])
	p.accessed = binary.LittleEndian.Uint64(b[36:])
	p.wrote = binary.LittleEndian.Uint64(b[44:])
	p.size = readU32(t, b, 52)
	p.iconIndex = int32(readU32(t, b, 56))
	p.show = readU32(t, b, 60)
	off := 0x4C

	if p.flags&lnkHasLinkTargetIDList != 0 {
		listSize := int(readU16(t, b, off))
		end := off + 2 + listSize
		off += 2
		for {
			n := int(readU16(t, b, off))
			if n == 0 {
				off += 2
				break
			}
			p.items = append(p.items, b[off+2:off+n])
			off += n
		}
		if off != end {
			t.Fatalf("ID list ends at %d, its size says %d", off, end)
		}
	}
	if p.flags&lnkHasLinkInfo != 0 {
		info := b[off:]
		total := int(readU32(t, info, 0))
		header := readU32(t, info, 4)
		if readU32(t, info, 8)&1 == 0 {
			t.Fatal("LinkInfo lacks VolumeIDAndLocalBasePath")
		}
		vol := info[readU32(t, info, 12):]
		p.driveType, p.serial = readU32(t, vol, 4), readU32(t, vol, 8)
		p.label = cstring(vol[readU32(t, vol, 12):])
		p.basePath = cstring(info[readU32(t, info, 16):])
		if cstring(info[readU32(t, info, 24):]) != "" {
			t.Error("common path suffix is not empty")
		}
		if header >= 0x24 {
			p.basePathUnicode = wstring(info[readU32(t, info, 28):])
		}
		off += total
	}
	for _, f := range []uint32{lnkHasName, lnkHasRelativePath, lnkHasWorkingDir, lnkHasArguments, lnkHasIconLocation} {
		if p.flags&f == 0 {
			p.strs = append(p.strs, "")
			continue
		}
		n := int(readU16(t, b, off))
		p.strs = append(p.strs, wstring(append(append([]byte(nil), b[off+2:off+2+2*n]...), 0, 0)))
		off += 2 + 2*n
	}
	// Extra data: blocks until the terminal one.
	for {
		size := int(readU32(t, b, off))
		if size < 4 {
			off += 4
			break
		}
		if sig := readU32(t, b, off+4); sig == 0xA0000003 {
			blk := b[off : off+size]
			if size != 0x60 || readU32(t, blk, 8) != 0x58 {
				t.Fatalf("tracker block size %#x length %#x", size, readU32(t, blk, 8))
			}
			p.machine = cstring(blk[16:32])
			for i := range p.droids {
				p.droids[i] = readGUID(blk[32+16*i:])
			}
		}
		off += size
	}
	if off != len(b) {
		t.Fatalf("link is %d bytes, the structures account for %d", len(b), off)
	}
	return p
}

// fileEntryName reads a file entry shell item's 8.3 name, and the long name
// from its 0xBEEF0004 block, found through the offset the block's last two
// bytes give.
func fileEntryName(t *testing.T, item []byte) (class byte, short, long string) {
	t.Helper()
	full := append(binary.LittleEndian.AppendUint16(nil, uint16(len(item)+2)), item...)
	extOff := int(readU16(t, full, len(full)-2))
	ext := full[extOff:]
	if readU16(t, ext, 2) != 9 || readU32(t, ext, 4) != 0xBEEF0004 {
		t.Fatalf("extension block at %d: version %d signature %#x", extOff, readU16(t, ext, 2), readU32(t, ext, 4))
	}
	if int(readU16(t, ext, 0)) != len(ext) {
		t.Fatalf("extension block size %d, %d bytes left in the item", readU16(t, ext, 0), len(ext))
	}
	return item[0], cstring(item[12:]), wstring(ext[46:])
}

func sampleLNKSpec() LNKSpec {
	created := time.Date(2024, 3, 15, 9, 30, 12, 345678900, time.UTC)
	return LNKSpec{
		Target:       `C:\Users\Public\Long Folder Name\report.final.docx`,
		Arguments:    "/q --open",
		WorkingDir:   `C:\Users\Public`,
		RelativePath: `..\Long Folder Name\report.final.docx`,
		Description:  "Quarterly report",
		IconLocation: `C:\Windows\System32\shell32.dll`,
		IconIndex:    -3,
		ShowCommand:  "maximized",
		DriveType:    "removable",
		VolumeSerial: 0x1A2B3C4D,
		VolumeLabel:  "USBSTICK",
		MachineID:    "DESKTOP-LAB01",
		Created:      created,
		Accessed:     created.Add(time.Hour),
		Modified:     created.Add(2 * time.Hour),
		Size:         0x1_2345_6789,
		Attributes:   []string{"hidden", "readonly"},
		MFTEntry:     12345,
		MFTSequence:  3,
	}
}

// TestLNKRoundTrip: everything the spec says is in the link where a parser
// looks for it — header fields, times to 100 ns, the ID list down to the
// target's long name, the volume, the strings and the tracking block — and
// the link accounts for every one of its bytes.
func TestLNKRoundTrip(t *testing.T) {
	spec := sampleLNKSpec()
	data, err := BuildLNK(spec, prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	p := lnkReader(t, data)

	wantFlags := uint32(lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkIsUnicode | lnkHasName | lnkHasRelativePath | lnkHasWorkingDir | lnkHasArguments | lnkHasIconLocation)
	if p.flags != wantFlags {
		t.Errorf("flags %#x, want %#x", p.flags, wantFlags)
	}
	if p.attrs != 0x0001|0x0002 {
		t.Errorf("attributes %#x, want readonly|hidden", p.attrs)
	}
	for name, got := range map[string]struct {
		v    uint64
		want time.Time
	}{"created": {p.created, spec.Created}, "accessed": {p.accessed, spec.Accessed}, "modified": {p.wrote, spec.Modified}} {
		if !libntfs.FiletimeToTime(got.v).Equal(got.want) {
			t.Errorf("%s %v, want %v", name, libntfs.FiletimeToTime(got.v), got.want)
		}
	}
	if p.size != 0x2345_6789 || p.iconIndex != -3 || p.show != 3 {
		t.Errorf("size %#x icon %d show %d", p.size, p.iconIndex, p.show)
	}

	if len(p.items) != 2+4 {
		t.Fatalf("%d ID list items, want My Computer, the drive and four components", len(p.items))
	}
	if p.items[0][0] != 0x1F || readGUID(p.items[0][2:]) != myComputer {
		t.Errorf("first item is not My Computer: % x", p.items[0])
	}
	if p.items[1][0] != 0x2F || cstring(p.items[1][1:]) != `C:\` {
		t.Errorf("second item is not drive C: % x", p.items[1])
	}
	want := []struct {
		class       byte
		short, long string
	}{
		{0x31, "USERS", "Users"},
		{0x31, "PUBLIC", "Public"},
		{0x31, "LONGFO~1", "Long Folder Name"},
		{0x32, "REPORT~1.DOC", "report.final.docx"},
	}
	for i, w := range want {
		class, short, long := fileEntryName(t, p.items[2+i])
		if class != w.class || short != w.short || long != w.long {
			t.Errorf("item %d = %#x %q %q, want %#x %q %q", 2+i, class, short, long, w.class, w.short, w.long)
		}
	}
	target := p.items[len(p.items)-1]
	if binary.LittleEndian.Uint32(target[2:]) != 0x2345_6789 {
		t.Errorf("target item size %#x", binary.LittleEndian.Uint32(target[2:]))
	}

	if p.driveType != 2 || p.serial != 0x1A2B3C4D || p.label != "USBSTICK" || p.basePath != spec.Target || p.basePathUnicode != "" {
		t.Errorf("link info: type %d serial %#x label %q path %q unicode %q", p.driveType, p.serial, p.label, p.basePath, p.basePathUnicode)
	}
	wantStrs := []string{spec.Description, spec.RelativePath, spec.WorkingDir, spec.Arguments, spec.IconLocation}
	for i := range wantStrs {
		if p.strs[i] != wantStrs[i] {
			t.Errorf("string %d = %q, want %q", i, p.strs[i], wantStrs[i])
		}
	}

	if p.machine != "DESKTOP-LAB01" {
		t.Errorf("machine %q", p.machine)
	}
	if p.droids[0] != p.droids[2] || p.droids[1] != p.droids[3] {
		t.Error("birth droids differ from current ones for a link that never moved")
	}
	if v := p.droids[1][6] >> 4; v != 1 {
		t.Errorf("object id is version %d, want 1 (time-based)", v)
	}
	if got := guidV1Time(p.droids[1]); !got.Equal(spec.Created.Truncate(100 * time.Nanosecond)) {
		t.Errorf("object id is dated %v, want the target's creation %v", got, spec.Created)
	}
}

// guidV1Time decodes the time a version 1 GUID carries.
func guidV1Time(g GUID) time.Time {
	ticks := uint64(binary.BigEndian.Uint32(g[0:4])) |
		uint64(binary.BigEndian.Uint16(g[4:6]))<<32 |
		uint64(binary.BigEndian.Uint16(g[6:8])&0x0FFF)<<48
	ticks -= gregorianToUnix
	return time.Unix(int64(ticks/10_000_000), int64(ticks%10_000_000)*100).UTC()
}

// TestLNKMinimalAndUnicode: a link with nothing but a target carries only the
// ID list and LinkInfo; a directory target is a folder item with the
// directory attribute; a path outside ASCII gets the Unicode LinkInfo fields,
// with ? in the ANSI copy.
func TestLNKMinimalAndUnicode(t *testing.T) {
	data, err := BuildLNK(LNKSpec{Target: `D:\Données\été`, Dir: true}, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	p := lnkReader(t, data)
	if p.flags != lnkHasLinkTargetIDList|lnkHasLinkInfo|lnkIsUnicode {
		t.Errorf("flags %#x", p.flags)
	}
	if p.attrs != 0x10 {
		t.Errorf("attributes %#x, want directory only", p.attrs)
	}
	if p.show != 1 || p.driveType != 3 {
		t.Errorf("show %d drive type %d, want normal and fixed by default", p.show, p.driveType)
	}
	if p.basePath != `D:\Donn?es\?t?` || p.basePathUnicode != `D:\Données\été` {
		t.Errorf("ANSI path %q, Unicode path %q", p.basePath, p.basePathUnicode)
	}
	class, _, long := fileEntryName(t, p.items[len(p.items)-1])
	if class != 0x31 || long != "été" {
		t.Errorf("target item %#x %q", class, long)
	}

	root, err := BuildLNK(LNKSpec{Target: `E:\`, Dir: true}, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	if p := lnkReader(t, root); len(p.items) != 2 || p.basePath != `E:\` {
		t.Errorf("drive root: %d items, path %q", len(p.items), p.basePath)
	}
}

// TestLNKDeterministic: the same spec and stream give the same bytes, and the
// stream is what the tracking block's ids come from.
func TestLNKDeterministic(t *testing.T) {
	a, _ := BuildLNK(sampleLNKSpec(), prng.Root(7).Stream())
	b, _ := BuildLNK(sampleLNKSpec(), prng.Root(7).Stream())
	c, _ := BuildLNK(sampleLNKSpec(), prng.Root(8).Stream())
	if !bytes.Equal(a, b) {
		t.Error("same spec and seed, different links")
	}
	if bytes.Equal(a, c) {
		t.Error("a different seed left the tracking ids alone")
	}
}

// TestLNKRefusals: what a link cannot express is an error, not a guess.
func TestLNKRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec LNKSpec
		want string
	}{
		{"relative", LNKSpec{Target: `Users\x`}, "not an absolute Windows path"},
		{"forward slash", LNKSpec{Target: `C:/Users/x`}, "not an absolute Windows path"},
		{"unc", LNKSpec{Target: `\\server\share\x`}, "not an absolute Windows path"},
		{"empty component", LNKSpec{Target: `C:\Users\\x`}, "empty"},
		{"dot dot", LNKSpec{Target: `C:\Users\..\x`}, "empty, . or .."},
		{"bad char", LNKSpec{Target: `C:\Users\a?b`}, "does not allow"},
		{"trailing dot", LNKSpec{Target: `C:\Users\a.`}, "ends in a dot"},
		{"root as file", LNKSpec{Target: `C:\`}, "drive's root"},
		{"attribute", LNKSpec{Target: `C:\a`, Attributes: []string{"compressed"}}, "target attribute"},
		{"directory attribute", LNKSpec{Target: `C:\a`, Attributes: []string{"directory"}}, "target attribute"},
		{"show", LNKSpec{Target: `C:\a`, ShowCommand: "hidden"}, "show command"},
		{"drive", LNKSpec{Target: `C:\a`, DriveType: "network"}, "drive type"},
		{"machine", LNKSpec{Target: `C:\a`, MachineID: "A-NAME-TOO-LONG-1"}, "machine id"},
		{"label", LNKSpec{Target: `C:\a`, VolumeLabel: "Étiquette"}, "volume label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildLNK(tc.spec, prng.Root(1).Stream())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestShortName: the 8.3 names a link records for each component.
func TestShortName(t *testing.T) {
	for in, want := range map[string]string{
		"Users":             "USERS",
		"NTUSER.DAT":        "NTUSER.DAT",
		"Program Files":     "PROGRA~1",
		"report.final.docx": "REPORT~1.DOC",
		"a+b.txt":           "A_B~1.TXT",
		"setup.exe":         "SETUP.EXE",
		"Long Folder Name":  "LONGFO~1",
		".hidden":           "HIDDEN~1",
	} {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseVolumeSerial: both ways Windows prints a serial, and nothing else.
func TestParseVolumeSerial(t *testing.T) {
	for in, want := range map[string]uint32{"1A2B-3C4D": 0x1A2B3C4D, "deadbeef": 0xDEADBEEF} {
		if got, err := ParseVolumeSerial(in); err != nil || got != want {
			t.Errorf("%q = %#x, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1A2B3C4", "1A2B-3C4DE", "1A-2B3C4D", "ZZZZZZZZ"} {
		if _, err := ParseVolumeSerial(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestFiletime: libgen writes FILETIMEs with libntfs, and relies on its
// epoch, its 100 ns resolution, zero for unset, and MaxFiletime being the
// largest count every parser reads.
func TestFiletime(t *testing.T) {
	if libntfs.TimeToFiletime(time.Time{}) != 0 || libntfs.TimeToFiletime(MinFiletime) != 0 {
		t.Error("zero time or the epoch is not 0")
	}
	unix := time.Unix(0, 0)
	if libntfs.TimeToFiletime(unix) != 116444736000000000 {
		t.Errorf("1970 = %d", libntfs.TimeToFiletime(unix))
	}
	if got := libntfs.FiletimeToTime(libntfs.TimeToFiletime(time.Date(2024, 1, 2, 3, 4, 5, 678912345, time.UTC))); !got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 678912300, time.UTC)) {
		t.Errorf("round trip %v", got)
	}
	if got := libntfs.TimeToFiletime(MaxFiletime); got != 1<<63-1 {
		t.Errorf("MaxFiletime = %d, want the largest positive 64-bit count", got)
	}
}
