package libgen

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
)

// A Windows shell link (.lnk), as [MS-SHLLINK] describes it: the header with
// the target's times, size and attributes; the shell's ID list for the
// target; the LinkInfo that records the volume it was on; the strings; and the
// link-tracking block with the machine and object ids. That is what a link
// parser walks and what a forensic tool reports from one — where the target
// was, when it was made and changed, on which volume and on which machine.
//
// Like the PE writer, this is a file for a parser to read. Explorer will
// resolve it, and what it resolves to is only a path.

// lnkCLSID is the class id every shell link header carries; [MS-SHLLINK]
// fixes it.
var lnkCLSID = MustGUID("{00021401-0000-0000-C000-000000000046}")

// myComputer is the root of every local target's ID list.
var myComputer = MustGUID("{20D04FE0-3AEA-1069-A2D8-08002B30309D}")

// LinkFlags bits used here.
const (
	lnkHasLinkTargetIDList = 0x00000001
	lnkHasLinkInfo         = 0x00000002
	lnkHasName             = 0x00000004
	lnkHasRelativePath     = 0x00000008
	lnkHasWorkingDir       = 0x00000010
	lnkHasArguments        = 0x00000020
	lnkHasIconLocation     = 0x00000040
	lnkIsUnicode           = 0x00000080
)

// FILE_ATTRIBUTE_* values a link records for its target.
var lnkAttributeBits = map[string]uint32{
	"readonly":  0x0001,
	"hidden":    0x0002,
	"system":    0x0004,
	"directory": 0x0010,
	"archive":   0x0020,
}

// LNKAttributes is every target attribute a link can record, besides the
// directory bit, which follows from LNKSpec.Dir.
var LNKAttributes = []string{"readonly", "hidden", "system", "archive"}

// LNKShowCommands is the closed set of window states a link asks for.
var LNKShowCommands = []string{"normal", "maximized", "minimized"}

var lnkShowCommand = map[string]uint32{"normal": 1, "maximized": 3, "minimized": 7}

// LNKDriveTypes is the closed set of drive types a link can record for a
// target on a local drive letter. A network share is recorded differently
// (as a CommonNetworkRelativeLink), which this writer does not build.
var LNKDriveTypes = []string{"fixed", "removable", "cdrom", "ramdisk"}

var lnkDriveType = map[string]uint32{"removable": 2, "fixed": 3, "cdrom": 5, "ramdisk": 6}

// MaxLNKMachineID is the longest machine name the tracking block holds: a
// NetBIOS name, NUL-terminated in 16 bytes.
const MaxLNKMachineID = 15

// LNKSpec is what a link says about its target.
type LNKSpec struct {
	// Target is the target's Windows path on a drive letter, C:\dir\file.
	Target string
	// Dir says the target is a directory.
	Dir bool
	// Arguments, WorkingDir, RelativePath, Description and IconLocation are
	// the link's strings; each empty one is left out.
	Arguments, WorkingDir, RelativePath, Description, IconLocation string
	IconIndex                                                      int32
	// ShowCommand is one of LNKShowCommands; empty is normal.
	ShowCommand string
	// DriveType is one of LNKDriveTypes; empty is fixed.
	DriveType    string
	VolumeSerial uint32
	// VolumeLabel is the label of the target's volume, ASCII; empty is none.
	VolumeLabel string
	// MachineID is the NetBIOS name of the machine the link was made on.
	MachineID string
	// Created, Accessed and Modified are the target's times as the link
	// records them.
	Created, Accessed, Modified time.Time
	// Size is the target's size; a link keeps its low 32 bits.
	Size int64
	// Attributes are the target's attributes, from LNKAttributes. With none,
	// a file is archive and a directory is just a directory.
	Attributes []string
	// MFTEntry and MFTSequence are the target's NTFS file reference, which
	// the shell item for the target's own name records.
	MFTEntry    uint64
	MFTSequence uint16
}

// CheckLNKTarget reports whether target is a path a link can point at: an
// absolute Windows path on a drive letter, with no empty component and no
// character Windows forbids in a name.
func CheckLNKTarget(target string) error {
	_, _, err := splitWindowsPath(target)
	return err
}

// splitWindowsPath splits C:\a\b into its drive and components.
func splitWindowsPath(p string) (drive byte, parts []string, err error) {
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' || !isDriveLetter(p[0]) {
		return 0, nil, fmt.Errorf("%q is not an absolute Windows path on a drive letter (want C:\\dir\\file)", p)
	}
	rest := strings.TrimSuffix(p[3:], `\`)
	if rest == "" {
		return upper(p[0]), nil, nil
	}
	for _, c := range strings.Split(rest, `\`) {
		if c == "" || c == "." || c == ".." {
			return 0, nil, fmt.Errorf("%q has an empty, . or .. component", p)
		}
		if i := strings.IndexFunc(c, func(r rune) bool { return r < 0x20 || strings.ContainsRune(`<>:"/|?*`, r) }); i >= 0 {
			return 0, nil, fmt.Errorf("%q: component %q holds %q, which Windows does not allow in a name", p, c, c[i])
		}
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return 0, nil, fmt.Errorf("%q: component %q ends in a dot or space", p, c)
		}
		parts = append(parts, c)
	}
	return upper(p[0]), parts, nil
}

func isDriveLetter(b byte) bool { return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' }

func upper(b byte) byte {
	if 'a' <= b && b <= 'z' {
		return b - 'a' + 'A'
	}
	return b
}

// BuildLNK writes the shell link. Every value a real link carries that the
// spec does not give — the tracking block's object ids — is drawn from s.
func BuildLNK(spec LNKSpec, s *prng.Stream) ([]byte, error) {
	drive, parts, err := splitWindowsPath(spec.Target)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 && !spec.Dir {
		return nil, fmt.Errorf("%q is a drive's root, which is a directory; set the target's type to dir", spec.Target)
	}
	attrs, err := lnkAttributes(spec)
	if err != nil {
		return nil, err
	}
	show, ok := lnkShowCommand[or(spec.ShowCommand, "normal")]
	if !ok {
		return nil, fmt.Errorf("show command %q (want one of: %s)", spec.ShowCommand, strings.Join(LNKShowCommands, ", "))
	}
	driveType, ok := lnkDriveType[or(spec.DriveType, "fixed")]
	if !ok {
		return nil, fmt.Errorf("drive type %q (want one of: %s)", spec.DriveType, strings.Join(LNKDriveTypes, ", "))
	}
	if err := checkLNKStrings(spec); err != nil {
		return nil, err
	}

	flags := uint32(lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkIsUnicode)
	strs := []struct {
		flag  uint32
		value string
	}{
		{lnkHasName, spec.Description},
		{lnkHasRelativePath, spec.RelativePath},
		{lnkHasWorkingDir, spec.WorkingDir},
		{lnkHasArguments, spec.Arguments},
		{lnkHasIconLocation, spec.IconLocation},
	}
	for _, sd := range strs {
		if sd.value != "" {
			flags |= sd.flag
		}
	}

	out := make([]byte, 0, 1024)
	out = binary.LittleEndian.AppendUint32(out, 0x4C)
	out = appendGUID(out, lnkCLSID)
	out = binary.LittleEndian.AppendUint32(out, flags)
	out = binary.LittleEndian.AppendUint32(out, attrs)
	out = binary.LittleEndian.AppendUint64(out, filetime(spec.Created))
	out = binary.LittleEndian.AppendUint64(out, filetime(spec.Accessed))
	out = binary.LittleEndian.AppendUint64(out, filetime(spec.Modified))
	out = binary.LittleEndian.AppendUint32(out, uint32(spec.Size))
	out = binary.LittleEndian.AppendUint32(out, uint32(spec.IconIndex))
	out = binary.LittleEndian.AppendUint32(out, show)
	out = append(out, make([]byte, 2+2+4+4)...) // HotKey, Reserved1-3

	out = append(out, lnkIDList(drive, parts, spec, attrs)...)
	out = append(out, lnkLinkInfo(spec.Target, driveType, spec.VolumeSerial, spec.VolumeLabel)...)
	for _, sd := range strs {
		if sd.value != "" {
			u := utf16.Encode([]rune(sd.value))
			out = binary.LittleEndian.AppendUint16(out, uint16(len(u)))
			out = append(out, utf16le(sd.value)...)
		}
	}
	out = append(out, lnkTracker(spec, s)...)
	return binary.LittleEndian.AppendUint32(out, 0), nil // TerminalBlock
}

func lnkAttributes(spec LNKSpec) (uint32, error) {
	var a uint32
	for _, name := range spec.Attributes {
		bit, ok := lnkAttributeBits[name]
		if !ok || name == "directory" {
			return 0, fmt.Errorf("target attribute %q (want any of: %s)", name, strings.Join(LNKAttributes, ", "))
		}
		a |= bit
	}
	if spec.Dir {
		a |= lnkAttributeBits["directory"]
	} else if a == 0 {
		a = lnkAttributeBits["archive"]
	}
	return a, nil
}

// checkLNKStrings refuses what the fixed-size and counted fields cannot hold.
func checkLNKStrings(spec LNKSpec) error {
	if len(spec.MachineID) > MaxLNKMachineID || !isASCII(spec.MachineID) {
		return fmt.Errorf("machine id %q: at most %d ASCII characters, as a NetBIOS name", spec.MachineID, MaxLNKMachineID)
	}
	if !isASCII(spec.VolumeLabel) || len(spec.VolumeLabel) > 32 {
		return fmt.Errorf("volume label %q: at most 32 ASCII characters", spec.VolumeLabel)
	}
	for _, v := range []string{spec.Arguments, spec.WorkingDir, spec.RelativePath, spec.Description, spec.IconLocation} {
		if len(utf16.Encode([]rune(v))) > 0xFFFF {
			return fmt.Errorf("a link string is longer than the 65535 UTF-16 units its count can say")
		}
	}
	return nil
}

// lnkIDList is the LinkTargetIDList: My Computer, the drive, then one file
// entry per component of the path. The last component is the target itself,
// carrying its size, times and attributes; the folders above it carry the
// directory attribute and the target's modification time, as nothing else is
// known about them.
func lnkIDList(drive byte, parts []string, spec LNKSpec, attrs uint32) []byte {
	var items [][]byte
	root := []byte{0x1F, 0x50}
	items = append(items, appendGUID(root, myComputer))
	vol := append([]byte{0x2F, drive, ':', '\\', 0}, make([]byte, 18)...)
	items = append(items, vol)
	for i, name := range parts {
		last := i == len(parts)-1
		item := fileEntry{name: name, dir: true, attrs: lnkAttributeBits["directory"], modified: spec.Modified, created: spec.Modified, accessed: spec.Modified}
		if last {
			item = fileEntry{
				name: name, dir: spec.Dir, attrs: attrs, size: uint32(spec.Size),
				modified: spec.Modified, created: spec.Created, accessed: spec.Accessed,
				mftEntry: spec.MFTEntry, mftSeq: spec.MFTSequence,
			}
		}
		items = append(items, item.bytes())
	}

	var list []byte
	for _, it := range items {
		list = binary.LittleEndian.AppendUint16(list, uint16(len(it)+2))
		list = append(list, it...)
	}
	list = binary.LittleEndian.AppendUint16(list, 0) // TerminalID
	return append(binary.LittleEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// fileEntry is a file entry shell item: the 8.3 name, size, modification time
// and attributes, then a 0xBEEF0004 extension block (version 9, as Windows 8
// and later write it) with the creation and access times, the NTFS file
// reference and the long name.
type fileEntry struct {
	name                        string
	dir                         bool
	attrs                       uint32
	size                        uint32
	modified, created, accessed time.Time
	mftEntry                    uint64
	mftSeq                      uint16
}

func (f fileEntry) bytes() []byte {
	class := byte(0x32)
	if f.dir {
		class = 0x31
	}
	b := []byte{class, 0}
	b = binary.LittleEndian.AppendUint32(b, f.size)
	b = appendDOSTime(b, f.modified)
	b = binary.LittleEndian.AppendUint16(b, uint16(f.attrs))
	b = append(b, shortName(f.name)...)
	b = append(b, 0)
	// The item, counted from its size field, keeps the extension block
	// 16-bit aligned.
	if (len(b)+2)%2 != 0 {
		b = append(b, 0)
	}
	extOffset := uint16(len(b) + 2)

	ext := binary.LittleEndian.AppendUint16(nil, 9) // version
	ext = binary.LittleEndian.AppendUint32(ext, 0xBEEF0004)
	ext = appendDOSTime(ext, f.created)
	ext = appendDOSTime(ext, f.accessed)
	ext = binary.LittleEndian.AppendUint16(ext, 0x2E) // Windows 8 and later
	ext = binary.LittleEndian.AppendUint16(ext, 0)
	ext = binary.LittleEndian.AppendUint64(ext, f.mftEntry&0xFFFFFFFFFFFF|uint64(f.mftSeq)<<48)
	ext = binary.LittleEndian.AppendUint64(ext, 0)
	ext = binary.LittleEndian.AppendUint16(ext, 0) // no localised name
	ext = binary.LittleEndian.AppendUint32(ext, 0)
	ext = binary.LittleEndian.AppendUint32(ext, 0)
	ext = append(ext, utf16z(f.name)...)
	ext = binary.LittleEndian.AppendUint16(ext, extOffset)

	b = binary.LittleEndian.AppendUint16(b, uint16(len(ext)+2))
	return append(b, ext...)
}

// appendDOSTime writes t as a shell item does: the MS-DOS date in the low
// 16 bits and the time in the high ones. A date MS-DOS cannot hold (after
// 2107) is written as 0, which parsers read as not set, rather than wrapped
// round to a wrong one.
func appendDOSTime(b []byte, t time.Time) []byte {
	if t.IsZero() || t.UTC().Year() > 2107 {
		return binary.LittleEndian.AppendUint32(b, 0)
	}
	date, clock := dosTime(t)
	b = binary.LittleEndian.AppendUint16(b, date)
	return binary.LittleEndian.AppendUint16(b, clock)
}

// shortName is the 8.3 name Windows would give name, assuming no other name
// in its folder collides with it: the name itself, upper-cased, if it is
// already a valid 8.3 name, otherwise the first six usable characters, ~1,
// and the first three of the extension.
func shortName(name string) string {
	base, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		base, ext = name[:i], name[i+1:]
	}
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToUpper(s) {
			switch {
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("!#$%&'()-@^_`{}~", r):
				b.WriteRune(r)
			case r == ' ' || r == '.':
				// dropped, as Windows drops them
			default:
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	cb, ce := clean(base), clean(ext)
	exact := strings.ToUpper(base) == cb && strings.ToUpper(ext) == ce
	if exact && len(cb) >= 1 && len(cb) <= 8 && len(ce) <= 3 && strings.Count(name, ".") <= 1 {
		return joinShort(cb, ce)
	}
	if len(cb) > 6 {
		cb = cb[:6]
	}
	if cb == "" {
		cb = "_"
	}
	if len(ce) > 3 {
		ce = ce[:3]
	}
	return joinShort(cb+"~1", ce)
}

func joinShort(base, ext string) string {
	if ext == "" {
		return base
	}
	return base + "." + ext
}

// lnkLinkInfo records the volume the target was on and its path there. A
// path that is not ASCII is also written in UTF-16, in the header's optional
// Unicode fields; the ANSI copy then has ? for each character it cannot
// carry, as Windows' own conversion would.
func lnkLinkInfo(target string, driveType, serial uint32, label string) []byte {
	unicode := !isASCII(target)
	header := uint32(0x1C)
	if unicode {
		header = 0x24
	}

	volume := binary.LittleEndian.AppendUint32(nil, 0) // size, filled in below
	volume = binary.LittleEndian.AppendUint32(volume, driveType)
	volume = binary.LittleEndian.AppendUint32(volume, serial)
	volume = binary.LittleEndian.AppendUint32(volume, 0x10) // label offset
	volume = append(volume, label...)
	volume = append(volume, 0)
	binary.LittleEndian.PutUint32(volume, uint32(len(volume)))

	base := append([]byte(ansi(target)), 0)
	suffix := []byte{0}

	volOff := header
	baseOff := volOff + uint32(len(volume))
	suffixOff := baseOff + uint32(len(base))
	body := slices.Concat(volume, base, suffix)
	var baseUni, suffixUni []byte
	if unicode {
		baseUni = utf16z(target)
		suffixUni = []byte{0, 0}
		body = slices.Concat(body, baseUni, suffixUni)
	}

	h := binary.LittleEndian.AppendUint32(nil, header+uint32(len(body)))
	h = binary.LittleEndian.AppendUint32(h, header)
	h = binary.LittleEndian.AppendUint32(h, 0x1) // VolumeIDAndLocalBasePath
	h = binary.LittleEndian.AppendUint32(h, volOff)
	h = binary.LittleEndian.AppendUint32(h, baseOff)
	h = binary.LittleEndian.AppendUint32(h, 0) // no CommonNetworkRelativeLink
	h = binary.LittleEndian.AppendUint32(h, suffixOff)
	if unicode {
		baseUniOff := suffixOff + uint32(len(suffix))
		h = binary.LittleEndian.AppendUint32(h, baseUniOff)
		h = binary.LittleEndian.AppendUint32(h, baseUniOff+uint32(len(baseUni)))
	}
	return append(h, body...)
}

// ansi is s with every character outside ASCII replaced by ?, which is what
// the ANSI fields of a link hold for a name the code page cannot spell.
func ansi(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x80 {
			return '?'
		}
		return r
	}, s)
}

// lnkTracker is the TrackerDataBlock the distributed link-tracking service
// writes: the machine's NetBIOS name and the volume and object ids, twice
// (current and at birth, the same for a link that has not moved). The volume
// id is random, as an NTFS volume's is; the object id is time-based, dated
// when the target was created, with the node a tool reports as a MAC address.
func lnkTracker(spec LNKSpec, s *prng.Stream) []byte {
	var volume GUID
	copy(volume[:], s.Bytes(16))
	volume[6] = volume[6]&0x0F | 0x40
	volume[8] = volume[8]&0x3F | 0x80
	object := guidV1(spec.Created, s)

	b := binary.LittleEndian.AppendUint32(nil, 0x60)
	b = binary.LittleEndian.AppendUint32(b, 0xA0000003)
	b = binary.LittleEndian.AppendUint32(b, 0x58)
	b = binary.LittleEndian.AppendUint32(b, 0)
	machine := make([]byte, 16)
	copy(machine, spec.MachineID)
	b = append(b, machine...)
	for range 2 {
		b = appendGUID(b, volume)
		b = appendGUID(b, object)
	}
	return b
}

// ParseVolumeSerial reads a volume serial number as Windows prints it,
// 1A2B-3C4D, or as eight hex digits.
func ParseVolumeSerial(s string) (uint32, error) {
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 8 || (strings.Contains(s, "-") && (len(s) != 9 || s[4] != '-')) {
		return 0, fmt.Errorf("volume serial %q (want eight hex digits, as 1A2B-3C4D or 1A2B3C4D)", s)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return 0, fmt.Errorf("volume serial %q (want eight hex digits, as 1A2B-3C4D or 1A2B3C4D)", s)
	}
	return binary.BigEndian.Uint32(b), nil
}
