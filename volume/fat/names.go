package fat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libfat"
)

// A short (8.3) name as a directory entry stores it: eight characters of
// base and three of extension, upper case, padded with spaces.
type shortName [11]byte

func (s shortName) String() string {
	base, ext := strings.TrimRight(string(s[:8]), " "), strings.TrimRight(string(s[8:]), " ")
	if ext == "" {
		return base
	}
	return base + "." + ext
}

// shortIllegal are the printable ASCII characters a short name cannot hold,
// beyond '.', which only separates the extension.
const shortIllegal = `"*+,/:;<=>?[\]|`

// longIllegal are the characters no FAT name can hold.
const longIllegal = `"*/:<>?\|`

// ValidName refuses a name FAT cannot store: one with a character Windows
// forbids, a control character, or more than 255 UTF-16 units.
func ValidName(name string) error {
	switch {
	case name == "" || name == "." || name == "..":
		return fmt.Errorf("%q is not a file name", name)
	case len(utf16.Encode([]rune(name))) > 255:
		return fmt.Errorf("%q is longer than the 255 characters a FAT name holds", name)
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(longIllegal, r) {
			return fmt.Errorf("%q holds %q, which a FAT name cannot", name, r)
		}
	}
	return nil
}

// shortChar reports whether a short name can hold c as it is (after upper
// casing), and what it becomes when it cannot: '_' for punctuation a short
// name forbids, nothing for a space, a dot or a character outside ASCII.
func shortChar(c rune) (rune, bool) {
	switch {
	case c <= ' ' || c == '.' || c >= 127:
		return 0, false
	case strings.ContainsRune(shortIllegal, c):
		return '_', false
	case c >= 'a' && c <= 'z':
		return c - 'a' + 'A', true
	}
	return c, true
}

// fits is how Windows stores a name that is already a valid 8.3 name: as
// itself, upper cased. bits are the NTRes flags that restore an all-lower
// base or extension; mixed says a part mixes cases, which only a long name
// keeps. ok is false when the name is not a valid 8.3 name.
func fits(name string) (s shortName, bits byte, mixed, ok bool) {
	base, ext, dotted := strings.Cut(name, ".")
	if dotted && strings.Contains(ext, ".") || len(base) < 1 || len(base) > 8 || len(ext) > 3 || dotted && ext == "" {
		return s, 0, false, false
	}
	for i := range s {
		s[i] = ' '
	}
	part := func(p string, at int, lower byte) bool {
		upper, low := false, false
		for i, c := range p {
			u, valid := shortChar(c)
			if !valid {
				return false
			}
			upper = upper || c >= 'A' && c <= 'Z'
			low = low || c >= 'a' && c <= 'z'
			s[at+i] = byte(u)
		}
		switch {
		case upper && low:
			mixed = true
		case low:
			bits |= lower
		}
		return true
	}
	if !part(base, 0, libfat.NTResLowerBase) || !part(ext, 8, libfat.NTResLowerExt) {
		return s, 0, false, false
	}
	if mixed {
		bits = 0
	}
	return s, bits, mixed, true
}

// errNoShortName is returned when a million tries find no free short name,
// where Windows also gives up.
var errNoShortName = errors.New("no free short name")

// generate makes the short name Windows gives a long name, the first that
// taken does not report as in use: up to six characters of the name, then
// ~1 to ~4; after that two characters, four hex digits of a checksum of
// the name, and ~1 on. A base of two characters or fewer takes the
// checksum at once. This is the algorithm of Windows' RtlGenerate8dot3Name,
// whose checksum was matched against names Windows made itself.
func generate(name string, taken func(shortName) bool) (shortName, error) {
	trimmed := strings.TrimLeft(name, ".")
	dot := strings.LastIndexByte(trimmed, '.')
	if dot < 0 {
		dot = len(trimmed)
	}
	var base, ext []rune
	for _, c := range trimmed[:dot] {
		if len(base) == 6 {
			break
		}
		if u, _ := shortChar(c); u != 0 {
			base = append(base, u)
		}
	}
	if dot < len(trimmed) {
		for _, c := range trimmed[dot+1:] {
			if len(ext) == 3 {
				break
			}
			if u, _ := shortChar(c); u != 0 {
				ext = append(ext, u)
			}
		}
	}
	summed := false
	if len(base) <= 2 {
		base = append(base, []rune(hex4(checksum(name)))...)
		summed = true
	}
	for index := 1; index < 1_000_000; index++ {
		if index > 4 && !summed {
			base = append(base[:2:2], []rune(hex4(checksum(name)))...)
			summed, index = true, 1
		}
		tail := "~" + strconv.Itoa(index)
		b := base[:min(len(base), 8-len(tail))]
		var s shortName
		for i := range s {
			s[i] = ' '
		}
		copy(s[:], string(b)+tail)
		copy(s[8:], string(ext))
		if !taken(s) {
			return s, nil
		}
	}
	return shortName{}, errNoShortName
}

// checksum is the 16-bit checksum Windows puts in a short name once the
// numbered ones run out, over the name's UTF-16 units as written.
func checksum(name string) uint16 {
	var h uint16
	for _, c := range utf16.Encode([]rune(name)) {
		h = h*0x25 + c
	}
	t := int32(uint32(h) * 0x12B9B0A5)
	if t < 0 {
		t = -t
	}
	return uint16(t % 1000000007)
}

// hex4 writes a checksum as Windows does: four hex digits, lowest first.
func hex4(c uint16) string {
	const digits = "0123456789ABCDEF"
	var b [4]byte
	for i := range b {
		b[i] = digits[c&0xF]
		c >>= 4
	}
	return string(b[:])
}

// lfnEntries are the long-name entries for name, in the order they are
// stored: the last part first, marked 0x40.
func lfnEntries(name string, s shortName) [][libfat.DirEntrySize]byte {
	u := utf16.Encode([]rune(name))
	n := (len(u) + libfat.LFNCharsPerSlot - 1) / libfat.LFNCharsPerSlot
	padded := make([]uint16, n*libfat.LFNCharsPerSlot)
	copy(padded, u)
	for i := len(u); i < len(padded); i++ {
		if i == len(u) {
			padded[i] = 0
		} else {
			padded[i] = 0xFFFF
		}
	}
	sum := libfat.LFNChecksum(s)
	out := make([][libfat.DirEntrySize]byte, n)
	for k := range n {
		var e [libfat.DirEntrySize]byte
		ord := byte(k + 1)
		if k == n-1 {
			ord |= libfat.LFNLastFlag
		}
		e[0], e[11], e[13] = ord, libfat.AttrLongName, sum
		part := padded[k*libfat.LFNCharsPerSlot:]
		for i, off := range libfat.LFNCharOffsets {
			e[off], e[off+1] = byte(part[i]), byte(part[i]>>8)
		}
		out[n-1-k] = e
	}
	return out
}
