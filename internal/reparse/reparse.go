// Package reparse lays out the reparse data of a Windows symlink and
// junction, as a live Windows target sets it and an NTFS image stores it,
// and reads it back.
package reparse

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

// The reparse tags of a symlink and a junction (a mount point).
const (
	TagSymlink    = 0xA000000C
	TagMountPoint = 0xA0000003
)

// symlinkRelative marks a symlink's substitute name as relative.
const symlinkRelative = 1

// Symlink is the reparse data CreateSymbolicLinkW writes: the print name,
// then the substitute name, which for a drive or a share is the NT path and
// otherwise the target itself, marked relative (a path from the drive's
// root, \etc\hosts, included). Slashes in target become backslashes.
func Symlink(target string) []byte {
	t := strings.ReplaceAll(target, "/", `\`)
	subst, flags := t, uint32(symlinkRelative)
	switch {
	case strings.HasPrefix(t, `\\`):
		subst, flags = `\??\UNC\`+t[2:], 0
	case len(t) > 1 && t[1] == ':':
		subst, flags = `\??\`+t, 0
	}
	s, p := utf16.Encode([]rune(subst)), utf16.Encode([]rune(t))
	b := header(TagSymlink, 12+2*(len(s)+len(p)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(p)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(s)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(p)))
	b = binary.LittleEndian.AppendUint32(b, flags)
	return appendUTF16(appendUTF16(b, p), s)
}

// Junction is the reparse data mklink /J writes for a junction to target,
// an absolute Windows path: the substitute name, its NT path, then the
// print name, the path itself.
func Junction(target string) []byte {
	s, p := utf16.Encode([]rune(`\??\`+target)), utf16.Encode([]rune(target))
	// A mount point's names are each NUL-terminated, and their lengths leave
	// the terminator out.
	b := header(TagMountPoint, 8+2*(len(s)+1+len(p)+1))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(s)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*(len(s)+1)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(p)))
	b = appendUTF16(appendUTF16(b, s), []uint16{0})
	return appendUTF16(appendUTF16(b, p), []uint16{0})
}

func header(tag uint32, dataLen int) []byte {
	b := binary.LittleEndian.AppendUint32(nil, tag)
	b = binary.LittleEndian.AppendUint16(b, uint16(dataLen))
	return binary.LittleEndian.AppendUint16(b, 0)
}

func appendUTF16(b []byte, u []uint16) []byte {
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// PrintName reads the tag and print name of a symlink's or junction's
// reparse data.
func PrintName(b []byte) (uint32, string, error) {
	if len(b) < 16 {
		return 0, "", errors.New("short reparse data")
	}
	tag := binary.LittleEndian.Uint32(b)
	off, size := int(binary.LittleEndian.Uint16(b[12:])), int(binary.LittleEndian.Uint16(b[14:]))
	start := 16
	switch tag {
	case TagSymlink:
		start = 20
	case TagMountPoint:
	default:
		return tag, "", errors.New("reparse data of neither a symlink nor a junction")
	}
	if start+off+size > len(b) || size%2 != 0 {
		return 0, "", errors.New("reparse name runs past its data")
	}
	name := b[start+off : start+off+size]
	u := make([]uint16, len(name)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(name[2*i:])
	}
	return tag, string(utf16.Decode(u)), nil
}
