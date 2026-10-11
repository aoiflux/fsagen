// Package reparse lays out the reparse data of a Windows symlink and
// junction, as a live Windows target sets it and an NTFS image stores it,
// and reads it back. The bytes are libntfs's codecs'; what is here is how
// Windows names a target in them.
package reparse

import (
	"errors"
	"strings"

	"github.com/aoiflux/libntfs"
)

// Symlink is the reparse data CreateSymbolicLinkW writes: the print name,
// then the substitute name, which for a drive or a share is the NT path and
// otherwise the target itself, marked relative (a path from the drive's
// root, \etc\hosts, included). Slashes in target become backslashes.
func Symlink(target string) ([]byte, error) {
	t := strings.ReplaceAll(target, "/", `\`)
	subst, relative := t, true
	switch {
	case strings.HasPrefix(t, `\`):
		subst, relative = `\??\UNC\`+t[2:], false
	case len(t) > 1 && t[1] == ':':
		subst, relative = `\??\`+t, false
	}
	return libntfs.EncodeSymlinkReparse(subst, t, relative)
}

// Junction is the reparse data mklink /J writes for a junction to target,
// an absolute Windows path: the substitute name, its NT path, then the
// print name, the path itself.
func Junction(target string) ([]byte, error) {
	return libntfs.EncodeMountPointReparse(`\??\`+target, target)
}

// PrintName reads the tag and print name of a symlink's or junction's
// reparse data.
func PrintName(b []byte) (uint32, string, error) {
	rp, err := libntfs.ParseReparsePoint(b)
	if err != nil {
		return 0, "", err
	}
	_, name, ok := rp.Target()
	if !ok || rp.ReparseType != libntfs.ReparsePointSymlink && rp.ReparseType != libntfs.ReparsePointMountPoint {
		return rp.ReparseType, "", errors.New("reparse data of neither a symlink nor a junction")
	}
	return rp.ReparseType, name, nil
}
