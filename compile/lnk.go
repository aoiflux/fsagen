package compile

import (
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/libgen"
)

// checkLNK validates an lnk block against what a shell link can hold.
func checkLNK(op *Op, at func(string, string, ...any)) {
	l := op.Lnk
	if strings.TrimSpace(l.Target) == "" {
		at("lnk", `target is required: the Windows path the link points at, for example C:\Users\Public\tool.exe`)
	} else if err := libgen.CheckWindowsPath(l.Target); err != nil {
		at("lnk", "target: %v", err)
	}
	if l.TargetType != "" && !slices.Contains(Types, l.TargetType) {
		at("lnk", "target_type %q (want file or dir)", l.TargetType)
	}
	closed := []struct {
		key, val string
		set      []string
	}{
		{"show_command", l.ShowCommand, libgen.LNKShowCommands},
		{"drive_type", l.DriveType, libgen.LNKDriveTypes},
	}
	for _, c := range closed {
		if c.val != "" && !slices.Contains(c.set, c.val) {
			at("lnk", "%s %q (want one of: %s)", c.key, c.val, strings.Join(c.set, ", "))
		}
	}
	if l.VolumeSerial != "" {
		if _, err := libgen.ParseVolumeSerial(l.VolumeSerial); err != nil {
			at("lnk", "%v", err)
		}
	}
	if len(l.MachineID) > libgen.MaxLNKMachineID || !ascii(l.MachineID) {
		at("lnk", "machine_id %q: at most %d ASCII characters, as a NetBIOS name", l.MachineID, libgen.MaxLNKMachineID)
	}
	if len(l.VolumeLabel) > 32 || !ascii(l.VolumeLabel) {
		at("lnk", "volume_label %q: at most 32 ASCII characters", l.VolumeLabel)
	}
	if l.TargetSize < 0 {
		at("lnk", "target_size %d is negative", l.TargetSize)
	}
	if int64(l.IconIndex) != int64(int32(l.IconIndex)) {
		at("lnk", "icon_index %d does not fit the 32 bits a link holds", l.IconIndex)
	}
	seen := map[string]bool{}
	for _, a := range l.TargetAttributes {
		switch {
		case !slices.Contains(libgen.LNKAttributes, a):
			at("lnk", "target_attributes: %q (want any of: %s; a directory is target_type: dir)", a, strings.Join(libgen.LNKAttributes, ", "))
		case seen[a]:
			at("lnk", "target_attributes: %q appears twice", a)
		}
		seen[a] = true
	}
	for _, f := range []field{{"target_crtime", l.TargetCrtime}, {"target_atime", l.TargetAtime}, {"target_mtime", l.TargetMtime}} {
		checkFiletimeField(at, "lnk", f)
	}
}

// checkFiletimeField checks an optional time that will be written as a
// FILETIME, which cannot hold anything before 1601.
func checkFiletimeField(at func(string, string, ...any), block string, f field) {
	if err := checkTime(f.val); err != nil {
		at(block, "%s: %v", f.key, err)
		return
	}
	if strings.TrimSpace(f.val) == "" {
		return
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(f.val))
	if t.Before(libgen.MinFiletime) || t.After(libgen.MaxFiletime) {
		at(block, "%s: %s is outside what a FILETIME holds (1601 to 30828)", f.key, f.val)
	}
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
