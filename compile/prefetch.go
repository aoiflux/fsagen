package compile

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// checkPrefetch validates a prefetch block against what a prefetch file can
// hold.
func checkPrefetch(op *Op, at func(string, string, ...any)) {
	p := op.Prefetch
	exeOK := false
	switch {
	case strings.TrimSpace(p.Executable) == "":
		at("prefetch", `executable is required: the Windows path of the program that ran, for example C:\Windows\System32\cmd.exe`)
	case libgen.CheckWindowsPath(p.Executable) != nil:
		at("prefetch", "executable: %v", libgen.CheckWindowsPath(p.Executable))
	case len(strings.Trim(p.Executable[2:], `\`)) == 0:
		at("prefetch", "executable %q is a drive's root, not a program", p.Executable)
	default:
		exeOK = true
	}
	if p.Version != "" && !slices.Contains(libgen.PrefetchVersions, p.Version) {
		at("prefetch", "version %q (want one of: %s)", p.Version, strings.Join(libgen.PrefetchVersions, ", "))
	}
	if len(p.LastRunTimes) > libgen.MaxPrefetchRuns {
		at("prefetch", "last_run_times: %d given; a prefetch file keeps the last %d", len(p.LastRunTimes), libgen.MaxPrefetchRuns)
	}
	seen := map[string]bool{}
	for i, t := range p.LastRunTimes {
		if strings.TrimSpace(t) == "" {
			at("prefetch", "last_run_times[%d] is empty", i)
			continue
		}
		checkFiletimeField(at, "prefetch", field{"last_run_times[" + strconv.Itoa(i) + "]", t})
		if seen[strings.TrimSpace(t)] {
			at("prefetch", "last_run_times: %s appears twice", t)
		}
		seen[strings.TrimSpace(t)] = true
	}
	if p.RunCount < 0 || int64(p.RunCount) > 0xFFFFFFFF {
		at("prefetch", "run_count %d does not fit the 32 bits a prefetch file holds", p.RunCount)
	} else if p.RunCount != 0 && p.RunCount < len(p.LastRunTimes) {
		at("prefetch", "run_count %d is less than the %d last_run_times given", p.RunCount, len(p.LastRunTimes))
	}
	if p.HarddiskVolume < 0 {
		at("prefetch", "harddisk_volume %d is negative", p.HarddiskVolume)
	}
	filesOK := true
	for i, f := range p.ReferencedFiles {
		if err := libgen.CheckWindowsPath(f); err != nil {
			at("prefetch", "referenced_files[%d]: %v", i, err)
			filesOK = false
		} else if len(strings.Trim(f[2:], `\`)) == 0 {
			at("prefetch", "referenced_files[%d]: %q is a drive's root, not a file", i, f)
			filesOK = false
		}
	}
	if exeOK && filesOK {
		checkPrefetchVolumes(p, at)
	}
}

// checkPrefetchVolumes checks the volumes block: each names a drive one of
// the listed files is on, once, with a serial and a creation time a prefetch
// file can hold.
func checkPrefetchVolumes(p *spec.PrefetchSpec, at func(string, string, ...any)) {
	drives, err := libgen.PrefetchDrives(p.Executable, referencedFiles(p))
	if err != nil {
		at("prefetch", "%v", err)
		return
	}
	seen := map[string]bool{}
	for i, v := range p.Volumes {
		d := strings.ToUpper(strings.TrimSuffix(v.Drive, ":"))
		switch {
		case len(d) != 1 || d[0] < 'A' || d[0] > 'Z':
			at("prefetch", "volumes[%d]: drive %q is not a drive letter", i, v.Drive)
		case !slices.Contains(drives, d[0]):
			at("prefetch", "volumes[%d]: no listed file is on %s: (the files are on %s)", i, d, driveList(drives))
		case seen[d]:
			at("prefetch", "volumes[%d]: drive %s appears twice", i, d)
		}
		seen[d] = true
		if v.Serial != "" {
			if _, err := libgen.ParseVolumeSerial(v.Serial); err != nil {
				at("prefetch", "volumes[%d]: %v", i, err)
			}
		}
		checkFiletimeField(at, "prefetch", field{"volumes[" + strconv.Itoa(i) + "].created", v.Created})
	}
}

// referencedFiles is the block's referenced_files as PrefetchFiles takes
// them: nil, for the default list, when none are given.
func referencedFiles(p *spec.PrefetchSpec) []string {
	if len(p.ReferencedFiles) == 0 {
		return nil
	}
	return p.ReferencedFiles
}

func driveList(drives []byte) string {
	var out []string
	for _, d := range drives {
		out = append(out, string(d)+":")
	}
	return strings.Join(out, ", ")
}

// rePrefetchName is the shape of the name Windows gives a prefetch file:
// the program's name, a dash, eight hex digits of hash, .pf.
var rePrefetchName = regexp.MustCompile(`(?i)^.+-[0-9a-f]{8}\.pf$`)

// checkPrefetchName refuses a prefetch file named the way Windows names one
// for a different program. A tool reads the program and hash off the name as
// readily as from the header, so the two must agree. A file named any other
// way is left alone: that is a copy someone renamed.
func checkPrefetchName(op *Op, r reporter) {
	p := op.Prefetch
	if op.Format != spec.FormatPrefetch || p == nil || op.Path == "" {
		return
	}
	base := path.Base(op.Path)
	if !rePrefetchName.MatchString(base) {
		return
	}
	want, err := libgen.PrefetchFileName(p.Executable, p.HarddiskVolume)
	if err != nil {
		return // the block's own check reports the executable
	}
	if !strings.EqualFold(base, want) {
		volume := p.HarddiskVolume
		if volume == 0 {
			volume = libgen.DefaultHarddiskVolume
		}
		r.at("path", "%s is named like the prefetch file of another program: Windows names the one for %s on HarddiskVolume%d %s (rename the file, or set prefetch.harddisk_volume)", base, p.Executable, volume, want)
	}
}
