package libgen

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
)

// A Windows prefetch file (.pf): the record the prefetcher keeps of a program
// it has seen start — the program's name and the hash of its path, how many
// times it ran and the last eight times it did, every file it loaded in its
// first seconds, and the volumes those files were on. A forensic tool reads it
// as proof of execution, which is what a scenario uses it for.
//
// The layout is the SCCA format as Windows 10 (version 30, in the shape
// Windows 10 1903 introduced) and Windows 11 (version 31) write it, wrapped
// in the MAM header and compressed with XPRESS Huffman as both do. Where the
// format holds a value whose meaning is not known, it gets what Windows was
// seen to write, or zero. The run count is kept where Windows 10 1903 and
// later keep it, and the field older files kept it in is left zero, so that
// every parser reads the same count.

// PrefetchVersions is the closed set of formats written: win10 is version 30,
// win11 is version 31.
var PrefetchVersions = []string{"win10", "win11"}

var prefetchVersion = map[string]uint32{"win10": 30, "win11": 31}

// MaxPrefetchRuns is how many run times a prefetch file keeps.
const MaxPrefetchRuns = 8

// DefaultHarddiskVolume is the n of \Device\HarddiskVolume<n> assumed for the
// executable's volume: C: on a default UEFI install of Windows 10 or 11.
const DefaultHarddiskVolume = 3

// maxPrefetchName is how many UTF-16 units of the executable's name the
// header keeps, before its NUL.
const maxPrefetchName = 29

// prefetchNTDLL is loaded by every Windows process, and is the first file a
// prefetch file lists.
const prefetchNTDLL = `C:\Windows\System32\ntdll.dll`

// prefetchDefaultLoaded is what a program is recorded as loading when the
// scenario names nothing: the two libraries every Win32 program maps.
var prefetchDefaultLoaded = []string{`C:\Windows\System32\kernel32.dll`, `C:\Windows\System32\KernelBase.dll`}

// PrefetchVolume is what a prefetch file records about a volume.
type PrefetchVolume struct {
	Serial uint32
	// Created is when the volume was formatted; with the serial it also
	// names the volume, as \VOLUME{<created>-<serial>}.
	Created time.Time
}

// PrefetchSpec is what a prefetch file says about a program's runs.
type PrefetchSpec struct {
	// Version is one of PrefetchVersions; empty is win11.
	Version string
	// Executable is the program's Windows path, C:\dir\name.exe.
	Executable string
	// Loaded are the other files the program loaded, as Windows paths. Nil
	// is kernel32.dll and KernelBase.dll; ntdll.dll is always recorded.
	Loaded []string
	// RunCount is how many times the program ran; at least len(LastRuns).
	RunCount uint32
	// LastRuns are when it last ran, at most MaxPrefetchRuns and at least
	// one, in any order; the file keeps them newest first.
	LastRuns []time.Time
	// HarddiskVolume is the n of \Device\HarddiskVolume<n> for the
	// executable's volume, which the hash is computed over. Zero is
	// DefaultHarddiskVolume.
	HarddiskVolume int
	// Volumes holds, for each drive letter a file is on, what the file
	// records about that volume.
	Volumes map[byte]PrefetchVolume
	// Uncompressed writes the SCCA data without the MAM wrapper, as a tool
	// that has decompressed one does.
	Uncompressed bool
}

// PrefetchFiles is every file a prefetch file for exe lists, in its order:
// ntdll.dll, the executable, then what it loaded (by default kernel32.dll and
// KernelBase.dll). A path given twice, in any case, is listed once.
func PrefetchFiles(exe string, loaded []string) []string {
	if loaded == nil {
		loaded = prefetchDefaultLoaded
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range slices.Concat([]string{prefetchNTDLL, exe}, loaded) {
		if k := strings.ToUpper(p); !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// PrefetchDrives is the drive letters, upper case and sorted, that the files
// of a prefetch file for exe are on.
func PrefetchDrives(exe string, loaded []string) ([]byte, error) {
	var drives []byte
	for _, p := range PrefetchFiles(exe, loaded) {
		d, _, err := splitWindowsPath(p)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(drives, d) {
			drives = append(drives, d)
		}
	}
	slices.Sort(drives)
	return drives, nil
}

// PrefetchFileName is the name Windows gives the prefetch file of exe on
// \Device\HarddiskVolume<harddiskVolume>: the executable's name, upper case
// and cut to 29 characters, a dash, the path hash in hex, and .pf.
func PrefetchFileName(exe string, harddiskVolume int) (string, error) {
	h, err := PrefetchHash(exe, harddiskVolume)
	if err != nil {
		return "", err
	}
	_, parts, _ := splitWindowsPath(exe)
	return fmt.Sprintf("%s-%08X.pf", prefetchName(parts[len(parts)-1]), h), nil
}

// PrefetchHash is the hash Windows 10 and 11 put in a prefetch file's name
// and header: the SCCA Vista hash of the executable's device path, upper
// case, \DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\CMD.EXE, over its UTF-16LE
// bytes.
func PrefetchHash(exe string, harddiskVolume int) (uint32, error) {
	_, parts, err := splitWindowsPath(exe)
	if err != nil {
		return 0, err
	}
	if len(parts) == 0 {
		return 0, fmt.Errorf("%q is a drive's root, not a program", exe)
	}
	if harddiskVolume == 0 {
		harddiskVolume = DefaultHarddiskVolume
	}
	device := fmt.Sprintf(`\DEVICE\HARDDISKVOLUME%d\%s`, harddiskVolume, strings.ToUpper(strings.Join(parts, `\`)))
	h := uint32(314159)
	for _, b := range utf16le(device) {
		h = h*37 + uint32(b)
	}
	return h, nil
}

// prefetchName is the executable's name as the header and the file name
// carry it: upper case, at most 29 UTF-16 units, never cutting a character
// in two.
func prefetchName(name string) string {
	name = strings.ToUpper(name)
	units := 0
	for i, r := range name {
		if units+utf16.RuneLen(r) > maxPrefetchName {
			return name[:i]
		}
		units += utf16.RuneLen(r)
	}
	return name
}

// prefetchImage reports whether a loaded file is an image (a program or a
// library) rather than data, which the file metrics and trace chains flag.
func prefetchImage(path string) bool {
	i := strings.LastIndexByte(path, '.')
	return i >= 0 && slices.Contains([]string{".EXE", ".DLL", ".SYS", ".DRV", ".OCX", ".CPL", ".SCR", ".COM"}, strings.ToUpper(path[i:]))
}

// pfFile is one listed file, placed on its volume.
type pfFile struct {
	path   string // \VOLUME{...}\DIR\NAME, upper case
	image  bool
	traces int
}

// pfVolume is one volume and the directories its listed files are in.
type pfVolume struct {
	device string
	vol    PrefetchVolume
	dirs   []string
}

// BuildPrefetch writes the prefetch file. What the scenario does not say —
// how many trace entries each file has and where its blocks are — is drawn
// from s.
func BuildPrefetch(spec PrefetchSpec, s *prng.Stream) ([]byte, error) {
	version, ok := prefetchVersion[cmp.Or(spec.Version, "win11")]
	if !ok {
		return nil, fmt.Errorf("prefetch version %q (want one of: %s)", spec.Version, strings.Join(PrefetchVersions, ", "))
	}
	if len(spec.LastRuns) == 0 || len(spec.LastRuns) > MaxPrefetchRuns {
		return nil, fmt.Errorf("a prefetch file keeps 1 to %d run times, not %d", MaxPrefetchRuns, len(spec.LastRuns))
	}
	if int(spec.RunCount) < len(spec.LastRuns) {
		return nil, fmt.Errorf("run count %d is less than the %d run times given", spec.RunCount, len(spec.LastRuns))
	}
	hash, err := PrefetchHash(spec.Executable, spec.HarddiskVolume)
	if err != nil {
		return nil, err
	}
	files, vols, err := prefetchLayout(spec, s)
	if err != nil {
		return nil, err
	}
	runs := slices.Clone(spec.LastRuns)
	slices.SortStableFunc(runs, func(a, b time.Time) int { return b.Compare(a) })
	// A trace entry's used and prefetched bits say, one bit per run, in which
	// of the last eight runs its block was used.
	runMask := byte(0xFF >> (8 - min(spec.RunCount, 8)))

	const headerSize, infoSize, metricSize, traceSize, volumeEntrySize = 84, 212, 32, 8, 96
	metricsOff := headerSize + infoSize
	traceOff := metricsOff + metricSize*len(files)
	traceCount := 0
	for _, f := range files {
		traceCount += f.traces
	}
	stringsOff := traceOff + traceSize*traceCount
	var strs []byte
	nameOffs := make([]int, len(files))
	for i, f := range files {
		nameOffs[i] = len(strs)
		strs = append(strs, utf16z(f.path)...)
	}
	volOff := roundUp(stringsOff+len(strs), 8)
	volInfo := prefetchVolumes(vols)
	b := make([]byte, volOff+len(volInfo))
	le := binary.LittleEndian

	le.PutUint32(b[0:], version)
	copy(b[4:], "SCCA")
	le.PutUint32(b[8:], 0x11)
	le.PutUint32(b[12:], uint32(len(b)))
	_, exeParts, _ := splitWindowsPath(spec.Executable)
	copy(b[16:76], utf16le(prefetchName(exeParts[len(exeParts)-1])))
	le.PutUint32(b[76:], hash)

	info := b[headerSize:]
	le.PutUint32(info[0:], uint32(metricsOff))
	le.PutUint32(info[4:], uint32(len(files)))
	le.PutUint32(info[8:], uint32(traceOff))
	le.PutUint32(info[12:], uint32(traceCount))
	le.PutUint32(info[16:], uint32(stringsOff))
	le.PutUint32(info[20:], uint32(volOff-stringsOff))
	le.PutUint32(info[24:], uint32(volOff))
	le.PutUint32(info[28:], uint32(len(vols)))
	le.PutUint32(info[32:], uint32(len(volInfo)))
	dirs := 0
	for _, v := range vols {
		dirs += len(v.dirs)
	}
	le.PutUint32(info[36:], uint32(dirs))
	le.PutUint32(info[40:], 1)
	for i, t := range runs {
		le.PutUint64(info[44+8*i:], filetime(t))
	}
	le.PutUint32(info[116:], spec.RunCount)
	le.PutUint32(info[120:], 1) // what Windows 10 1903 and later write here; tools tell the layouts apart by it

	trace := 0
	for i, f := range files {
		m := b[metricsOff+metricSize*i:]
		le.PutUint32(m[0:], uint32(trace))
		le.PutUint32(m[4:], uint32(f.traces))
		le.PutUint32(m[8:], uint32(f.traces))
		le.PutUint32(m[12:], uint32(nameOffs[i]))
		le.PutUint32(m[16:], uint32(len(utf16.Encode([]rune(f.path)))))
		flags, chain := uint32(0x2), byte(0x04) // data: loaded as a resource
		if f.image {
			flags, chain = 0x100, 0x02
		}
		le.PutUint32(m[20:], flags)
		block := uint32(8 * (1 + s.IntN(1<<12)))
		for range f.traces {
			e := b[traceOff+traceSize*trace:]
			le.PutUint32(e[0:], block)
			e[4], e[5], e[6], e[7] = chain, 0x01, runMask, runMask
			block += 8
			trace++
		}
	}
	copy(b[stringsOff:], strs)
	copy(b[volOff:], volInfo)

	if spec.Uncompressed {
		return b, nil
	}
	out := append([]byte("MAM\x04"), le.AppendUint32(nil, uint32(len(b)))...)
	return append(out, XpressHuffman(b)...), nil
}

// prefetchLayout places each listed file on its volume and finds the
// directories each volume's files are in. Volumes are ordered by their
// device names, as Windows orders them.
func prefetchLayout(spec PrefetchSpec, s *prng.Stream) ([]pfFile, []pfVolume, error) {
	byDrive := map[byte]*pfVolume{}
	dirs := map[byte]map[string]bool{}
	var files []pfFile
	for _, p := range PrefetchFiles(spec.Executable, spec.Loaded) {
		drive, parts, err := splitWindowsPath(p)
		if err != nil {
			return nil, nil, err
		}
		if len(parts) == 0 {
			return nil, nil, fmt.Errorf("%q is a drive's root, not a file", p)
		}
		v, ok := byDrive[drive]
		if !ok {
			vol, known := spec.Volumes[drive]
			if !known {
				return nil, nil, fmt.Errorf("%q is on %c:, and no volume is given for it", p, drive)
			}
			v = &pfVolume{device: fmt.Sprintf(`\VOLUME{%016x-%08x}`, filetime(vol.Created), vol.Serial), vol: vol}
			byDrive[drive] = v
			dirs[drive] = map[string]bool{}
		}
		upperParts := strings.Split(strings.ToUpper(strings.Join(parts, `\`)), `\`)
		for k := 1; k < len(upperParts); k++ {
			dirs[drive][v.device+`\`+strings.Join(upperParts[:k], `\`)] = true
		}
		files = append(files, pfFile{
			path:   v.device + `\` + strings.Join(upperParts, `\`),
			image:  prefetchImage(p),
			traces: 1 + s.IntN(16),
		})
	}
	for _, d := range slices.Sorted(maps.Keys(spec.Volumes)) {
		if _, used := byDrive[d]; !used {
			return nil, nil, fmt.Errorf("a volume is given for %c:, which no listed file is on", d)
		}
	}
	var vols []pfVolume
	for d, v := range byDrive {
		v.dirs = slices.Sorted(maps.Keys(dirs[d]))
		vols = append(vols, *v)
	}
	slices.SortFunc(vols, func(a, b pfVolume) int { return strings.Compare(a.device, b.device) })
	return files, vols, nil
}

// prefetchVolumes is the volumes information: one 96-byte entry per volume,
// then each volume's device name, its (empty) file references and its
// directory names, each name preceded by its length.
func prefetchVolumes(vols []pfVolume) []byte {
	le := binary.LittleEndian
	b := make([]byte, 96*len(vols))
	for i, v := range vols {
		e := 96 * i
		le.PutUint32(b[e+0:], uint32(len(b)))
		le.PutUint32(b[e+4:], uint32(len(utf16.Encode([]rune(v.device)))))
		le.PutUint64(b[e+8:], filetime(v.vol.Created))
		le.PutUint32(b[e+16:], v.vol.Serial)
		b = append(b, utf16z(v.device)...)
		b = append(b, make([]byte, roundUp(len(b), 8)-len(b))...)

		le.PutUint32(b[e+20:], uint32(len(b)))
		le.PutUint32(b[e+24:], 16)
		refs := le.AppendUint32(nil, 3) // version
		refs = le.AppendUint32(refs, 0) // no references: Windows 10 and later leave them out
		b = append(b, append(refs, make([]byte, 8)...)...)

		le.PutUint32(b[e+28:], uint32(len(b)))
		le.PutUint32(b[e+32:], uint32(len(v.dirs)))
		le.PutUint32(b[e+64:], uint32(len(v.dirs)))
		for _, d := range v.dirs {
			b = le.AppendUint16(b, uint16(len(utf16.Encode([]rune(d)))))
			b = append(b, utf16z(d)...)
		}
	}
	return append(b, make([]byte, roundUp(len(b), 8)-len(b))...)
}

func roundUp(n, to int) int { return (n + to - 1) / to * to }
