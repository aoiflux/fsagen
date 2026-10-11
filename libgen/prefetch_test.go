package libgen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libntfs"
)

// TestPrefetchHashMatchesWindows: the hash is the one Windows 10 put in the
// names of two real prefetch files, CMD.EXE-D269B812.pf and
// CALC.EXE-3FBEF7FD.pf, both from a machine whose C: was HarddiskVolume8.
func TestPrefetchHashMatchesWindows(t *testing.T) {
	for _, tc := range []struct {
		exe  string
		want string
	}{
		{`C:\Windows\System32\cmd.exe`, "CMD.EXE-D269B812.pf"},
		{`C:\Windows\System32\calc.exe`, "CALC.EXE-3FBEF7FD.pf"},
	} {
		got, err := PrefetchFileName(tc.exe, 8)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s on HarddiskVolume8 is named %s, Windows named it %s", tc.exe, got, tc.want)
		}
	}
}

// TestPrefetchNameIsCut: a name longer than the header's 29 characters is
// cut there, in the header and in the file name alike, without splitting a
// character that takes two UTF-16 units.
func TestPrefetchNameIsCut(t *testing.T) {
	long := `C:\Tools\` + strings.Repeat("decode", 6) + ".exe"
	name, err := PrefetchFileName(long, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, strings.Repeat("DECODE", 4)+"DECOD-") {
		t.Errorf("long name became %s, want its first 29 characters, upper case", name)
	}
	if got := prefetchName(strings.Repeat("a", 28) + "\U0001F600.exe"); got != strings.Repeat("A", 28) {
		t.Errorf("a name whose 29th unit is half a surrogate pair became %q", got)
	}
}

func samplePrefetchSpec() PrefetchSpec {
	return PrefetchSpec{
		Executable: `E:\Tools\Mimi.exe`,
		Loaded:     []string{`C:\Windows\System32\advapi32.dll`, `E:\Tools\mimilib.dll`, `C:\Windows\System32\en-US\KernelBase.dll.mui`},
		RunCount:   12,
		LastRuns: []time.Time{
			time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC),
			time.Date(2024, 3, 2, 14, 30, 0, 0, time.UTC),
			time.Date(2024, 2, 28, 8, 15, 0, 0, time.UTC),
		},
		HarddiskVolume: 5,
		Volumes: map[byte]PrefetchVolume{
			'C': {Serial: 0x8C9F49EC, Created: time.Date(2023, 6, 1, 10, 0, 0, 0, time.UTC)},
			'E': {Serial: 0x1A2B3C4D, Created: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)},
		},
	}
}

// pfRead is what a reader finds in a prefetch file.
type pfRead struct {
	version, size, hash, runCount uint32
	name                          string
	runs                          []time.Time
	files                         []string
	flags                         []uint32
	traces, chains                []int
	volumes                       []pfReadVolume
	unknown120, unknown124        uint32
}

type pfReadVolume struct {
	device  string
	serial  uint32
	created time.Time
	dirs    []string
}

// readPrefetch parses a prefetch file the way libscca documents it, taking
// nothing from the writer: the MAM wrapper, the header, version 30's second
// file information layout, the metrics and trace chains, the names and the
// volumes.
func readPrefetch(t *testing.T, data []byte) pfRead {
	t.Helper()
	le := binary.LittleEndian
	if bytes.HasPrefix(data, []byte("MAM\x04")) {
		size := int(le.Uint32(data[4:]))
		d, err := xpressDecode(data[8:], size)
		if err != nil {
			t.Fatalf("MAM payload: %v", err)
		}
		data = d
	}
	if string(data[4:8]) != "SCCA" {
		t.Fatalf("signature %q, want SCCA", data[4:8])
	}
	u16 := func(b []byte) string {
		var u []uint16
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, le.Uint16(b[i:]))
		}
		return string(utf16.Decode(u))
	}
	r := pfRead{version: le.Uint32(data), size: le.Uint32(data[12:]), hash: le.Uint32(data[76:])}
	r.name = strings.TrimRight(u16(data[16:76]), "\x00")
	if int(r.size) != len(data) {
		t.Errorf("header says %d bytes, the data is %d", r.size, len(data))
	}
	info := data[84:]
	metricsOff := le.Uint32(info[0:])
	if metricsOff != 0x128 {
		t.Fatalf("file metrics at %#x; version 30's second layout and version 31 put them at 0x128", metricsOff)
	}
	for i := range MaxPrefetchRuns {
		if ft := le.Uint64(info[44+8*i:]); ft != 0 {
			r.runs = append(r.runs, libntfs.FiletimeToTime(ft))
		}
	}
	r.runCount, r.unknown120, r.unknown124 = le.Uint32(info[116:]), le.Uint32(info[120:]), le.Uint32(info[124:])

	n, traceOff, traceN := le.Uint32(info[4:]), le.Uint32(info[8:]), le.Uint32(info[12:])
	strOff, strSize := le.Uint32(info[16:]), le.Uint32(info[20:])
	next := 0
	for i := range n {
		m := data[metricsOff+32*i:]
		first, count := int(le.Uint32(m[0:])), int(le.Uint32(m[4:]))
		if first != next {
			t.Errorf("file %d's trace chain starts at %d, want %d", i, first, next)
		}
		next += count
		r.traces = append(r.traces, count)
		off, chars := le.Uint32(m[12:]), le.Uint32(m[16:])
		if off+2*chars+2 > strSize {
			t.Fatalf("file %d's name runs past the filename strings", i)
		}
		name := data[strOff+off : strOff+off+2*chars+2]
		if name[len(name)-1] != 0 || name[len(name)-2] != 0 {
			t.Errorf("file %d's name is not NUL-terminated", i)
		}
		r.files = append(r.files, u16(name[:len(name)-2]))
		r.flags = append(r.flags, le.Uint32(m[20:]))
	}
	if next != int(traceN) {
		t.Errorf("the metrics use %d trace entries, the header says %d", next, traceN)
	}
	for i := range traceN {
		r.chains = append(r.chains, int(data[traceOff+8*i+4]))
	}

	volOff, volN, volSize := le.Uint32(info[24:]), le.Uint32(info[28:]), le.Uint32(info[32:])
	if volOff+volSize != uint32(len(data)) {
		t.Errorf("the volumes end at %d, the file at %d", volOff+volSize, len(data))
	}
	vi := data[volOff : volOff+volSize]
	totalDirs := 0
	for i := range volN {
		e := vi[96*i:]
		pathOff, chars := le.Uint32(e[0:]), le.Uint32(e[4:])
		ft := le.Uint64(e[8:])
		v := pfReadVolume{
			device:  u16(vi[pathOff : pathOff+2*chars]),
			serial:  le.Uint32(e[16:]),
			created: libntfs.FiletimeToTime(ft).Truncate(time.Second),
		}
		refs := vi[le.Uint32(e[20:]):]
		if le.Uint32(refs) != 3 || le.Uint32(refs[4:]) != 0 || le.Uint32(e[24:]) != 16 {
			t.Errorf("volume %d's file references: version %d, %d of them, %d bytes", i, le.Uint32(refs), le.Uint32(refs[4:]), le.Uint32(e[24:]))
		}
		p := le.Uint32(e[28:])
		dirs := le.Uint32(e[32:])
		if le.Uint32(e[64:]) != dirs {
			t.Errorf("volume %d: directory count copy %d, count %d", i, le.Uint32(e[64:]), dirs)
		}
		for range dirs {
			n := uint32(le.Uint16(vi[p:]))
			v.dirs = append(v.dirs, u16(vi[p+2:p+2+2*n]))
			p += 2 + 2*n + 2
		}
		totalDirs += len(v.dirs)
		r.volumes = append(r.volumes, v)
	}
	if got := le.Uint32(info[36:]); int(got) != totalDirs {
		t.Errorf("file information counts %d directories, the volumes hold %d", got, totalDirs)
	}
	return r
}

// TestPrefetchReadBack: a reader that knows only the format finds what the
// spec said, as Windows would have recorded it.
func TestPrefetchReadBack(t *testing.T) {
	spec := samplePrefetchSpec()
	for _, compressed := range []bool{true, false} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			spec.Uncompressed = !compressed
			data, err := BuildPrefetch(spec, prng.Root(1).Stream())
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.HasPrefix(data, []byte("MAM\x04")); got != compressed {
				t.Fatalf("MAM header present: %v, want %v", got, compressed)
			}
			r := readPrefetch(t, data)

			hash, _ := PrefetchHash(spec.Executable, 5)
			if r.version != 31 || r.name != "MIMI.EXE" || r.hash != hash {
				t.Errorf("header: version %d, name %q, hash %#x; want 31, MIMI.EXE, %#x", r.version, r.name, r.hash, hash)
			}
			if r.runCount != 12 || r.unknown120 != 1 || r.unknown124 != 0 {
				t.Errorf("run count %d (at 116), %d at 120, %d at 124; want 12, 1, 0", r.runCount, r.unknown120, r.unknown124)
			}
			wantRuns := []time.Time{spec.LastRuns[1], spec.LastRuns[0], spec.LastRuns[2]}
			if !slices.EqualFunc(r.runs, wantRuns, time.Time.Equal) {
				t.Errorf("run times %v, want the given ones newest first %v", r.runs, wantRuns)
			}

			// A volume is named by its creation FILETIME and its serial, in
			// lower-case hex: \VOLUME{01d1217a9c4c6779-8c9f49ec}.
			volume := func(created time.Time, serial uint32) string {
				return fmt.Sprintf(`\VOLUME{%016x-%08x}`, libntfs.TimeToFiletime(created.Truncate(time.Second)), serial)
			}
			c, e := volume(spec.Volumes['C'].Created, 0x8C9F49EC), volume(spec.Volumes['E'].Created, 0x1A2B3C4D)
			wantFiles := []string{
				c + `\WINDOWS\SYSTEM32\NTDLL.DLL`,
				e + `\TOOLS\MIMI.EXE`,
				c + `\WINDOWS\SYSTEM32\ADVAPI32.DLL`,
				e + `\TOOLS\MIMILIB.DLL`,
				c + `\WINDOWS\SYSTEM32\EN-US\KERNELBASE.DLL.MUI`,
			}
			if !slices.Equal(r.files, wantFiles) {
				t.Errorf("files\n got %q\nwant %q", r.files, wantFiles)
			}
			if want := []uint32{0x100, 0x100, 0x100, 0x100, 0x2}; !slices.Equal(r.flags, want) {
				t.Errorf("file flags %#x, want images 0x100 and data 0x2: %#x", r.flags, want)
			}
			for i, n := range r.traces {
				if n < 1 {
					t.Errorf("file %d has no trace entries", i)
				}
			}

			wantVols := []pfReadVolume{
				{device: c, serial: 0x8C9F49EC, created: spec.Volumes['C'].Created, dirs: []string{c + `\WINDOWS`, c + `\WINDOWS\SYSTEM32`, c + `\WINDOWS\SYSTEM32\EN-US`}},
				{device: e, serial: 0x1A2B3C4D, created: spec.Volumes['E'].Created, dirs: []string{e + `\TOOLS`}},
			}
			if len(r.volumes) != len(wantVols) {
				t.Fatalf("%d volumes, want %d", len(r.volumes), len(wantVols))
			}
			for i, v := range r.volumes {
				w := wantVols[i]
				if v.device != w.device || v.serial != w.serial || !v.created.Equal(w.created) || !slices.Equal(v.dirs, w.dirs) {
					t.Errorf("volume %d\n got %+v\nwant %+v", i, v, w)
				}
			}
		})
	}
}

// TestPrefetchDeterministic: the same spec and stream give the same bytes,
// and the default file list is the one Windows records for any program.
func TestPrefetchDeterministic(t *testing.T) {
	spec := samplePrefetchSpec()
	a, _ := BuildPrefetch(spec, prng.Root(1).Stream())
	b, _ := BuildPrefetch(spec, prng.Root(1).Stream())
	if !bytes.Equal(a, b) {
		t.Fatal("the same spec gave two different files")
	}
	got := PrefetchFiles(`C:\Windows\System32\cmd.exe`, nil)
	want := []string{prefetchNTDLL, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\kernel32.dll`, `C:\Windows\System32\KernelBase.dll`}
	if !slices.Equal(got, want) {
		t.Errorf("default files %q, want %q", got, want)
	}
	if got := PrefetchFiles(`C:\x.exe`, []string{`C:\WINDOWS\system32\NTDLL.DLL`, `c:\X.EXE`}); len(got) != 2 {
		t.Errorf("a file named twice in another case was listed twice: %q", got)
	}
}

// TestPrefetchRefuses: what a prefetch file cannot hold is refused, never
// cut down to fit.
func TestPrefetchRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*PrefetchSpec)
		want   string
	}{
		{"unknown version", func(s *PrefetchSpec) { s.Version = "win7" }, "version"},
		{"no run times", func(s *PrefetchSpec) { s.LastRuns = nil }, "run times"},
		{"nine run times", func(s *PrefetchSpec) {
			for len(s.LastRuns) < 9 {
				s.LastRuns = append(s.LastRuns, s.LastRuns[0].Add(time.Duration(len(s.LastRuns))*time.Hour))
			}
			s.RunCount = 9
		}, "run times"},
		{"count below the times", func(s *PrefetchSpec) { s.RunCount = 2 }, "run count"},
		{"no volume for a drive", func(s *PrefetchSpec) { delete(s.Volumes, 'E') }, "no volume"},
		{"a volume no file is on", func(s *PrefetchSpec) { s.Volumes['D'] = PrefetchVolume{} }, "D:"},
		{"a drive root", func(s *PrefetchSpec) { s.Executable = `E:\` }, "root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := samplePrefetchSpec()
			tc.change(&spec)
			_, err := BuildPrefetch(spec, prng.Root(1).Stream())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}
