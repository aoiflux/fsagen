package conformance

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/prng"
)

// TestPrefetchReadByGoPrefetch: Velocidex's go-prefetch, the parser
// Velociraptor uses, reads a generated prefetch file — compressed or not, as
// Windows 10 or 11 writes it — and finds the program, its hash, the run count,
// the run times and every file it loaded.
func TestPrefetchReadByGoPrefetch(t *testing.T) {
	runs := []time.Time{
		time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC),
		time.Date(2024, 3, 2, 14, 30, 5, 0, time.UTC),
	}
	spec := libgen.PrefetchSpec{
		Executable:     `E:\Tools\mimi.exe`,
		Loaded:         []string{`C:\Windows\System32\advapi32.dll`, `E:\Tools\mimilib.dll`},
		RunCount:       7,
		LastRuns:       runs,
		HarddiskVolume: 5,
		Volumes: map[byte]libgen.PrefetchVolume{
			'C': {Serial: 0x8C9F49EC, Created: time.Date(2023, 6, 1, 10, 0, 0, 0, time.UTC)},
			'E': {Serial: 0x1A2B3C4D, Created: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)},
		},
	}
	// A volume is named by its creation FILETIME and serial, in lower-case hex.
	c := fmt.Sprintf(`\VOLUME{%016x-8c9f49ec}`, uint64(spec.Volumes['C'].Created.Unix()+11644473600)*10_000_000)
	e := fmt.Sprintf(`\VOLUME{%016x-1a2b3c4d}`, uint64(spec.Volumes['E'].Created.Unix()+11644473600)*10_000_000)
	wantFiles := []string{
		c + `\WINDOWS\SYSTEM32\NTDLL.DLL`,
		e + `\TOOLS\MIMI.EXE`,
		c + `\WINDOWS\SYSTEM32\ADVAPI32.DLL`,
		e + `\TOOLS\MIMILIB.DLL`,
	}
	hash, _ := libgen.PrefetchHash(spec.Executable, 5)

	for _, tc := range []struct {
		version, want string
		uncompressed  bool
	}{
		{"win11", "Win11", false},
		{"win10", "Win10", false},
		{"win11", "Win11", true},
	} {
		t.Run(fmt.Sprintf("%s/uncompressed=%v", tc.version, tc.uncompressed), func(t *testing.T) {
			s := spec
			s.Version, s.Uncompressed = tc.version, tc.uncompressed
			data, err := libgen.BuildPrefetch(s, prng.Root(1).Stream())
			if err != nil {
				t.Fatal(err)
			}
			info, err := prefetch.LoadPrefetch(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("go-prefetch: %v", err)
			}
			if info.Executable != "MIMI.EXE" || info.Hash != fmt.Sprintf("0x%08X", hash) || info.Version != tc.want {
				t.Errorf("executable %q, hash %s, version %q; want MIMI.EXE, 0x%08X, %s", info.Executable, info.Hash, info.Version, hash, tc.want)
			}
			if info.RunCount != 7 {
				t.Errorf("run count %d, want 7", info.RunCount)
			}
			if want := []time.Time{runs[1], runs[0]}; !slices.EqualFunc(info.LastRunTimes, want, time.Time.Equal) {
				t.Errorf("run times %v, want %v (newest first)", info.LastRunTimes, want)
			}
			if !slices.Equal(info.FilesAccessed, wantFiles) {
				t.Errorf("files\n got %q\nwant %q", info.FilesAccessed, wantFiles)
			}
		})
	}
}

// TestPrefetchDecompressedByGoPrefetch: go-prefetch's own XPRESS Huffman
// decoder, which it uses wherever Windows' is not there to ask, unpacks a
// compressed prefetch file to exactly the bytes it was compressed from. On
// Windows LoadPrefetch prefers ntdll's decoder, so this calls the Go one
// directly.
func TestPrefetchDecompressedByGoPrefetch(t *testing.T) {
	spec := libgen.PrefetchSpec{
		Executable: `C:\Windows\System32\cmd.exe`,
		RunCount:   1,
		LastRuns:   []time.Time{time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC)},
		Volumes:    map[byte]libgen.PrefetchVolume{'C': {Serial: 1, Created: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)}},
	}
	plain := spec
	plain.Uncompressed = true
	want, err := libgen.BuildPrefetch(plain, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	packed, err := libgen.BuildPrefetch(spec, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	size := int(binary.LittleEndian.Uint32(packed[4:]))
	got, err := prefetch.LZXpressHuffmanDecompress(packed[8:], size)
	if err != nil {
		t.Fatalf("go-prefetch's decoder: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decompressed %d bytes that differ from the %d uncompressed ones", len(got), len(want))
	}
}
