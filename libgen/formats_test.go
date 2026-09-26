package libgen

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"image/jpeg"
	"image/png"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

func stream(seed int64) *prng.Stream { return prng.Root(seed).Stream() }

var peStamp = time.Date(2024, 3, 15, 9, 30, 0, 0, time.UTC)

func samplePE(t *testing.T, machine string, dll bool) PESpec {
	t.Helper()
	imports, err := ParseImports([]string{
		"kernel32.dll!CreateFileW", "kernel32.dll!WriteFile", "advapi32.dll!RegOpenKeyExW",
	})
	if err != nil {
		t.Fatal(err)
	}
	return PESpec{
		Machine:   machine,
		Subsystem: "console",
		DLL:       dll,
		Timestamp: peStamp,
		Sections: []PESection{
			{Name: ".text", Data: Filler(KindZeros, 1024, stream(1))},
			{Name: ".rdata", Data: Filler(KindText, 256, stream(2))},
			{Name: ".data", Data: Filler(KindPattern, 64, stream(3))},
		},
		Imports: imports,
		Version: &PEVersion{
			FileVersion: "6.1.7601.24545", ProductVersion: "6.1.7601.24545",
			CompanyName: "Example Corp", FileDescription: "Update Helper",
			InternalName: "updhelper", OriginalFilename: "updhelper.exe",
			ProductName: "Example Suite", LegalCopyright: "(c) Example Corp",
		},
		Overlay: Filler(KindBytes, 512, stream(4)),
	}
}

// TestPEHeaderFieldsEqualInputs: what the scenario asks for is what debug/pe
// reads back, for both widths, including the imports an imphash is built from.
func TestPEHeaderFieldsEqualInputs(t *testing.T) {
	for _, tc := range []struct {
		machine string
		want    uint16
		optMag  uint16
		dll     bool
	}{
		{"amd64", pe.IMAGE_FILE_MACHINE_AMD64, 0x20b, false},
		{"i386", pe.IMAGE_FILE_MACHINE_I386, 0x10b, false},
		{"arm64", pe.IMAGE_FILE_MACHINE_ARM64, 0x20b, true},
	} {
		t.Run(tc.machine, func(t *testing.T) {
			data, err := BuildPE(samplePE(t, tc.machine, tc.dll))
			if err != nil {
				t.Fatal(err)
			}
			f, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("debug/pe cannot read it: %v", err)
			}
			defer f.Close()

			if f.Machine != tc.want {
				t.Errorf("machine %#x, want %#x", f.Machine, tc.want)
			}
			if got := f.TimeDateStamp; got != uint32(peStamp.Unix()) {
				t.Errorf("TimeDateStamp %d, want %d", got, peStamp.Unix())
			}
			isDLL := f.Characteristics&pe.IMAGE_FILE_DLL != 0
			if isDLL != tc.dll {
				t.Errorf("DLL characteristic %v, want %v", isDLL, tc.dll)
			}
			switch oh := f.OptionalHeader.(type) {
			case *pe.OptionalHeader64:
				if oh.Magic != tc.optMag {
					t.Errorf("optional header magic %#x", oh.Magic)
				}
				if oh.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI {
					t.Errorf("subsystem %d, want console", oh.Subsystem)
				}
				if oh.AddressOfEntryPoint == 0 {
					t.Error("no entry point")
				}
			case *pe.OptionalHeader32:
				if oh.Magic != tc.optMag {
					t.Errorf("optional header magic %#x", oh.Magic)
				}
			default:
				t.Fatalf("no optional header")
			}

			for _, name := range []string{".text", ".rdata", ".data", ".idata", ".rsrc"} {
				if f.Section(name) == nil {
					t.Errorf("no %s section", name)
				}
			}
			if s := f.Section(".text"); s != nil && s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 {
				t.Error(".text is not executable")
			}
			syms, err := f.ImportedSymbols()
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(syms, " ")
			for _, want := range []string{"CreateFileW", "WriteFile", "RegOpenKeyExW"} {
				if !strings.Contains(got, want) {
					t.Errorf("imports %q do not name %s", got, want)
				}
			}
			if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
				t.Logf("libraries %v", libs)
			}
			// The overlay is everything past the last section's raw data.
			var end uint32
			for _, s := range f.Sections {
				end = max(end, s.Offset+s.Size)
			}
			if over := len(data) - int(end); over != 512 {
				t.Errorf("overlay of %d bytes, want 512", over)
			}
		})
	}
}

// TestPEChecksumIsTheWindowsAlgorithm: the stored checksum is the one the
// algorithm gives for the finished file.
func TestPEChecksumCoversTheWholeImage(t *testing.T) {
	data, err := BuildPE(samplePE(t, "amd64", false))
	if err != nil {
		t.Fatal(err)
	}
	lfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
	at := lfanew + 4 + 20 + 64 // the checksum field of the optional header
	stored := binary.LittleEndian.Uint32(data[at:])
	if stored == 0 {
		t.Fatal("checksum left at zero")
	}
	if want := peChecksum(data, at); stored != want {
		t.Errorf("checksum %#x, want %#x", stored, want)
	}
}

// imphash is how tools fingerprint an import table: every "dll.function"
// lowercased, in order, joined with commas.
func imphash(f *pe.File) (string, error) {
	syms, err := f.ImportedSymbols()
	if err != nil {
		return "", err
	}
	var parts []string
	for _, s := range syms {
		fn, dll, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		dll = strings.ToLower(dll)
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			dll = strings.TrimSuffix(dll, ext)
		}
		parts = append(parts, dll+"."+strings.ToLower(fn))
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:]), nil
}

// TestImphashStable: the same imports give the same imphash every build, and
// different imports give a different one.
func TestImphashStable(t *testing.T) {
	hash := func(spec PESpec) string {
		data, err := BuildPE(spec)
		if err != nil {
			t.Fatal(err)
		}
		f, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h, err := imphash(f)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a := hash(samplePE(t, "amd64", false))
	if b := hash(samplePE(t, "amd64", false)); a != b {
		t.Errorf("imphash %s then %s", a, b)
	}
	other := samplePE(t, "amd64", false)
	other.Imports, _ = ParseImports([]string{"ws2_32.dll!connect"})
	if c := hash(other); c == a {
		t.Error("a different import table gave the same imphash")
	}
	t.Logf("imphash %s", a)
}

func TestParseImportsGroupsAndRejects(t *testing.T) {
	got, err := ParseImports([]string{"a.dll!One", "b.dll!Two", "A.DLL!Three"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DLL != "a.dll" || len(got[0].Functions) != 2 || got[1].DLL != "b.dll" {
		t.Errorf("grouping = %+v", got)
	}
	for _, bad := range []string{"kernel32.dll", "!f", "d!", ""} {
		if _, err := ParseImports([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// TestZipIsReadableWithSizesInPlace: archive/zip reads what we write, every
// member is stored with its size in the local header (no data descriptor), and
// the order is the order given.
func TestZipIsReadableWithSizesInPlace(t *testing.T) {
	mod := time.Date(2022, 6, 1, 12, 0, 0, 0, time.UTC)
	entries := []ZipEntry{
		{Name: "docs/", Modified: mod},
		{Name: "docs/a.txt", Data: []byte("alpha"), Modified: mod},
		{Name: "b.bin", Data: bytes.Repeat([]byte{7}, 4096), Modified: mod},
	}
	data, err := BuildZip(entries, "written by fsagen")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Comment != "written by fsagen" {
		t.Errorf("comment %q", zr.Comment)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.Flags&0x8 != 0 {
			t.Errorf("%s: written with a data descriptor", f.Name)
		}
		if f.Method != zip.Store {
			t.Errorf("%s: method %d, want store", f.Name, f.Method)
		}
		if !f.Modified.Equal(mod) {
			t.Errorf("%s: modified %v, want %v", f.Name, f.Modified, mod)
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		r.Close()
		if buf.Len() != int(f.UncompressedSize64) {
			t.Errorf("%s: read %d bytes, header says %d", f.Name, buf.Len(), f.UncompressedSize64)
		}
	}
	if got := strings.Join(names, ","); got != "docs/,docs/a.txt,b.bin" {
		t.Errorf("order = %s", got)
	}

	// The sizes are in the local headers too. archive/zip never writes them
	// there (it streams, so it cannot), but almost every real archive has
	// them, and a carver reading a member out of a fragment has nothing else
	// to go on. This is why fsagen writes its own zip files.
	sizes := map[string]int{"docs/": 0, "docs/a.txt": 5, "b.bin": 4096}
	found := 0
	for off := 0; off+30 <= len(data) && string(data[off:off+4]) == "PK\x03\x04"; {
		nameLen := int(binary.LittleEndian.Uint16(data[off+26:]))
		extraLen := int(binary.LittleEndian.Uint16(data[off+28:]))
		csize := int(binary.LittleEndian.Uint32(data[off+18:]))
		usize := int(binary.LittleEndian.Uint32(data[off+22:]))
		name := string(data[off+30 : off+30+nameLen])
		want, ok := sizes[name]
		if !ok {
			t.Fatalf("local header for an unexpected member %q", name)
		}
		if csize != want || usize != want {
			t.Errorf("%s: local header says %d compressed, %d uncompressed; want %d", name, csize, usize, want)
		}
		found++
		off += 30 + nameLen + extraLen + csize
	}
	if found != len(sizes) {
		t.Errorf("walked %d local headers, want %d", found, len(sizes))
	}
}

// TestStoredZipOverheadIsExact: the size arithmetic that lets a scenario ask
// for an archive of a given length is right to the byte.
func TestStoredZipOverheadIsExact(t *testing.T) {
	for _, n := range []int{0, 1, 1000} {
		data, err := BuildZip([]ZipEntry{{Name: "data.bin", Data: make([]byte, n)}}, "note")
		if err != nil {
			t.Fatal(err)
		}
		if want := StoredZipOverhead([]string{"data.bin"}, "note") + n; len(data) != want {
			t.Errorf("%d bytes of member gave a %d byte archive, want %d", n, len(data), want)
		}
	}
}

func TestZipRefusesDuplicateAndAbsoluteNames(t *testing.T) {
	for _, entries := range [][]ZipEntry{
		{{Name: "a"}, {Name: "a"}},
		{{Name: "/a"}},
		{{Name: `a\b`}},
		{{Name: "d/", Data: []byte("x")}},
	} {
		if _, err := BuildZip(entries, ""); err == nil {
			t.Errorf("%v was accepted", entries)
		}
	}
}

// TestPNGDecodesAndCarriesPadding: image/png reads it, the padding rides in a
// private ancillary chunk, and the bytes do not depend on the Go release
// (the image data is a zlib stream of stored blocks).
func TestPNGDecodesAndCarriesPadding(t *testing.T) {
	pad := Filler(KindText, 300, stream(9))
	data, err := PNG(DefaultImageSize, DefaultImageSize, stream(5), pad)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("image/png cannot read it: %v", err)
	}
	if b := img.Bounds(); b.Dx() != DefaultImageSize || b.Dy() != DefaultImageSize {
		t.Errorf("bounds %v", b)
	}
	if !bytes.Contains(data, []byte(padChunk)) || !bytes.Contains(data, pad) {
		t.Error("the padding chunk is missing")
	}
	again, err := PNG(DefaultImageSize, DefaultImageSize, stream(5), pad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Error("two identical calls gave different bytes")
	}
	if other, _ := PNG(DefaultImageSize, DefaultImageSize, stream(6), pad); bytes.Equal(data, other) {
		t.Error("a different stream gave the same image")
	}
}

// TestJPEGDecodesAndCarriesPadding: image/jpeg reads it and the filler rides
// in comment segments.
func TestJPEGDecodesAndCarriesPadding(t *testing.T) {
	pad := Filler(KindText, 200, stream(9))
	data, err := JPEG(DefaultImageSize, DefaultImageSize, stream(5), pad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("image/jpeg cannot read it: %v", err)
	}
	if !bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff, 0xfe}) {
		t.Errorf("no comment segment after the start marker: % x", data[:8])
	}
	if !bytes.Contains(data, pad) {
		t.Error("the filler is missing")
	}
	// Each comment segment declares its own length including the two bytes
	// of the length field, and together they hold the filler and nothing
	// else. A decoder that trusted a wrong length would read into the image.
	var carried []byte
	off := 2
	for off+4 <= len(data) && data[off] == 0xff && data[off+1] == 0xfe {
		n := int(binary.BigEndian.Uint16(data[off+2:]))
		if n < 2 || off+2+n > len(data) {
			t.Fatalf("comment segment at %d declares %d bytes in a %d byte file", off, n, len(data))
		}
		carried = append(carried, data[off+4:off+2+n]...)
		off += 2 + n
	}
	if !bytes.Equal(carried, pad) {
		t.Errorf("the comment segments carry %d bytes, want the %d of filler", len(carried), len(pad))
	}
}

// boxes walks the top-level boxes of an ISO base media file.
func boxes(t *testing.T, data []byte) map[string]int {
	t.Helper()
	out := map[string]int{}
	for off := 0; off+8 <= len(data); {
		size := int(binary.BigEndian.Uint32(data[off:]))
		kind := string(data[off+4 : off+8])
		if size < 8 || off+size > len(data) {
			t.Fatalf("box %q at %d has size %d in a %d byte file", kind, off, size, len(data))
		}
		out[kind] = size
		off += size
	}
	return out
}

// TestMP4HasFtypMoovMdat: the box tree walks end to end and holds the boxes a
// tool looks for, with the payload in mdat.
func TestMP4HasFtypMoovMdat(t *testing.T) {
	created := time.Date(2023, 8, 1, 6, 0, 0, 0, time.UTC)
	payload := Filler(KindBytes, 1000, stream(3))
	data := MP4(created, 2*time.Second, 320, 240, payload)
	top := boxes(t, data)
	for _, kind := range []string{"ftyp", "moov", "mdat"} {
		if top[kind] == 0 {
			t.Errorf("no %s box (found %v)", kind, keys(top))
		}
	}
	if top["mdat"] != len(payload)+8 {
		t.Errorf("mdat is %d bytes, want %d", top["mdat"], len(payload)+8)
	}
	if !bytes.Contains(data, payload) {
		t.Error("the payload is not in the file")
	}
	// mvhd carries the creation time, counted from 1904.
	want := uint32(created.Sub(mp4Epoch) / time.Second)
	i := bytes.Index(data, []byte("mvhd"))
	if i < 0 {
		t.Fatal("no mvhd box")
	}
	if got := binary.BigEndian.Uint32(data[i+8:]); got != want {
		t.Errorf("mvhd creation time %d, want %d", got, want)
	}
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestFillerKinds: each kind gives exactly the length asked for and looks
// like what its name says.
func TestFillerKinds(t *testing.T) {
	const n = 4096
	for _, kind := range []string{"", KindText, KindBytes, KindZeros, KindPattern, KindLorem} {
		got := Filler(kind, n, stream(11))
		if len(got) != n {
			t.Errorf("%s: %d bytes, want %d", kind, len(got), n)
		}
		switch kind {
		case "", KindText:
			if strings.Trim(string(got), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
				t.Errorf("text is not base32: %q", got[:32])
			}
		case KindZeros:
			if !bytes.Equal(got, make([]byte, n)) {
				t.Error("zeros are not zero")
			}
		case KindPattern:
			if got[0] != 0 || got[255] != 255 || got[256] != 0 {
				t.Errorf("pattern does not ramp: % x", got[250:260])
			}
		case KindLorem:
			if !strings.HasPrefix(string(got), "lorem") && !strings.Contains(string(got), " ") {
				t.Errorf("lorem has no words: %q", got[:32])
			}
		}
	}
	if Filler(KindText, 0, stream(1)) != nil {
		t.Error("zero bytes should be nothing")
	}
}

// TestBytesEntropyAbove7_9At64KiB: content_kind bytes is high-entropy, which
// is what a scenario asking for it wants (an encrypted or packed blob).
func TestBytesEntropyAbove7_9At64KiB(t *testing.T) {
	data := Filler(KindBytes, 64*1024, stream(2))
	if e := entropy(data); e < 7.9 {
		t.Errorf("entropy %.3f, want at least 7.9", e)
	}
	if e := entropy(Filler(KindZeros, 64*1024, stream(2))); e != 0 {
		t.Errorf("zeros have entropy %.3f", e)
	}
	if e := entropy(Filler(KindText, 64*1024, stream(2))); e > 5.1 {
		t.Errorf("base32 text has entropy %.3f, want about 5", e)
	}
}

func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return h
}
