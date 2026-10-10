package libgen

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
)

// ovbaDecompress is [MS-OVBA] 2.4.1.3.1, written from the specification
// rather than from the compressor: chunks of tokens, each copy token split
// into offset and length by how far into its chunk it is.
func ovbaDecompress(c []byte) ([]byte, error) {
	if len(c) == 0 || c[0] != 1 {
		return nil, fmt.Errorf("no signature byte")
	}
	var out []byte
	for i := 1; i < len(c); {
		if i+2 > len(c) {
			return nil, fmt.Errorf("truncated chunk header at %d", i)
		}
		h := binary.LittleEndian.Uint16(c[i:])
		size, compressed := int(h&0x0FFF)+3, h&0x8000 != 0
		if h&0x7000 != 0x3000 {
			return nil, fmt.Errorf("chunk signature %#x at %d", h&0x7000, i)
		}
		if i+size > len(c) {
			return nil, fmt.Errorf("chunk at %d runs past the end", i)
		}
		chunk, start := c[i+2:i+size], len(out)
		i += size
		if !compressed {
			if len(chunk) != 4096 {
				return nil, fmt.Errorf("raw chunk of %d bytes", len(chunk))
			}
			out = append(out, chunk...)
			continue
		}
		for j := 0; j < len(chunk); {
			flags := chunk[j]
			j++
			for bit := 0; bit < 8 && j < len(chunk); bit++ {
				if flags&(1<<bit) == 0 {
					out = append(out, chunk[j])
					j++
					continue
				}
				if j+2 > len(chunk) {
					return nil, fmt.Errorf("truncated copy token")
				}
				tok := binary.LittleEndian.Uint16(chunk[j:])
				j += 2
				diff := len(out) - start
				bitCount := 4
				for 1<<bitCount < diff {
					bitCount++
				}
				length := int(tok&(0xFFFF>>bitCount)) + 3
				offset := int(tok>>(16-bitCount)) + 1
				if offset > diff {
					return nil, fmt.Errorf("copy from %d bytes back, %d into the chunk", offset, diff)
				}
				for k := 0; k < length; k++ {
					out = append(out, out[len(out)-offset])
				}
			}
		}
		if len(out)-start > 4096 {
			return nil, fmt.Errorf("chunk decompressed to %d bytes", len(out)-start)
		}
	}
	return out, nil
}

// TestOVBARoundTrip: what the compressor writes, the specification's
// decompressor reads back exactly, for text, runs, random bytes (which go in
// raw chunks) and sizes on either side of a chunk.
func TestOVBARoundTrip(t *testing.T) {
	s := prng.Root(7).Derive("ovba").Stream()
	inputs := map[string][]byte{
		"empty":   nil,
		"short":   []byte("ab"),
		"run":     bytes.Repeat([]byte{'a'}, 10000),
		"text":    []byte(strings.Repeat("Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nEnd Sub\r\n", 200)),
		"random":  s.Bytes(9000),
		"chunk":   []byte(s.Text(4096)),
		"chunk+1": []byte(s.Text(4097)),
	}
	for name, in := range inputs {
		got, err := ovbaDecompress(OVBACompress(in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// A raw chunk is padded to 4096 bytes; only the last chunk can be
		// short, and random bytes fill whole ones here.
		if !bytes.Equal(got, in) {
			t.Errorf("%s: %d bytes in, %d back, first difference at %d", name, len(in), len(got), firstDiff(got, in))
		}
	}
	if c := OVBACompress(bytes.Repeat([]byte{'a'}, 4096)); len(c) > 64 {
		t.Errorf("4096 repeated bytes compressed to %d bytes", len(c))
	}
}

// TestOVBASpecExamples: the compressor chooses its matches as the
// specification does, so the three worked examples of [MS-OVBA] 3.2 (no,
// normal and maximum compression) come out byte for byte.
func TestOVBASpecExamples(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abcdefghijklmnopqrstuv.", "01 19 B0 00 61 62 63 64 65 66 67 68 00 69 6A 6B 6C 6D 6E 6F 70 00 71 72 73 74 75 76 2E"},
		{"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa", "01 2F B0 00 23 61 61 61 62 63 64 65 82 66 00 70 61 67 68 69 6A 01 38 08 61 6B 6C 00 20 6D 6E 6F 70 06 71 02 70 04 00 72 73 74 75 76 10 77 78 79 7A 00 2C"},
		{strings.Repeat("a", 73), "01 03 B0 02 61 45 00"},
	} {
		want, err := hex.DecodeString(strings.ReplaceAll(tc.want, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		if got := OVBACompress([]byte(tc.in)); !bytes.Equal(got, want) {
			t.Errorf("%q compressed to\n%x\nwant\n%x", tc.in, got, want)
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// cfbFile is a compound file read back by readCFB: each stream's bytes by
// its path, each storage's children in tree order, and how many entries are
// red (fsagen writes none; Office writes a true red-black tree).
type cfbFile struct {
	streams map[string][]byte
	order   map[string][]string
	red     int
}

// readCFB reads a version 3 compound file as [MS-CFB] describes it, checking
// as it goes what a strict reader would: the header, every chain, and that
// each storage's children form a binary search tree in the specification's
// order.
func readCFB(b []byte) (*cfbFile, error) {
	if len(b) < 512 || !bytes.Equal(b[:8], cfbSignature) || len(b)%512 != 0 {
		return nil, fmt.Errorf("not a sector-aligned compound file")
	}
	u16 := func(o int) int { return int(binary.LittleEndian.Uint16(b[o:])) }
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	if u16(0x1A) != 3 || u16(0x1C) != 0xFFFE || u16(0x1E) != 9 || u16(0x20) != 6 || u32(0x38) != 4096 || u32(0x44) != cfbEndOfChain || u32(0x48) != 0 {
		return nil, fmt.Errorf("header fields: %x", b[0x18:0x4C])
	}
	nSectors := len(b)/512 - 1
	sector := func(n uint32) []byte { return b[512*(1+int(n)) : 512*(2+int(n))] }
	var fat []uint32
	for i := 0; i < int(u32(0x2C)); i++ {
		s := sector(u32(0x4C + 4*i))
		for j := 0; j < 128; j++ {
			fat = append(fat, binary.LittleEndian.Uint32(s[4*j:]))
		}
	}
	chain := func(table []uint32, start uint32, limit int) ([]uint32, error) {
		var out []uint32
		for n := start; n != cfbEndOfChain; n = table[n] {
			if int(n) >= limit || len(out) > limit {
				return nil, fmt.Errorf("chain from %d runs to %d", start, n)
			}
			out = append(out, n)
		}
		return out, nil
	}
	read := func(start uint32) ([]byte, error) {
		ch, err := chain(fat, start, nSectors)
		var out []byte
		for _, n := range ch {
			out = append(out, sector(n)...)
		}
		return out, err
	}
	dir, err := read(u32(0x30))
	if err != nil {
		return nil, err
	}
	type entry struct {
		name               string
		kind               byte
		left, right, child uint32
		start              uint32
		size               uint64
	}
	var entries []entry
	red := 0
	for i := 0; i+128 <= len(dir); i += 128 {
		e := dir[i : i+128]
		nl := int(binary.LittleEndian.Uint16(e[0x40:]))
		var units []uint16
		for k := 0; k+2 < nl; k += 2 {
			units = append(units, binary.LittleEndian.Uint16(e[k:]))
		}
		entries = append(entries, entry{
			name: string(utf16.Decode(units)), kind: e[0x42],
			left: binary.LittleEndian.Uint32(e[0x44:]), right: binary.LittleEndian.Uint32(e[0x48:]), child: binary.LittleEndian.Uint32(e[0x4C:]),
			start: binary.LittleEndian.Uint32(e[0x74:]), size: binary.LittleEndian.Uint64(e[0x78:]),
		})
		if e[0x42] != 0 && e[0x43] != cfbColorBlack {
			red++
		}
	}
	if entries[0].kind != cfbTypeRoot {
		return nil, fmt.Errorf("first entry is not the root")
	}
	mini, err := read(entries[0].start)
	if err != nil {
		return nil, err
	}
	var miniFAT []uint32
	if mf, err := read(u32(0x3C)); err == nil {
		for j := 0; j+4 <= len(mf); j += 4 {
			miniFAT = append(miniFAT, binary.LittleEndian.Uint32(mf[j:]))
		}
	} else {
		return nil, err
	}

	f := &cfbFile{streams: map[string][]byte{}, order: map[string][]string{}, red: red}
	var walk func(id uint32, dir string, lo, hi string) error
	walk = func(id uint32, dir string, lo, hi string) error {
		if id == cfbNoStream {
			return nil
		}
		e := entries[id]
		if (lo != "" && cfbLess(lo, e.name) >= 0) || (hi != "" && cfbLess(e.name, hi) >= 0) {
			return fmt.Errorf("%s/%s is out of order between %q and %q", dir, e.name, lo, hi)
		}
		if err := walk(e.left, dir, lo, e.name); err != nil {
			return err
		}
		f.order[dir] = append(f.order[dir], e.name)
		p := strings.TrimPrefix(dir+"/"+e.name, "/")
		switch e.kind {
		case cfbTypeStorage:
			if err := walk(e.child, p, "", ""); err != nil {
				return err
			}
		case cfbTypeStream:
			var data []byte
			if e.size < 4096 {
				ch, err := chain(miniFAT, e.start, len(mini)/64)
				if err != nil && e.size > 0 {
					return err
				}
				for _, n := range ch {
					data = append(data, mini[64*n:64*n+64]...)
				}
			} else {
				if data, err = read(e.start); err != nil {
					return err
				}
			}
			if uint64(len(data)) < e.size {
				return fmt.Errorf("%s holds %d bytes, its entry says %d", p, len(data), e.size)
			}
			f.streams[p] = data[:e.size]
		default:
			return fmt.Errorf("%s has type %d", p, e.kind)
		}
		return walk(e.right, dir, e.name, hi)
	}
	return f, walk(entries[0].child, "", "", "")
}

// TestCFBReadBack: a compound file holding streams of every size class
// (empty, in the mini stream, at the cutoff, spanning sectors) and nested
// storages reads back exactly, its trees in the specification's order.
func TestCFBReadBack(t *testing.T) {
	s := prng.Root(3).Derive("cfb").Stream()
	var many []CFBEntry
	for i := range 40 {
		many = append(many, CFBEntry{Name: fmt.Sprintf("s%02d", 39-i), Data: s.Bytes(i * 37)})
	}
	entries := []CFBEntry{
		{Name: "VBA", Storage: true, Children: []CFBEntry{
			{Name: "dir", Data: s.Bytes(700)},
			{Name: "_VBA_PROJECT", Data: []byte{0xCC, 0x61, 0xFF, 0xFF, 0, 0, 0}},
			{Name: "Module1", Data: s.Bytes(4095)},
			{Name: "Big", Data: s.Bytes(4096)},
			{Name: "Bigger", Data: s.Bytes(70000)},
			{Name: "Empty"},
			{Name: "Deep", Storage: true, Children: many},
		}},
		{Name: "PROJECT", Data: []byte("ID=\"{x}\"\r\n")},
		{Name: "PROJECTwm", Data: s.Bytes(100)},
	}
	b, err := BuildCFB(entries)
	if err != nil {
		t.Fatal(err)
	}
	f, err := readCFB(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.red != 0 {
		t.Errorf("%d entries are red", f.red)
	}
	var check func(dir string, es []CFBEntry)
	check = func(dir string, es []CFBEntry) {
		for _, e := range es {
			p := strings.TrimPrefix(dir+"/"+e.Name, "/")
			if e.Storage {
				check(p, e.Children)
				continue
			}
			if got, ok := f.streams[p]; !ok || !bytes.Equal(got, e.Data) {
				t.Errorf("%s: %d bytes back, want %d", p, len(got), len(e.Data))
			}
		}
	}
	check("", entries)
	if got := strings.Join(f.order["VBA"], ","); got != "Big,dir,Deep,Empty,Bigger,Module1,_VBA_PROJECT" {
		t.Errorf("VBA's children in tree order: %s", got)
	}
	if again, _ := BuildCFB(entries); !bytes.Equal(again, b) {
		t.Error("the same entries gave different bytes")
	}
}

// Names a directory entry cannot hold, and two entries one storage cannot
// tell apart, are refused.
func TestCFBRefuses(t *testing.T) {
	for _, tc := range []struct {
		entries []CFBEntry
		want    string
	}{
		{[]CFBEntry{{Name: ""}}, "has no name"},
		{[]CFBEntry{{Name: strings.Repeat("x", 32)}}, "longer than the 31"},
		{[]CFBEntry{{Name: "a/b"}}, "contains a character"},
		{[]CFBEntry{{Name: "Module1"}, {Name: "MODULE1"}}, "two entries named"},
	} {
		if _, err := BuildCFB(tc.entries); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.entries, err, tc.want)
		}
	}
}

// ovbaDecrypt reverses the specification's data encryption (2.4.3.3),
// returning the project key it was made with and the data.
func ovbaDecrypt(enc []byte) (key byte, data []byte, err error) {
	if len(enc) < 3 {
		return 0, nil, fmt.Errorf("too short")
	}
	seed := enc[0]
	if enc[1]^seed != 2 {
		return 0, nil, fmt.Errorf("version %d", enc[1]^seed)
	}
	key = enc[2] ^ seed
	plain1, enc1, enc2 := key, enc[2], enc[1]
	var out []byte
	for _, e := range enc[3:] {
		c := e ^ (enc2 + plain1)
		out = append(out, c)
		enc2, enc1, plain1 = enc1, e, c
	}
	skip := int(seed&6) / 2
	if len(out) < skip+4 {
		return 0, nil, fmt.Errorf("no length")
	}
	n := int(binary.LittleEndian.Uint32(out[skip:]))
	if len(out) != skip+4+n {
		return 0, nil, fmt.Errorf("length %d, %d bytes follow", n, len(out)-skip-4)
	}
	return key, out[skip+4:], nil
}

// dirRecords splits a decompressed dir stream into its records, in order.
// The version record's size field says 4 but six bytes follow.
func dirRecords(d []byte) ([][2]any, error) {
	var out [][2]any
	for i := 0; i < len(d); {
		if i+6 > len(d) {
			return nil, fmt.Errorf("truncated record at %d", i)
		}
		id := binary.LittleEndian.Uint16(d[i:])
		size := int(binary.LittleEndian.Uint32(d[i+2:]))
		if id == 0x0009 {
			size = 6
		}
		if i+6+size > len(d) {
			return nil, fmt.Errorf("record %#x at %d runs past the end", id, i)
		}
		out = append(out, [2]any{id, d[i+6 : i+6+size]})
		i += 6 + size
	}
	return out, nil
}

// TestVBAProjectReadBack: each project reads back as a compound file whose
// streams say what the specification says they must, and whose modules
// decompress to exactly the inert source.
func TestVBAProjectReadBack(t *testing.T) {
	for _, spec := range []VBASpec{
		{Host: VBAWord, EntryPoint: "AutoOpen", Marker: "FSAGEN-VBA:word"},
		{Host: VBAWord, EntryPoint: "Document_Open", Marker: "m"},
		{Host: VBAExcel, EntryPoint: "Auto_Open", Module: "Loader", Marker: "FSAGEN-VBA:excel"},
		{Host: VBAExcel, EntryPoint: "Workbook_Open", Marker: "x y"},
	} {
		t.Run(spec.EntryPoint, func(t *testing.T) {
			b, err := BuildVBAProject(spec, prng.Root(1).Derive("vba").Stream())
			if err != nil {
				t.Fatal(err)
			}
			f, err := readCFB(b)
			if err != nil || f.red != 0 {
				t.Fatalf("%v (%d red entries)", err, f.red)
			}
			if got := f.streams["VBA/_VBA_PROJECT"]; !bytes.Equal(got, []byte{0xCC, 0x61, 0xFF, 0xFF, 0, 0, 0}) {
				t.Errorf("_VBA_PROJECT = %x", got)
			}
			modules := VBAModules(spec)
			checkProjectStream(t, string(f.streams["PROJECT"]), spec, modules)
			checkDir(t, f.streams["VBA/dir"], spec, modules)
			var wm []byte
			for _, m := range modules {
				wm = append(append(append(wm, m.Name...), 0), utf16z(m.Name)...)
				src, err := ovbaDecompress(f.streams["VBA/"+m.Name])
				if err != nil || string(src) != m.Source {
					t.Errorf("module %s: %v\n%s", m.Name, err, src)
				}
				if !strings.Contains(m.Source, `Attribute VB_Name = "`+m.Name+`"`) {
					t.Errorf("module %s does not name itself", m.Name)
				}
			}
			if got := f.streams["PROJECTwm"]; !bytes.Equal(got, append(wm, 0, 0)) {
				t.Errorf("PROJECTwm = %q", got)
			}
			all := ""
			for _, m := range modules {
				all += m.Source
			}
			if strings.Count(all, spec.EntryPoint+"()") != 1 || strings.Count(all, `marker = "`+spec.Marker+`"`) != 1 {
				t.Errorf("the entry point and marker are not there once each:\n%s", all)
			}
		})
	}
}

func checkProjectStream(t *testing.T, project string, spec VBASpec, modules []VBAModule) {
	t.Helper()
	lines := strings.Split(project, "\r\n")
	id := strings.TrimSuffix(strings.TrimPrefix(lines[0], `ID="`), `"`)
	if _, err := ParseGUID(id); err != nil || !strings.HasPrefix(id, "{") {
		t.Errorf("first line %q", lines[0])
	}
	var sum byte
	for _, c := range []byte(id) {
		sum += c
	}
	for i, m := range modules {
		want := "Module=" + m.Name
		if m.Document {
			want = "Document=" + m.Name + "/&H00000000"
		}
		if lines[1+i] != want {
			t.Errorf("line %d = %q, want %q", 2+i, lines[1+i], want)
		}
	}
	for field, want := range map[string]string{"CMG": "00000000", "DPB": "00", "GC": "ff"} {
		var hexed string
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, field+`="`); ok {
				hexed = strings.TrimSuffix(v, `"`)
			}
		}
		enc, err := hex.DecodeString(hexed)
		if err != nil || hexed != strings.ToUpper(hexed) {
			t.Errorf("%s=%q", field, hexed)
			continue
		}
		key, data, err := ovbaDecrypt(enc)
		if err != nil || key != sum || hex.EncodeToString(data) != want {
			t.Errorf("%s decrypts to key %#x data %x (%v), want key %#x data %s", field, key, data, err, sum, want)
		}
	}
	if !strings.Contains(project, "\r\nName=\""+vbaProjectName[spec.Host]+"\"\r\n") || !strings.HasSuffix(project, "\r\n") {
		t.Errorf("PROJECT:\n%s", project)
	}
}

func checkDir(t *testing.T, compressed []byte, spec VBASpec, modules []VBAModule) {
	t.Helper()
	d, err := ovbaDecompress(compressed)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := dirRecords(d)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	var names []string
	for _, r := range recs {
		id, data := r[0].(uint16), r[1].([]byte)
		ids = append(ids, fmt.Sprintf("%04x", id))
		switch id {
		case 0x0004:
			if string(data) != vbaProjectName[spec.Host] {
				t.Errorf("project name %q", data)
			}
		case 0x000D:
			if !bytes.Contains(data, []byte(stdoleLibid)) {
				t.Errorf("reference %q", data)
			}
		case 0x0019:
			names = append(names, string(data))
		case 0x0031:
			if binary.LittleEndian.Uint32(data) != 0 {
				t.Errorf("module source does not start its stream")
			}
		}
	}
	head := "0001 0002 0014 0003 0004 0005 0040 0006 003d 0007 0008 0009 000c 003c 0016 003e 000d 000f 0013"
	if got := strings.Join(ids, " "); !strings.HasPrefix(got, head) || !strings.HasSuffix(got, "002b 0010") {
		t.Errorf("records: %s", got)
	}
	var want []string
	for _, m := range modules {
		want = append(want, m.Name)
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("modules %v, want %v", names, want)
	}
}

// A macro the project cannot hold, or a body that would be anything but
// inert, is refused.
func TestCheckVBA(t *testing.T) {
	ok := VBASpec{Host: VBAWord, EntryPoint: "AutoOpen", Marker: "m"}
	for _, tc := range []struct {
		edit func(*VBASpec)
		want string
	}{
		{func(s *VBASpec) { s.EntryPoint = "Workbook_Open" }, "want one of: AutoOpen, Document_Open"},
		{func(s *VBASpec) { s.EntryPoint, s.Module = "Document_Open", "M" }, "no module to name"},
		{func(s *VBASpec) { s.Module = "1st" }, "not a VBA name"},
		{func(s *VBASpec) { s.Module = "thisdocument" }, "the document's own module"},
		{func(s *VBASpec) { s.Module = "Project" }, "the project's name"},
		{func(s *VBASpec) { s.Marker = "" }, "1 to 200"},
		{func(s *VBASpec) { s.Marker = `a" & Shell("calc") & "` }, "no double quote"},
		{func(s *VBASpec) { s.Marker = "a\r\nShell" }, "printable ASCII"},
	} {
		s := ok
		tc.edit(&s)
		if err := CheckVBA(s); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", s, err, tc.want)
		}
	}
	if err := CheckVBA(ok); err != nil {
		t.Error(err)
	}
}
