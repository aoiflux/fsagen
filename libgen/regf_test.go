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

	"github.com/aoiflux/libntfs"
)

// sampleHiveSpec exercises every way a hive stores things: names a byte per
// character and in UTF-16, values inline, in a cell and split into big-data
// segments, every value type, the default value, keys only given as parents,
// and a key with more subkeys than one hash leaf lists.
func sampleHiveSpec() HiveSpec {
	when := time.Date(2024, 3, 15, 9, 30, 12, 123456700, time.UTC)
	val := func(name, typ, data string, strs ...string) RegValue {
		code, b, err := ParseRegValue(typ, data, strs)
		if err != nil {
			panic(err)
		}
		return RegValue{Name: name, Type: code, Data: b}
	}
	large := make([]byte, 40000)
	for i := range large {
		large[i] = byte(i * 7)
	}
	keys := []RegKey{
		{Path: `Software\Microsoft\Windows\CurrentVersion\Run`, LastWritten: when.Add(time.Hour), Values: []RegValue{
			val("Updater", "REG_SZ", `C:\Users\user1\AppData\Local\Temp\wupdmgr32.exe /silent`),
			val("Count", "REG_DWORD", "7"),
			val("Big", "REG_QWORD", "0x1122334455667788"),
			val("Bin", "REG_BINARY", "01 02 03"),
			val("Five", "REG_BINARY", "0102030405"),
			val("Empty", "REG_BINARY", ""),
			val("EmptySz", "REG_SZ", ""),
			val("Multi", "REG_MULTI_SZ", "", "a", "bc"),
			val("Exp", "REG_EXPAND_SZ", `%TEMP%\x.exe`),
			val("BigEndian", "REG_DWORD_BIG_ENDIAN", "0x01020304"),
			val("Nothing", "REG_NONE", "ff"),
			{Name: "Large", Type: 3, Data: large},
			val("", "REG_SZ", "default"),
			val("Ünïcode", "REG_SZ", "x"),
			val("日本", "REG_SZ", "y"),
		}},
		{Path: `Software\Zeta`},
		{Path: `Software\alpha`},
		{Path: `Software\Beta`},
		{Path: `Software\Ünï`},
		{Path: `Software\日本語`, LastWritten: when.Add(2 * time.Hour)},
	}
	for i := range 600 {
		keys = append(keys, RegKey{Path: fmt.Sprintf(`Software\Many\K%03d`, i)})
	}
	keys = append(keys, UserAssistKeys([]UserAssist{
		{Path: `C:\Windows\System32\cmd.exe`, RunCount: 4, FocusCount: 2, FocusTimeMs: 61000, LastRun: when},
		{Path: `C:\Users\user1\Desktop\tool.lnk`, RunCount: 1, LastRun: when},
	}, when)...)
	usb, err := USBStorKeys([]USBDevice{{Vendor: "Generic", Product: "Storage Unit", Revision: "1.00", Serial: "4C530001231117116491",
		FirstInstall: when.Add(-24 * time.Hour), LastArrival: when, LastRemoval: when.Add(time.Hour)}}, when)
	if err != nil {
		panic(err)
	}
	keys = append(keys, usb...)
	return HiveSpec{FileName: `\??\C:\Users\user1\ntuser.dat`, Modified: when, Keys: keys}
}

type regReadKey struct {
	written time.Time
	values  []RegValue
	subkeys []string
}

// readHive parses a hive the way libregf documents the format, checking the
// base block, that the bins tile the file and their cells tile each bin,
// that every subkey list is sorted with the right hashes, and returns each
// key by path.
func readHive(t *testing.T, data []byte) map[string]regReadKey {
	t.Helper()
	le := binary.LittleEndian
	if string(data[:4]) != "regf" || le.Uint32(data[4:]) != le.Uint32(data[8:]) {
		t.Fatalf("base block: signature %q, sequence numbers %d and %d", data[:4], le.Uint32(data[4:]), le.Uint32(data[8:]))
	}
	sum := uint32(0)
	for i := 0; i < 508; i += 4 {
		sum ^= le.Uint32(data[i:])
	}
	if sum != le.Uint32(data[508:]) {
		t.Errorf("base block checksum %#x, stored %#x", sum, le.Uint32(data[508:]))
	}
	if le.Uint32(data[20:]) != 1 || le.Uint32(data[24:]) != 5 {
		t.Errorf("version %d.%d, want 1.5", le.Uint32(data[20:]), le.Uint32(data[24:]))
	}
	bins := data[4096:]
	if int(le.Uint32(data[40:])) != len(bins) {
		t.Fatalf("base block says %d bytes of bins, the file has %d", le.Uint32(data[40:]), len(bins))
	}
	for off := 0; off < len(bins); {
		if string(bins[off:off+4]) != "hbin" || int(le.Uint32(bins[off+4:])) != off {
			t.Fatalf("no bin at %#x", off)
		}
		size := int(le.Uint32(bins[off+8:]))
		if size%4096 != 0 {
			t.Errorf("bin at %#x is %d bytes", off, size)
		}
		for c := off + 32; c < off+size; {
			n := int(int32(le.Uint32(bins[c:])))
			n = max(n, -n)
			if n%8 != 0 || n == 0 || c+n > off+size {
				t.Fatalf("cell at %#x has size %d", c, n)
			}
			c += n
		}
		off += size
	}

	cell := func(off uint32) []byte {
		size := int32(le.Uint32(bins[off:]))
		if size >= 0 {
			t.Fatalf("offset %#x points at a free cell", off)
		}
		return bins[off+4 : off+uint32(-size)]
	}
	name := func(b []byte, latin1 bool) string {
		if latin1 {
			r := make([]rune, len(b))
			for i, c := range b {
				r[i] = rune(c)
			}
			return string(r)
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = le.Uint16(b[2*i:])
		}
		return string(utf16.Decode(u))
	}

	out := map[string]regReadKey{}
	var walk func(off uint32, path string)
	walk = func(off uint32, path string) {
		nk := cell(off)
		if string(nk[:2]) != "nk" {
			t.Fatalf("key at %#x: signature %q", off, nk[:2])
		}
		ft := le.Uint64(nk[4:])
		k := regReadKey{written: libntfs.FiletimeToTime(ft)}
		if sk := cell(le.Uint32(nk[44:])); string(sk[:2]) != "sk" {
			t.Errorf("key %q: security cell signature %q", path, sk[:2])
		}
		nvals, vlist := le.Uint32(nk[36:]), le.Uint32(nk[40:])
		for i := range nvals {
			vk := cell(le.Uint32(cell(vlist)[4*i:]))
			if string(vk[:2]) != "vk" {
				t.Fatalf("key %q value %d: signature %q", path, i, vk[:2])
			}
			nl := le.Uint16(vk[2:])
			v := RegValue{Name: name(vk[20:20+nl], le.Uint16(vk[16:])&1 != 0), Type: le.Uint32(vk[12:])}
			size, dataOff := le.Uint32(vk[4:]), le.Uint32(vk[8:])
			switch {
			case size&0x80000000 != 0:
				v.Data = le.AppendUint32(nil, dataOff)[:size&0x7FFFFFFF]
			case size > regBigData:
				db := cell(dataOff)
				if string(db[:2]) != "db" {
					t.Fatalf("value %q of %d bytes is not behind a big-data cell", v.Name, size)
				}
				list := cell(le.Uint32(db[4:]))
				for s := range le.Uint16(db[2:]) {
					seg := cell(le.Uint32(list[4*s:]))
					if len(seg) < regBigData {
						t.Errorf("value %q: segment %d holds %d bytes; Windows drops a value with a segment under %d", v.Name, s, len(seg), regBigData)
					}
					v.Data = append(v.Data, seg[:min(regBigData, int(size)-len(v.Data))]...)
				}
			default:
				v.Data = cell(dataOff)[:size]
			}
			k.values = append(k.values, v)
		}
		nsub, list := le.Uint32(nk[20:]), le.Uint32(nk[28:])
		var leaves [][]byte
		if nsub > 0 {
			l := cell(list)
			switch string(l[:2]) {
			case "lh":
				leaves = [][]byte{l}
			case "ri":
				for i := range le.Uint16(l[2:]) {
					leaves = append(leaves, cell(le.Uint32(l[4+4*i:])))
				}
			default:
				t.Fatalf("key %q: subkey list %q", path, l[:2])
			}
		}
		var children []uint32
		for _, l := range leaves {
			if string(l[:2]) != "lh" {
				t.Fatalf("key %q: leaf %q", path, l[:2])
			}
			for i := range le.Uint16(l[2:]) {
				c := le.Uint32(l[4+8*i:])
				children = append(children, c)
				ck := cell(c)
				cname := name(ck[76:76+le.Uint16(ck[72:])], le.Uint16(ck[2:])&0x20 != 0)
				if h := le.Uint32(l[8+8*i:]); h != regHashRef(cname) {
					t.Errorf("key %q: subkey %q has hash %#x, want %#x", path, cname, h, regHashRef(cname))
				}
				if le.Uint32(ck[16:]) != off {
					t.Errorf("subkey %q does not name %q as its parent", cname, path)
				}
				k.subkeys = append(k.subkeys, cname)
			}
		}
		if len(children) != int(nsub) {
			t.Errorf("key %q counts %d subkeys and lists %d", path, nsub, len(children))
		}
		if !slices.IsSortedFunc(k.subkeys, func(a, b string) int { return strings.Compare(strings.ToUpper(a), strings.ToUpper(b)) }) {
			t.Errorf("key %q lists its subkeys out of order: %q", path, k.subkeys)
		}
		out[path] = k
		for i, c := range children {
			walk(c, path+`\`+k.subkeys[i])
		}
	}
	root := le.Uint32(data[36:])
	if flags := le.Uint16(cell(root)[2:]); flags&0x04 == 0 {
		t.Errorf("root key flags %#x lack KEY_HIVE_ENTRY", flags)
	}
	walk(root, "")
	return out
}

// regHashRef is the hash libregf documents, written out again here.
func regHashRef(s string) uint32 {
	h := uint32(0)
	for _, r := range strings.ToUpper(s) {
		h = h*37 + uint32(r)
	}
	return h
}

// TestHiveReadBack: a reader written from the format's documentation finds
// every key at its path with its time, and every value with its type and
// data, in a hive whose structure checks out.
func TestHiveReadBack(t *testing.T) {
	spec := sampleHiveSpec()
	data, err := BuildHive(spec)
	if err != nil {
		t.Fatal(err)
	}
	got := readHive(t, data)
	run := got[`\Software\Microsoft\Windows\CurrentVersion\Run`]
	want := spec.Keys[0]
	if !run.written.Equal(want.LastWritten) {
		t.Errorf("Run written %v, want %v", run.written, want.LastWritten)
	}
	if len(run.values) != len(want.Values) {
		t.Fatalf("Run has %d values, want %d", len(run.values), len(want.Values))
	}
	for i, v := range run.values {
		w := want.Values[i]
		if v.Name != w.Name || v.Type != w.Type || !bytes.Equal(v.Data, w.Data) {
			t.Errorf("value %d: %q type %d, %d bytes; want %q type %d, %d bytes", i, v.Name, v.Type, len(v.Data), w.Name, w.Type, len(w.Data))
		}
	}
	if sw := got[`\Software`]; !slices.Equal(sw.subkeys, []string{"alpha", "Beta", "Many", "Microsoft", "Zeta", "Ünï", "日本語"}) {
		t.Errorf("Software's subkeys %q", sw.subkeys)
	}
	if got := got[`\Software\Many`].subkeys; len(got) != 600 || got[0] != "K000" || got[599] != "K599" {
		t.Errorf("Many has %d subkeys", len(got))
	}
	if w := got[`\Software\日本語`].written; !w.Equal(spec.Keys[5].LastWritten) {
		t.Errorf("日本語 written %v", w)
	}
	if w := got[`\Software\Microsoft`].written; !w.Equal(spec.Modified) {
		t.Errorf("a parent the spec did not give is dated %v, want the hive's time", w)
	}
	again, _ := BuildHive(sampleHiveSpec())
	if !bytes.Equal(data, again) {
		t.Error("the same spec gave two different hives")
	}
}

// TestRegValues: each value type parses as the hive stores it, and what a
// type cannot hold is refused.
func TestRegValues(t *testing.T) {
	for _, tc := range []struct {
		typ, data string
		strs      []string
		want      []byte
	}{
		{"REG_SZ", "ab", nil, []byte{'a', 0, 'b', 0, 0, 0}},
		{"REG_DWORD", "0x10", nil, []byte{0x10, 0, 0, 0}},
		{"REG_DWORD_BIG_ENDIAN", "1", nil, []byte{0, 0, 0, 1}},
		{"REG_QWORD", "1", nil, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{"REG_BINARY", "de ad BE EF", nil, []byte{0xde, 0xad, 0xbe, 0xef}},
		{"REG_MULTI_SZ", "", []string{"a", "b"}, []byte{'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0}},
	} {
		_, got, err := ParseRegValue(tc.typ, tc.data, tc.strs)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s %q %q: % x, %v; want % x", tc.typ, tc.data, tc.strs, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		typ, data string
		strs      []string
	}{
		{"REG_DWORD", "4294967296", nil}, {"REG_QWORD", "-1", nil}, {"REG_BINARY", "zz", nil},
		{"REG_MULTI_SZ", "a", nil}, {"REG_MULTI_SZ", "", []string{""}}, {"REG_SZ", "", []string{"a"}},
		{"REG_LINK", "x", nil},
	} {
		if _, _, err := ParseRegValue(tc.typ, tc.data, tc.strs); err == nil {
			t.Errorf("%s %q %q was accepted", tc.typ, tc.data, tc.strs)
		}
	}
	for _, p := range []string{`a\\b`, strings.Repeat("k", 256)} {
		if _, err := SplitRegPath(p); err == nil {
			t.Errorf("key path %q was accepted", p)
		}
	}
	if _, err := BuildHive(HiveSpec{Keys: []RegKey{{Path: `A\b`}, {Path: `a\B`}}}); err == nil {
		t.Error("the same key given twice, in another case, was accepted")
	}
}
