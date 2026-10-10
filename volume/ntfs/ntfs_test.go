package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

var le = binary.LittleEndian

var clock = time.Date(2022, 6, 1, 8, 0, 0, 0, time.UTC)

// testVolume is an NTFS volume in a file.
type testVolume struct {
	*volume.Volume
	fs   *FS
	file *os.File
}

func newVolume(t *testing.T, size int64, clusterSize int, policy string) testVolume {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "ntfs.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	res := &volume.Tracker{}
	fsys, err := Format(volume.NewDevice(f, 0, size), Options{ClusterSize: clusterSize, Label: "test", Serial: 0x0123456789ABCDEF, Clock: clock, Alloc: policy}, res)
	if err != nil {
		t.Fatal(err)
	}
	return testVolume{volume.New(fsys, res, f), fsys, f}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// record reads record num as it is on disk, its update sequence array
// undone.
func (v testVolume) record(t *testing.T, num uint32) []byte {
	t.Helper()
	off, _, err := v.fs.at(v.fs.mft.find(atData, "").runs, int64(num)*recordSize)
	must(t, err)
	b := make([]byte, recordSize)
	_, err = v.file.ReadAt(b, off)
	must(t, err)
	must(t, unprotect(b))
	return b
}

func (v testVolume) num(t *testing.T, name string) uint32 {
	t.Helper()
	n, err := v.Node(name)
	must(t, err)
	return nodeOf(n).rec.num
}

// finish finishes the volume and reads it back. Where The Sleuth Kit and
// ntfs-3g are installed, fls and ntfsls must read the volume too, and fls
// list every name fsagen's reader does.
func (v testVolume) finish(t *testing.T) (target.Reader, []target.Residue) {
	t.Helper()
	r, err := v.Finish()
	must(t, err)
	if fls, err := exec.LookPath("fls"); err == nil {
		out, err := exec.Command(fls, "-r", "-p", v.file.Name()).CombinedOutput()
		if err != nil {
			t.Fatalf("fls: %v\n%s", err, out)
		}
		must(t, r.WalkDir(func(name string, d os.DirEntry, err error) error {
			if err == nil && name != "." && !strings.Contains(string(out), ":\t"+name+"\n") {
				t.Errorf("fls does not list %s:\n%s", name, out)
			}
			return err
		}))
	}
	if ntfsls, err := exec.LookPath("ntfsls"); err == nil {
		if out, err := exec.Command(ntfsls, "-R", "-a", v.file.Name()).CombinedOutput(); err != nil {
			t.Fatalf("ntfsls: %v\n%s", err, out)
		}
	}
	return r, v.Residue()
}

// The geometry mkntfs 2022.10.3 gave each size and cluster size: its
// clusters, where $MFT, $MFTMirr and $LogFile start, and $LogFile's size.
func TestPlanMatchesMkntfs(t *testing.T) {
	const mib = 1 << 20
	for _, c := range []struct {
		size                       int64
		cs                         int
		clusters, mft, mirror, log int64
		logSize                    int64
	}{
		{3 * mib, 0, 767, 4, 383, 384, 512 << 10},
		{8 * mib, 0, 2047, 4, 1023, 1024, 2 * mib},
		{64 * mib, 0, 16383, 4, 8191, 8192, 2 * mib},
		{64 * mib, 512, 131071, 32, 65535, 65543, 2 * mib},
		{64 * mib, 1024, 65535, 16, 32767, 32771, 2 * mib},
		{64 * mib, 2048, 32767, 8, 16383, 16385, 2 * mib},
		{64 * mib, 8192, 8191, 2, 4095, 4096, 2 * mib},
		{64 * mib, 65536, 1023, 2, 511, 512, 2 * mib},
		{1 << 30, 0, 262143, 4, 131071, 131072, (1<<30 - 4096) / 200 &^ 4095},
		{16 << 30, 0, 4194303, 4, 2097151, 2097152, 64 * mib},
	} {
		g, err := Plan(c.size, c.cs)
		must(t, err)
		if g.Clusters != c.clusters || g.MFT != c.mft || g.Mirror != c.mirror || g.Log != c.log || g.LogSize != c.logSize {
			t.Errorf("%d MiB, %d-byte clusters: %+v", c.size/mib, c.cs, g)
		}
	}
	if _, err := Plan(1<<20, 0); err == nil {
		t.Error("1 MiB less a sector was accepted")
	}
	if _, err := Plan(64<<20, 3000); err == nil {
		t.Error("a 3000-byte cluster was accepted")
	}
	if _, err := Plan(64<<20, 4<<20); err == nil {
		t.Error("a 4 MiB cluster was accepted")
	}
}

// An empty volume is mkntfs's, byte for byte, when mkntfs is given the same
// serial number, partition start and time (its -T, 1970): only the boot
// code, which fsagen leaves out, and the padding mkntfs leaves holding what
// its buffers held, differ. It runs where mkntfs is on the path.
func TestFormatMatchesMkntfs(t *testing.T) {
	mkntfs, err := exec.LookPath("mkntfs")
	if err != nil {
		t.Skip("mkntfs (ntfs-3g) is not installed")
	}
	const mib = 1 << 20
	for _, c := range []struct {
		size  int64
		cs    int
		label string
	}{{3 * mib, 0, ""}, {8 * mib, 0, ""}, {64 * mib, 0, ""}, {64 * mib, 0, "EVIDENCE"}, {64 * mib, 512, ""}, {64 * mib, 1024, ""}, {64 * mib, 2048, ""}, {64 * mib, 8192, ""}, {64 * mib, 65536, ""}} {
		t.Run(fmt.Sprintf("%dMiB-%d-%s", c.size/mib, c.cs, c.label), func(t *testing.T) {
			ref := filepath.Join(t.TempDir(), "mkntfs.img")
			must(t, os.WriteFile(ref, nil, 0o644))
			must(t, os.Truncate(ref, c.size))
			args := []string{"-q", "-F", "-Q", "-T", "-p", "2048", "-H", "255", "-S", "63"}
			if c.cs != 0 {
				args = append(args, "-c", fmt.Sprint(c.cs))
			}
			if c.label != "" {
				args = append(args, "-L", c.label)
			}
			if out, err := exec.Command(mkntfs, append(args, ref)...).CombinedOutput(); err != nil {
				t.Fatalf("mkntfs: %v\n%s", err, out)
			}
			theirs, err := os.ReadFile(ref)
			must(t, err)
			f, err := os.Create(filepath.Join(t.TempDir(), "ntfs.img"))
			must(t, err)
			defer f.Close()
			must(t, f.Truncate(c.size))
			fsys, err := Format(volume.NewDevice(f, 0, c.size), Options{
				ClusterSize: c.cs, Label: c.label, Serial: le.Uint64(theirs[0x48:]), Hidden: 2048, Clock: time.Unix(0, 0).UTC(), Alloc: volume.NextFit,
			}, &volume.Tracker{})
			must(t, err)
			must(t, fsys.Flush())
			ours, err := os.ReadFile(f.Name())
			must(t, err)
			g := fsys.g
			normalizeImage(t, ours, g)
			normalizeImage(t, theirs, g)
			for i := range ours {
				if ours[i] != theirs[i] {
					cs := int64(g.ClusterSize)
					at := int64(i)
					t.Fatalf("first difference at byte %d (cluster %d, +%d): ours % x, mkntfs's % x", at, at/cs, at%cs, ours[i:min(i+16, len(ours))], theirs[i:min(i+16, len(theirs))])
				}
			}
		})
	}
}

// normalizeImage clears what an empty volume of fsagen's and mkntfs's may
// differ in without differing in meaning: the boot code, in the boot
// sector and its backup, which mkntfs has and fsagen leaves out; and the
// padding of every attribute in every record of $MFT and $MFTMirr, and of
// every entry of every index block, which mkntfs leaves holding whatever
// its buffer held.
func normalizeImage(t *testing.T, img []byte, g Geometry) {
	t.Helper()
	for _, at := range []int64{0, g.Sectors * sectorSize} {
		clear(img[at+0x54 : at+0x1FE])
	}
	cs := int64(g.ClusterSize)
	for at := int64(0); at+indexSize <= int64(len(img)); at += min(cs, indexSize) {
		blk := img[at : at+indexSize]
		if string(blk[:4]) != "INDX" {
			continue
		}
		usn := le.Uint16(blk[le.Uint16(blk[4:]):])
		if err := unprotect(blk); err != nil {
			t.Fatalf("index block at %d: %v", at, err)
		}
		h := blk[0x18:]
		for p := int(le.Uint32(h[0:])); p < int(le.Uint32(h[4:])); {
			e := h[p:]
			n, kl, flags := int(le.Uint16(e[8:])), int(le.Uint16(e[10:])), le.Uint16(e[12:])
			end := n
			if flags&ieNode != 0 {
				end -= 8
			}
			clear(e[16+kl : end])
			if flags&ieEnd != 0 {
				break
			}
			p += n
		}
		protect(blk, usn)
	}
	for _, base := range []int64{g.MFT * cs, g.Mirror * cs} {
		n := g.MFTRecords
		if base == g.Mirror*cs {
			n = g.MirrorClusters * cs / recordSize
		}
		for i := range n {
			rec := img[base+i*recordSize : base+(i+1)*recordSize]
			if string(rec[:4]) != "FILE" {
				continue
			}
			usn := le.Uint16(rec[le.Uint16(rec[4:]):])
			if err := unprotect(rec); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
			for p := int(le.Uint16(rec[20:])); le.Uint32(rec[p:]) != atEnd; {
				n := int(le.Uint32(rec[p+4:]))
				a := rec[p : p+n]
				if a[8] == 0 {
					clear(a[le.Uint16(a[20:])+uint16(le.Uint32(a[16:])):])
				} else {
					mp := a[le.Uint16(a[32:]):]
					end := 0
					for end < len(mp) && mp[end] != 0 {
						end += 1 + int(mp[end]&0x0F) + int(mp[end]>>4)
					}
					if end+1 < len(mp) {
						clear(mp[end+1:])
					}
				}
				p += n
			}
			protect(rec, usn)
		}
	}
}

// The descriptors mkntfs files in $Secure hash to what mkntfs files them
// under, and the ones fsagen adds read back from $SDS, $SDH and $SII.
func TestSecureDescriptors(t *testing.T) {
	if h := sdHash(secureSDs[0].sd); h != 0xF80312F0 {
		t.Errorf("descriptor 0x100 hashes to %#x", h)
	}
	if h := sdHash(secureSDs[1].sd); h != 0x00B32451 {
		t.Errorf("descriptor 0x101 hashes to %#x", h)
	}
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.MkdirAll("dir", target.DirMode))
	must(t, v.WriteFile("dir/file.txt", []byte("x"), target.FileMode))
	must(t, v.WriteFile("other.txt", []byte("y"), target.FileMode))
	_, _ = v.finish(t)
	sec := func(name string) uint32 {
		return le.Uint32(nodeOf(must2(v.Node(name))).rec.find(atStdInfo, "").value[52:])
	}
	if sec("dir") != 0x102 || sec("dir/file.txt") != 0x103 || sec("other.txt") != 0x103 {
		t.Errorf("security IDs: dir %#x, file %#x, other %#x", sec("dir"), sec("dir/file.txt"), sec("other.txt"))
	}
	sds := v.fs.secure.find(atData, "$SDS")
	for _, c := range []struct {
		id uint32
		at int64
		sd []byte
	}{{0x102, 0x100, dirSD()}, {0x103, align16(0x100 + 20 + int64(len(dirSD()))), fileSD()}} {
		want := sdsEntry(c.id, c.at, c.sd)
		for _, at := range []int64{c.at, c.at + 0x40000} {
			got, _, err := v.fs.readRuns(sds.runs, at, int64(len(want)))
			must(t, err)
			if !bytes.Equal(got, want) {
				t.Errorf("$SDS at %#x: % x, want % x", at, got, want)
			}
		}
	}
	var ids []uint32
	for _, e := range viewEntries(v.fs.secure.find(atIndexRoot, "$SII").value) {
		ids = append(ids, le.Uint32(e.body))
	}
	if fmt.Sprint(ids) != "[256 257 258 259]" {
		t.Errorf("$SII files IDs %v", ids)
	}
	var hashes []uint32
	for _, e := range viewEntries(v.fs.secure.find(atIndexRoot, "$SDH").value) {
		hashes = append(hashes, le.Uint32(e.body))
	}
	if !slices.IsSorted(hashes) || len(hashes) != 4 {
		t.Errorf("$SDH hashes %x", hashes)
	}
}

func must2[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// writeTimes is a set of times only NTFS's 100 ns ticks keep whole.
var writeTimes = target.Times{
	Atime: time.Date(2023, 1, 2, 3, 4, 5, 123456700, time.UTC),
	Mtime: time.Date(2023, 1, 2, 3, 4, 6, 100, time.UTC),
	Ctime: time.Date(2023, 1, 2, 3, 4, 7, 999999900, time.UTC),
	Btime: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
}

// What is written reads back through fsagen's own reader, from the disk:
// every name, every byte, resident or not, every time to 100 ns, and a
// read-only file's mode. Records for the scenario start at 64.
func TestWriteReadBack(t *testing.T) {
	v := newVolume(t, 32<<20, 0, volume.NextFit)
	files := map[string][]byte{
		"empty":                 nil,
		"a/small.txt":           []byte("hello"),
		"a/b/c/README.TXT":      bytes.Repeat([]byte("r"), 600),
		"a/b/Ünïcode-名前.dat":    bytes.Repeat([]byte{0xA5}, 2000),
		"a/b/big.bin":           bytes.Repeat([]byte("0123456789"), 10_000),
		"MixedCase.Doc":         []byte("m"),
		"a/b/c/d/e/deep/x.json": []byte("{}"),
	}
	for name, data := range files {
		must(t, v.WriteFile(name, data, target.FileMode))
	}
	must(t, v.WriteFile("ro.txt", []byte("read only"), 0o444))
	must(t, v.SetTimes("a/b/big.bin", writeTimes))
	must(t, v.SetTimes("a/b", writeTimes))
	r, _ := v.finish(t)
	for name, data := range files {
		got, err := r.ReadFile(name)
		must(t, err)
		if !bytes.Equal(got, data) {
			t.Errorf("%s reads back %d bytes, not the %d written", name, len(got), len(data))
		}
		m, err := r.Meta(name)
		must(t, err)
		var num uint32
		fmt.Sscan(m.ID, &num)
		if num < firstUser || m.Links != 1 {
			t.Errorf("%s: record %s, %d links", name, m.ID, m.Links)
		}
	}
	for _, name := range []string{"a/b/big.bin", "a/b"} {
		got, err := r.Times(name)
		must(t, err)
		if got != writeTimes {
			t.Errorf("%s's times read back as %+v", name, got)
		}
	}
	entries, err := r.ReadDirQuiet(".")
	must(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if info, _ := e.Info(); e.Name() == "ro.txt" && info.Mode() != 0o444 || e.Name() == "empty" && info.Mode() != 0o666 || e.Name() == "a" && !info.IsDir() {
			t.Errorf("%s has mode %v", e.Name(), info.Mode())
		}
	}
	if fmt.Sprint(names) != "[MixedCase.Doc a empty ro.txt]" {
		t.Errorf("the root lists %v", names)
	}
	// A name Windows could hold as a short name is in both namespaces.
	for name, ns := range map[string]byte{"a/b/c/README.TXT": nsWin32DOS, "a/small.txt": nsWin32, "MixedCase.Doc": nsWin32} {
		fn, err := readFileName(nodeOf(must2(v.Node(name))).rec.find(atFileName, "").value)
		must(t, err)
		if fn.namespace != ns {
			t.Errorf("%s is in namespace %d", name, fn.namespace)
		}
	}
}

// Content stays in the record while it fits; once it has left for
// clusters it never comes back, as Windows leaves it, and a truncating
// write takes new clusters, leaving the old ones' bytes behind as residue.
func TestContentLeavesTheRecordForGood(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.WriteFile("f", []byte("small"), target.FileMode))
	data := func() *attr { return nodeOf(must2(v.Node("f"))).rec.find(atData, "") }
	if !data().resident {
		t.Fatal("5 bytes are not kept in the record")
	}
	big := bytes.Repeat([]byte("B"), 3000)
	must(t, v.WriteFile("f", big, target.FileMode))
	if d := data(); d.resident || d.size != 3000 || d.alloc != 4096 {
		t.Fatalf("3000 bytes: %+v", d)
	}
	first := data().runs
	must(t, v.WriteFile("f", []byte("tiny"), target.FileMode))
	d := data()
	if d.resident || d.size != 4 || clusters(d.runs) != 1 || d.runs[0] == first[0] {
		t.Errorf("4 bytes after 3000: %+v, first in %v", d, first)
	}
	r, res := v.finish(t)
	got, err := r.ReadFile("f")
	must(t, err)
	if string(got) != "tiny" {
		t.Errorf("reads back %q", got)
	}
	if len(res) != 1 || res[0].Cause != target.ResidueOverwrite || res[0].Size != 3000 || res[0].Recoverable != target.RecoverableFull ||
		res[0].Extents[0].Offset != first[0].lcn*4096 {
		t.Errorf("residue %+v", res)
	}
	// The cluster's tail past the content is zeros, as the cache writes it.
	tail := make([]byte, 4092)
	_, err = v.file.ReadAt(tail, d.runs[0].lcn*4096+4)
	must(t, err)
	if !bytes.Equal(tail, make([]byte, 4092)) {
		t.Error("the last cluster is not zeroed past the content")
	}
}

// Deleting does what Windows does: the record keeps its attributes but
// loses its in-use flag and gains a sequence number, its clusters are
// freed with their bytes in place, and its name leaves the index, the
// entries after it moving up and leaving their old bytes past its end.
func TestDeleteAsWindows(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	content := bytes.Repeat([]byte("secret!"), 2000)
	must(t, v.WriteFile("keep.txt", []byte("k"), target.FileMode))
	must(t, v.WriteFile("zz-gone.bin", content, target.FileMode))
	must(t, v.WriteFile("small.txt", []byte("tiny secret"), target.FileMode))
	gone, small := v.num(t, "zz-gone.bin"), v.num(t, "small.txt")
	runs := nodeOf(must2(v.Node("zz-gone.bin"))).rec.find(atData, "").runs
	v.BeginOp(7, time.Time{})
	must(t, v.Remove("zz-gone.bin"))
	must(t, v.Remove("small.txt"))
	raw := v.record(t, gone)
	if flags, seq := le.Uint16(raw[22:]), le.Uint16(raw[16:]); flags&recInUse != 0 || seq != 2 {
		t.Errorf("deleted record: flags %#x, sequence %d", flags, seq)
	}
	if !bytes.Contains(raw, utf16le("zz-gone.bin")) || !bytes.Contains(raw, mappingPairs(runs)) {
		t.Error("the deleted record lost its name or its runlist")
	}
	for _, c := range lcns(runs) {
		if v.fs.data.Used(c) {
			t.Errorf("cluster %d is still in use", c)
		}
	}
	if v.fs.inUse[gone] || v.fs.inUse[small] {
		t.Error("the deleted records are still in use")
	}
	// The root's index block keeps the last entry's old bytes past its end.
	ix := v.fs.root.dir.blocks[0].raw
	if end := 0x18 + int(le.Uint32(ix[0x1C:])); !bytes.Contains(ix[end:], utf16le("zz-gone.bin")) {
		t.Error("the deleted name is not in the index block's slack")
	}
	r, res := v.finish(t)
	if _, err := r.Meta("zz-gone.bin"); err == nil {
		t.Error("the deleted file is still listed")
	}
	if len(res) != 2 {
		t.Fatalf("residue %+v", res)
	}
	e := res[0].Entry
	if res[0].N != 7 || res[0].Path != "zz-gone.bin" || res[0].Cause != target.ResidueDelete || e.Type != "ntfs_mft_record" || e.Number != int64(gone) || e.Seq != 2 || e.Length != recordSize || e.Overwritten ||
		res[0].Size != int64(len(content)) || res[0].Recoverable != target.RecoverableFull {
		t.Errorf("residue %+v, entry %+v", res[0], e)
	}
	if res[1].Entry.Number != int64(small) || res[1].Extents != nil {
		t.Errorf("a resident file's residue %+v", res[1])
	}
	on := make([]byte, recordSize)
	_, err := v.file.ReadAt(on, e.Offset)
	must(t, err)
	must(t, unprotect(on))
	if !bytes.Equal(on, raw) {
		t.Error("the residue's offset is not the record's")
	}
}

// A new object takes the lowest free record from 64 up, a deleted one's
// included, with the sequence number its deletion left; the deleted
// entry's residue is then overwritten.
func TestRecordReused(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.WriteFile("one", []byte("1"), target.FileMode))
	must(t, v.WriteFile("two", []byte("2"), target.FileMode))
	if v.num(t, "one") != firstUser || v.num(t, "two") != firstUser+1 {
		t.Fatalf("records %d and %d", v.num(t, "one"), v.num(t, "two"))
	}
	must(t, v.Remove("one"))
	must(t, v.WriteFile("three", []byte("3"), target.FileMode))
	n := nodeOf(must2(v.Node("three"))).rec
	if n.num != firstUser || n.seq != 2 {
		t.Errorf("the new file has record %d, sequence %d", n.num, n.seq)
	}
	r, res := v.finish(t)
	if len(res) != 1 || !res[0].Entry.Overwritten {
		t.Errorf("residue %+v", res)
	}
	if m, err := r.Meta("three"); err != nil || m.ID != fmt.Sprint(firstUser) {
		t.Errorf("three: %+v, %v", m, err)
	}
}

// $MFT grows as libntfs-3g grows it: a record at a time, its clusters 16
// records at a time, after its last cluster; and its mirror follows its
// first record.
func TestMFTGrows(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	for i := range 40 {
		must(t, v.WriteFile(fmt.Sprintf("d%d/f%02d", i%2, i), []byte{byte(i)}, target.FileMode))
	}
	_, _ = v.finish(t)
	d := v.fs.mft.find(atData, "")
	g := v.fs.g
	if want := int64(firstUser + 42); d.size != want*recordSize || len(d.runs) != 1 || d.runs[0].lcn != g.MFT || d.alloc != 28*1024+ceil(want-28, mftGrowth)*mftGrowth*recordSize {
		t.Errorf("$MFT: %+v", d)
	}
	mirror := make([]byte, recordSize)
	_, err := v.file.ReadAt(mirror, g.offset(g.Mirror))
	must(t, err)
	must(t, unprotect(mirror))
	if !bytes.Equal(mirror, v.record(t, recMFT)) {
		t.Error("$MFTMirr's copy of $MFT's record is stale")
	}
}

// A directory's entries move from its record to an index block once the
// record would keep less than 120 bytes free, as libntfs-3g moves them,
// and the index reads back in order.
func TestIndexMovesToBlock(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.MkdirAll("d", target.DirMode))
	dir := nodeOf(must2(v.Node("d")))
	n := 0
	for ; dir.dir.root.leaf(); n++ {
		must(t, v.WriteFile(fmt.Sprintf("d/file-%02d.txt", 99-n), nil, target.FileMode))
	}
	if dir.rec.find(atIndexAlloc, "$I30") == nil || dir.rec.find(atBitmap, "$I30") == nil {
		t.Fatalf("after %d entries: %+v", n, dir.rec.attrs)
	}
	// Each entry takes 104 bytes; the record held the root with n-1 of
	// them and 120 bytes to spare, but not with n.
	used := dir.rec.used() + align8(64+16+(n-1)*104)
	for _, a := range []*attr{dir.rec.find(atIndexRoot, "$I30"), dir.rec.find(atIndexAlloc, "$I30"), dir.rec.find(atBitmap, "$I30")} {
		used -= len(a.encode())
	}
	if used+120 > recordSize || used+104+120 <= recordSize {
		t.Errorf("the root moved after %d entries, with the record using %d bytes", n, used)
	}
	if b := dir.dir.blocks[0]; len(b.es) != n || !b.leaf() || dir.dir.root.end != 0 || len(dir.dir.root.es) != 0 {
		t.Fatalf("after %d entries: block %+v, root %+v", n, b, dir.dir.root)
	}
	for ; n < 30; n++ {
		must(t, v.WriteFile(fmt.Sprintf("d/file-%02d.txt", 99-n), nil, target.FileMode))
	}
	r, _ := v.finish(t)
	entries, err := r.ReadDirQuiet("d")
	must(t, err)
	if len(entries) != 30 || entries[0].Name() != "file-70.txt" || entries[29].Name() != "file-99.txt" {
		t.Errorf("d lists %d entries", len(entries))
	}
}

// A rename moves the name between indexes and gives $FILE_NAME the times
// the record has once the rename has changed it.
func TestRenameRewritesFileName(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	t1, t2 := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	v.BeginOp(1, t1)
	must(t, v.WriteFile("from/x.txt", []byte("x"), target.FileMode))
	must(t, v.MkdirAll("to", target.DirMode))
	v.BeginOp(2, t2)
	must(t, v.Rename("from/x.txt", "to/y.txt"))
	n := nodeOf(must2(v.Node("to/y.txt")))
	fn, err := readFileName(n.rec.find(atFileName, "").value)
	must(t, err)
	to := nodeOf(must2(v.Node("to")))
	if fn.name != "y.txt" || fn.parent != to.rec.ref() || fn.t != (times{t1, t1, t2, t1}) {
		t.Errorf("$FILE_NAME %+v", fn)
	}
	from := nodeOf(must2(v.Node("from")))
	if len(from.dir.root.es) != 0 || len(to.dir.root.es) != 1 || !bytes.Equal(to.dir.root.es[0].key, fn.encode()) {
		t.Errorf("indexes: from %d entries, to %+v", len(from.dir.root.es), to.dir.root.es)
	}
	if from.si.modified != t2 || to.si.changed != t2 {
		t.Errorf("directories' times: from %+v, to %+v", from.si, to.si)
	}
	_, _ = v.finish(t)
}

// Names are checked as Windows checks them, and NTFS's own names at the
// root are kept for it.
func TestNames(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "a:b", "a\x01", `a\b`, strings.Repeat("x", 256)} {
		if ValidName(bad) == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{"$MFT", "Ünïcode 名前", strings.Repeat("x", 255), "trailing.dot."} {
		if err := ValidName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if ValidLabel(strings.Repeat("L", 33)) == nil || ValidLabel("tab\there") == nil || ValidLabel(strings.Repeat("L", 32)) != nil {
		t.Error("labels are checked wrongly")
	}
	if !slices.Contains(Caps(4096).Reserved, "$Extend") {
		t.Error("$Extend is not reserved")
	}
	for name, want := range map[string]bool{"README.TXT": true, "A": true, "ABCDEFGH.XYZ": true, "readme.txt": false, "ABCDEFGHI": false, "A.B.C": false, "A B": false, "A.": false, "Ü.TXT": false, "A+B": false} {
		if isDOSName(name) != want {
			t.Errorf("isDOSName(%q) is %v", name, !want)
		}
	}
	if collate("a", "B") >= 0 || collate("$MFT", ".") >= 0 || collate("file10", "file9") >= 0 || collate("ABC", "abc") != 0 || collate("ab", "abc") >= 0 {
		t.Error("names collate wrongly")
	}
}

// NTFS keeps times from 1601 to 30828, to 100 ns.
func TestTimeRange(t *testing.T) {
	if !MinTime.Equal(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)) || MaxTime.Year() != 30828 {
		t.Errorf("range %v to %v", MinTime, MaxTime)
	}
	for _, tm := range []time.Time{MinTime, writeTimes.Atime, MaxTime.Truncate(100 * time.Nanosecond)} {
		if got := fromFiletime(filetime(tm)); !got.Equal(tm) {
			t.Errorf("%v reads back as %v", tm, got)
		}
	}
}
