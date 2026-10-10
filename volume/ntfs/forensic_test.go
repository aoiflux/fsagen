package ntfs

import (
	"bytes"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/internal/reparse"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// Named streams are named $DATA attributes, kept in the record while they
// fit and in clusters once they do not; replacing one truncates it first,
// so its old clusters are residue. Content that grows past what its record
// holds goes to clusters itself, as libntfs-3g moves the attribute being
// resized; a record that still does not hold its attributes, as when a
// hard link adds a name, moves its largest resident content out. A
// directory can carry a stream too.
func TestStreams(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.WriteFile("f.txt", []byte("content"), target.FileMode))
	must(t, v.WriteStream("f.txt", "small", []byte("a small stream")))
	big := bytes.Repeat([]byte("big stream "), 900)
	must(t, v.WriteStream("f.txt", "big", big))
	n := nodeOf(must2(v.Node("f.txt")))
	if a := n.rec.find(atData, "small"); a == nil || !a.resident {
		t.Errorf("small stream %+v", a)
	}
	if a := n.rec.find(atData, "big"); a == nil || a.resident || a.size != int64(len(big)) {
		t.Errorf("big stream %+v", a)
	}
	v.BeginOp(3, time.Time{})
	must(t, v.WriteStream("f.txt", "big", []byte("shorter")))
	if a := n.rec.find(atData, "big"); a.resident || a.size != 7 || a.alloc != int64(v.fs.g.ClusterSize) {
		t.Errorf("replaced stream %+v", a)
	}

	must(t, v.WriteFile("crowded.txt", bytes.Repeat([]byte("c"), 500), target.FileMode))
	must(t, v.WriteStream("crowded.txt", "s", bytes.Repeat([]byte("s"), 400)))
	c := nodeOf(must2(v.Node("crowded.txt"))).rec
	if !c.find(atData, "").resident || c.find(atData, "s").resident {
		t.Errorf("the stream written last did not move out: content %+v, stream %+v", c.find(atData, ""), c.find(atData, "s"))
	}
	must(t, v.WriteFile("linked.txt", bytes.Repeat([]byte("l"), 600), target.FileMode))
	for i := 0; nodeOf(must2(v.Node("linked.txt"))).rec.find(atData, "").resident; i++ {
		if i == 10 {
			t.Fatal("ten long names did not crowd the content out")
		}
		must(t, v.Link("linked.txt", fmt.Sprintf("link-%d-%s", i, strings.Repeat("n", 100))))
	}
	if fn := nodeOf(must2(v.Node("linked.txt"))).names[0].fn; fn.size != 600 || fn.alloc != int64(v.fs.g.ClusterSize) {
		t.Errorf("$FILE_NAME sizes %d, %d after the content moved", fn.size, fn.alloc)
	}

	must(t, v.MkdirAll("d", target.DirMode))
	must(t, v.WriteStream("d", "note", []byte("a directory's stream")))

	r, res := v.finish(t)
	for _, c := range []struct{ name, stream, want string }{
		{"f.txt", "small", "a small stream"}, {"f.txt", "big", "shorter"},
		{"crowded.txt", "s", strings.Repeat("s", 400)}, {"d", "note", "a directory's stream"},
	} {
		if got, err := r.ReadStream(c.name, c.stream); err != nil || string(got) != c.want {
			t.Errorf("%s:%s = %q, %v", c.name, c.stream, got, err)
		}
	}
	if ss, err := r.Streams("f.txt"); err != nil || len(ss) != 2 || ss[0].Name != "big" || ss[1].Name != "small" || ss[0].Size != 7 {
		t.Errorf("streams %+v, %v", ss, err)
	}
	if got, err := r.ReadFile("linked.txt"); err != nil || len(got) != 600 {
		t.Errorf("linked.txt: %d bytes, %v", len(got), err)
	}
	if len(res) != 1 || res[0].N != 3 || res[0].Cause != target.ResidueOverwrite || res[0].Size != int64(len(big)) || res[0].Recoverable != target.RecoverableFull {
		t.Errorf("residue %+v", res)
	}
}

// A hard link is a further $FILE_NAME in the record, in the POSIX
// namespace, after those whose values sort before it byte by byte, as
// libntfs-3g places an indexed attribute, with the times the file has once
// the link has changed it; it has an entry in its own directory's index. Removing one name drops its $FILE_NAME and entry and
// keeps the record; renaming one moves only that name; the last name gone,
// the record is deleted.
func TestHardLinks(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	t1, t2 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	v.BeginOp(1, t1)
	must(t, v.WriteFile("b/f.txt", []byte("one file, three names"), target.FileMode))
	must(t, v.MkdirAll("a", target.DirMode))
	v.BeginOp(2, t2)
	must(t, v.Link("b/f.txt", "a/g.txt"))
	must(t, v.Link("b/f.txt", "b/h.txt"))
	n := nodeOf(must2(v.Node("b/f.txt")))
	var values [][]byte
	fns := map[string]fileName{}
	for _, a := range n.rec.attrs {
		if a.typ == atFileName {
			values = append(values, a.value)
			fn := must2(readFileName(a.value))
			fns[fn.name] = fn
		}
	}
	a, b := nodeOf(must2(v.Node("a"))).rec.ref(), nodeOf(must2(v.Node("b"))).rec.ref()
	if n.rec.links != 3 || len(values) != 3 || !slices.IsSortedFunc(values, bytes.Compare) {
		t.Fatalf("%d links, $FILE_NAMEs %+v", n.rec.links, fns)
	}
	for name, want := range map[string]fileName{
		"f.txt": {parent: b, namespace: nsWin32, t: allAt(t1)},
		"h.txt": {parent: b, namespace: nsPOSIX, t: times{t1, t1, t2, t1}},
		"g.txt": {parent: a, namespace: nsPOSIX, t: times{t1, t1, t2, t1}},
	} {
		if fn := fns[name]; fn.parent != want.parent || fn.namespace != want.namespace || fn.t != want.t {
			t.Errorf("%s: $FILE_NAME %+v", name, fn)
		}
	}

	v.BeginOp(3, t2)
	must(t, v.Remove("b/f.txt"))
	must(t, v.Rename("b/h.txt", "b/k.txt"))
	if n.rec.links != 2 || len(n.names) != 2 || n.rec.flags&recInUse == 0 {
		t.Errorf("after one name went: %d links, %d names", n.rec.links, len(n.names))
	}
	if nm := n.nameIn(nodeOf(must2(v.Node("b"))), "k.txt"); nm == nil || nm.fn.namespace != nsWin32 {
		t.Errorf("the renamed name %+v", nm)
	}
	r, res := v.finish(t)
	for _, p := range []string{"a/g.txt", "b/k.txt"} {
		m, err := r.Meta(p)
		if err != nil || m.Links != 2 || m.ID != fmt.Sprint(n.rec.num) {
			t.Errorf("%s: %+v, %v", p, m, err)
		}
	}
	if _, err := r.Meta("b/f.txt"); err == nil {
		t.Error("the removed name is still listed")
	}
	for _, x := range res {
		if x.Entry != nil && x.Entry.Type == "ntfs_mft_record" {
			t.Errorf("a name's removal deleted the record: %+v", x)
		}
	}
}

// A symlink is an empty file, and a directory symlink and a junction empty
// directories, with a $REPARSE_POINT holding the data Windows writes and
// the reparse flag; the tag and flag are in its directory's entry, and in
// the record's $FILE_NAME only once a rename writes it anew, as libntfs-3g
// and Windows set a reparse point on an object already made. Each is filed
// in $Reparse's $R by tag and file reference. A junction's target is a path
// on C:. $R grows into index blocks and back as a directory index does.
func TestReparsePoints(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.Symlink("l/file", "../x/y.txt", false))
	must(t, v.Symlink("l/dir", `C:\Windows`, true))
	must(t, v.MkdirAll("d/e", target.DirMode))
	must(t, v.Junction("l/junction", "d/e"))
	for _, c := range []struct {
		name string
		tag  uint32
		dir  bool
		data []byte
	}{
		{"l/file", reparse.TagSymlink, false, reparse.Symlink("../x/y.txt")},
		{"l/dir", reparse.TagSymlink, true, reparse.Symlink(`C:\Windows`)},
		{"l/junction", reparse.TagMountPoint, true, reparse.Junction(`C:\d\e`)},
	} {
		n := nodeOf(must2(v.Node(c.name)))
		if rp := n.rec.find(atReparse, ""); rp == nil || !bytes.Equal(rp.value, c.data) {
			t.Errorf("%s: reparse point %+v", c.name, rp)
		}
		if n.rec.flags&recDir != 0 != c.dir || n.attrs&faReparse == 0 || n.tag != c.tag {
			t.Errorf("%s: flags %#x, attributes %#x, tag %#x", c.name, n.rec.flags, n.attrs, n.tag)
		}
		fn := must2(readFileName(n.rec.find(atFileName, "").value))
		if fn.reparse != 0 || fn.flags&faReparse != 0 || (fn.flags&faI30Index != 0) != c.dir {
			t.Errorf("%s: the record's $FILE_NAME %+v", c.name, fn)
		}
		e := must2(readFileName(n.entry(n.names[0]).key))
		if e.reparse != c.tag || e.flags&faReparse == 0 || (e.flags&faI30Index != 0) != c.dir {
			t.Errorf("%s: the entry's $FILE_NAME %+v", c.name, e)
		}
	}
	must(t, v.Rename("l/file", "l/file2"))
	if fn := must2(readFileName(nodeOf(must2(v.Node("l/file2"))).rec.find(atFileName, "").value)); fn.reparse != reparse.TagSymlink || fn.flags&faReparse == 0 {
		t.Errorf("a renamed symlink's $FILE_NAME %+v", fn)
	}
	must(t, v.Rename("l/file2", "l/file"))
	tags := func() []uint32 {
		var out []uint32
		for _, e := range v.fs.reparse.dir.root.es {
			out = append(out, le.Uint32(e.body))
		}
		return out
	}
	if got := tags(); !slices.Equal(got, []uint32{reparse.TagMountPoint, reparse.TagSymlink, reparse.TagSymlink}) {
		t.Errorf("$R tags %#x", got)
	}
	must(t, v.Remove("l/file"))
	if got := tags(); len(got) != 2 {
		t.Errorf("$R after a removal: %#x", got)
	}
	for i := range 60 {
		must(t, v.Symlink(fmt.Sprintf("many/link-%02d", i), "t", false))
	}
	if v.fs.reparse.rec.find(atIndexAlloc, "$R") == nil || v.fs.reparse.dir.root.leaf() {
		t.Error("$R did not move to an index block")
	}
	r, _ := v.finish(t)
	for p, want := range map[string][2]string{
		"l/dir": {target.LinkSymlink, "C:/Windows"}, "l/junction": {target.LinkJunction, "d/e"}, "many/link-07": {target.LinkSymlink, "t"},
	} {
		if m, err := r.Meta(p); err != nil || m.Link != want[0] || m.Target != want[1] {
			t.Errorf("%s: %+v, %v", p, m, err)
		}
	}
	if es, err := r.ReadDirQuiet("l"); err != nil || len(es) != 2 || es[0].IsDir() || es[0].Type() != fs.ModeSymlink {
		t.Errorf("l lists %v, %v", es, err)
	}
	if _, err := r.ReadDirQuiet("l/junction"); err == nil {
		t.Error("the reader went through a junction")
	}
}

// Removing every link takes $R back into its record.
func TestReparseIndexShrinks(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	for i := range 60 {
		must(t, v.Symlink(fmt.Sprintf("link-%02d", i), "t", false))
	}
	for i := range 60 {
		must(t, v.Remove(fmt.Sprintf("link-%02d", i)))
	}
	if ix := v.fs.reparse.dir; !ix.root.leaf() || len(ix.root.es) != 0 || len(ix.blocks) != 0 {
		t.Errorf("$R root %+v, %d blocks", ix.root, len(ix.blocks))
	}
	_, _ = v.finish(t)
}

// A name's $FILE_NAME times are set in its record and in its directory's
// index alike, for that name only; setting the times it has writes
// nothing.
func TestFileNameTimes(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	t1, t2 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2010, 6, 1, 12, 0, 0, 100, time.UTC)
	v.BeginOp(1, t1)
	must(t, v.WriteFile("d/f.txt", []byte("x"), target.FileMode))
	must(t, v.Link("d/f.txt", "d/g.txt"))
	must(t, v.SetFileNameTimes("d/f.txt", target.Times{Btime: t2, Mtime: t2}))
	n := nodeOf(must2(v.Node("d/f.txt")))
	f, g := n.names[0], n.names[1]
	if f.fn.t != (times{t2, t2, t1, t1}) || g.fn.t != allAt(t1) {
		t.Errorf("$FILE_NAME times %+v, %+v", f.fn.t, g.fn.t)
	}
	d := nodeOf(must2(v.Node("d")))
	if path, ok := d.dir.lookup(fileEntry(n.rec.ref(), f.fn)); !ok || !bytes.Equal(path[len(path)-1].n.es[path[len(path)-1].pos].key, f.fn.encode()) {
		t.Error("the index entry kept the old times")
	}
	usn := n.rec.usn
	must(t, v.SetFileNameTimes("d/f.txt", target.Times{Btime: t2}))
	if n.rec.usn != usn {
		t.Error("setting the times a name has rewrote its record")
	}
	r, _ := v.finish(t)
	if m, err := r.Meta("d/f.txt"); err != nil || *m.FileName != (target.Times{Btime: t2, Mtime: t2, Ctime: t1, Atime: t1}) || m.Times.Btime != t1 {
		t.Errorf("read back %+v, %v", m, err)
	}
}

// Slack is written in the rest of the last cluster of a file in clusters,
// and refused for one in its record.
func TestSlack(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	content := bytes.Repeat([]byte("c"), 5000)
	must(t, v.WriteFile("f.bin", content, target.FileMode))
	slack := bytes.Repeat([]byte("S"), 4096*2-5000)
	must(t, v.WriteSlack("f.bin", 5000, slack))
	must(t, v.WriteFile("small.txt", []byte("small"), target.FileMode))
	if err := v.WriteSlack("small.txt", 5, []byte("x")); err == nil || !strings.Contains(err.Error(), "MFT record") {
		t.Errorf("slack on a resident file: %v", err)
	}
	if err := v.WriteSlack("f.bin", 5000, append(slack, 'x')); err == nil {
		t.Error("slack past the last cluster was written")
	}
	r, _ := v.finish(t)
	if got, err := r.ReadFile("f.bin"); err != nil || !bytes.Equal(got, content) {
		t.Errorf("the content read back changed: %v", err)
	}
	d := nodeOf(must2(v.Node("f.bin"))).rec.find(atData, "")
	got, _, err := v.fs.readRuns(d.runs, 5000, int64(len(slack)))
	must(t, err)
	if !bytes.Equal(got, slack) {
		t.Error("the slack is not on disk")
	}
}

// An entry taken out of an index is residue where its bytes are whole: in
// a block the index freed with the entry in it, in a deleted directory's
// blocks, and past the entries of a block in use. One overwritten in part
// is not.
func TestIndexEntryResidue(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	name := func(i int) string { return fmt.Sprintf("d/cached-thumbnail-%04d-0123456789abcdef.tmp", i) }
	for i := range 8 {
		must(t, v.WriteFile(name(i), []byte{byte(i)}, target.FileMode))
	}
	d := nodeOf(must2(v.Node("d")))
	if d.dir.root.leaf() {
		t.Fatal("the index did not move to a block")
	}
	last := nodeOf(must2(v.Node(name(7)))).rec.ref()
	for i := range 8 {
		v.BeginOp(10+i, time.Time{})
		must(t, v.Remove(name(i)))
	}
	r, res := v.finish(t)
	_ = r
	var entries []target.Residue
	for _, x := range res {
		if x.Entry != nil && x.Entry.Type == "ntfs_index_entry" {
			entries = append(entries, x)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("index entry residue %+v", entries)
	}
	e := entries[0]
	if e.N != 17 || e.Path != name(7) || e.Cause != target.ResidueDelete || e.Entry.Number != int64(refNum(last)) || e.Entry.Seq != int(last>>48) || e.Entry.Overwritten {
		t.Errorf("residue %+v, entry %+v", e, e.Entry)
	}
	at := make([]byte, e.Entry.Length)
	_, err := v.file.ReadAt(at, e.Entry.Offset)
	must(t, err)
	if le.Uint64(at) != last || !bytes.Contains(at, utf16le("cached-thumbnail-0007")) {
		t.Errorf("the residue's offset holds % x", at[:32])
	}
}

// Entries removed last first leave nothing whole behind but the first, the
// block's only entry when the block is freed: it is found among the freed
// block's entries, as no copy of it lies in any slack.
func TestIndexEntryResidueInFreedBlock(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	name := func(i int) string { return fmt.Sprintf("d/cached-thumbnail-%04d-0123456789abcdef.tmp", i) }
	for i := range 8 {
		must(t, v.WriteFile(name(i), []byte{byte(i)}, target.FileMode))
	}
	first := nodeOf(must2(v.Node(name(0)))).rec.ref()
	for i := 7; i >= 0; i-- {
		must(t, v.Remove(name(i)))
	}
	_, res := v.finish(t)
	var found []string
	for _, x := range res {
		if x.Entry != nil && x.Entry.Type == "ntfs_index_entry" {
			found = append(found, x.Path)
			if x.Entry.Number != int64(refNum(first)) {
				t.Errorf("residue %+v", x.Entry)
			}
		}
	}
	if !slices.Equal(found, []string{name(0)}) {
		t.Errorf("index entry residue for %q", found)
	}
}
