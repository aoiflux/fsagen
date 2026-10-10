package ntfs

import (
	"bytes"
	"flag"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

var update = flag.Bool("update", false, "rewrite testdata/libntfs3g-index.txt from libntfs-3g")

// indexShape lays out the $I30 index of every directory on the volume dev:
// its $BITMAP and how many bytes $INDEX_ALLOCATION holds, then node by
// node from the root down (the root with the room it has for entries),
// each node's entries (how many, a checksum of their names and the first
// of them) and the VCNs of its children.
func indexShape(t *testing.T, dev *volume.Device) string {
	t.Helper()
	r, err := Open(dev)
	must(t, err)
	var b strings.Builder
	var dir func(d *rnode, p string)
	dir = func(d *rnode, p string) {
		_, _, _, attrs, err := r.record(d.num)
		must(t, err)
		ir, ia, bm := findAttr(attrs, atIndexRoot, "$I30"), findAttr(attrs, atIndexAlloc, "$I30"), findAttr(attrs, atBitmap, "$I30")
		fmt.Fprintf(&b, "%s:", p)
		if bm != nil {
			fmt.Fprintf(&b, " bitmap %x, %d bytes of blocks", bm.value, ia.size)
		}
		b.WriteString("\n")
		var node func(label string, h []byte)
		node = func(label string, h []byte) {
			var names []string
			var kids []int64
			for p := int(le.Uint32(h[0:])); ; {
				e := h[p:]
				n, kl, flags := int(le.Uint16(e[8:])), int(le.Uint16(e[10:])), le.Uint16(e[12:])
				if flags&ieNode != 0 {
					kids = append(kids, int64(le.Uint64(e[n-8:])))
				}
				if flags&ieEnd != 0 {
					break
				}
				fn, err := readFileName(e[16 : 16+kl])
				must(t, err)
				names = append(names, fn.name)
				p += n
			}
			fmt.Fprintf(&b, "  %s: %d entries %08x", label, len(names), crc32.ChecksumIEEE([]byte(strings.Join(names, "/"))))
			if len(names) > 0 {
				fmt.Fprintf(&b, " from %.12q", names[0])
			}
			if kids != nil {
				fmt.Fprintf(&b, ", children %v", kids)
			}
			b.WriteString("\n")
			for _, vcn := range kids {
				blk, err := r.indexBlock(ia.runs, vcn)
				must(t, err)
				node(fmt.Sprintf("block %d", vcn), blk[0x18:])
			}
		}
		node(fmt.Sprintf("root, room %d", le.Uint32(ir.value[24:])-16), ir.value[16:])
		for _, c := range d.children {
			if c.dir {
				dir(c, path.Join(p, c.name))
			}
		}
	}
	dir(r.root, "/")
	return b.String()
}

// fold is a name as NTFS compares it: each UTF-16 unit in upper case.
func fold(name string) string {
	u := utf16.Encode([]rune(name))
	for i, c := range u {
		u[i] = upcase[c]
	}
	return string(utf16.Decode(u))
}

// indexWorkload is a seeded run of creates and removes, in phases, that
// grows directories several levels deep and shrinks them again: names of
// every length up to 15 characters, some of them outside ASCII. Each
// operation is "d /path" (make a directory), "f /path" (make an empty
// file) or "r /path" (remove one). No entry of 15 characters or less
// grows a directory's record by more than the 120 bytes libntfs-3g keeps
// free in it; a longer one can make libntfs-3g move $INDEX_ROOT out to an
// extension record, where fsagen moves the root's entries to a block.
func indexWorkload() [][]string {
	const longest = 15
	rng := rand.New(rand.NewPCG(4, 2))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-éÉßωΩ")
	taken := map[string]bool{}
	live := map[string][]string{}
	create := func(dir string, n int) []string {
		var ops []string
		for range n {
			var name string
			for name == "" || taken[fold(dir+"/"+name)] {
				r := make([]rune, 1+rng.IntN(longest))
				for i := range r {
					r[i] = letters[rng.IntN(len(letters))]
				}
				name = string(r)
			}
			taken[fold(dir+"/"+name)] = true
			live[dir] = append(live[dir], name)
			ops = append(ops, "f "+dir+"/"+name)
		}
		return ops
	}
	remove := func(dir string, n int) []string {
		var ops []string
		for range n {
			i := rng.IntN(len(live[dir]))
			name := live[dir][i]
			live[dir] = slices.Delete(live[dir], i, i+1)
			delete(taken, fold(dir+"/"+name))
			ops = append(ops, "r "+dir+"/"+name)
		}
		return ops
	}
	return [][]string{
		slices.Concat(create("", 150), []string{"d /small"}, create("/small", 5)),
		slices.Concat([]string{"d /deep", "d /deep2", "d /deep2/sub"}, create("/deep", 3000), create("/deep2/sub", 60), remove("/small", 2)),
		slices.Concat(remove("/deep", 2000), remove("", 100)),
		slices.Concat(create("/deep", 1500), remove("/deep", 1000), create("/deep", 800)),
		slices.Concat(remove("/deep2/sub", 60), remove("/deep", len(live["/deep"])-4)),
	}
}

// The directory indexes come out as libntfs-3g's: after each phase of
// indexWorkload, every directory's B-tree has the same nodes, entries and
// VCNs, the same $BITMAP and as many bytes of blocks as when libntfs-3g
// 2022.10.3 runs the workload on the volume mkntfs makes.
// testdata/libntfs3g-index.txt records libntfs-3g's. Where the harness in
// testdata/libntfs3g is built and FSAGEN_NTFS_HARNESS names it, and mkntfs
// is on the path, the test runs libntfs-3g too, and -update rewrites the
// record from it.
func TestIndexMatchesLibntfs3g(t *testing.T) {
	const size = 64 << 20
	phases := indexWorkload()
	v := newVolume(t, size, 0, volume.NextFit)
	var ours strings.Builder
	for i, ops := range phases {
		for _, op := range ops {
			switch name := op[3:]; op[0] {
			case 'd':
				must(t, v.MkdirAll(name, target.DirMode))
			case 'f':
				must(t, v.WriteFile(name, nil, target.FileMode))
			case 'r':
				must(t, v.Remove(name))
			}
		}
		fmt.Fprintf(&ours, "== phase %d\n%s", i+1, indexShape(t, volume.NewDevice(v.file, 0, size)))
	}
	_, _ = v.finish(t)
	golden := filepath.Join("testdata", "libntfs3g-index.txt")
	if harness := os.Getenv("FSAGEN_NTFS_HARNESS"); harness != "" {
		theirs := libntfs3gShape(t, harness, size, phases)
		if *update {
			must(t, os.WriteFile(golden, []byte(theirs), 0o644))
		}
		compareShapes(t, "libntfs-3g's", ours.String(), theirs)
	}
	want, err := os.ReadFile(golden)
	must(t, err)
	compareShapes(t, golden, ours.String(), string(want))
}

// libntfs3gShape runs the phases with the harness on a volume mkntfs makes,
// and lays out its indexes after each.
func libntfs3gShape(t *testing.T, harness string, size int64, phases [][]string) string {
	t.Helper()
	mkntfs, err := exec.LookPath("mkntfs")
	if err != nil {
		t.Fatal("FSAGEN_NTFS_HARNESS is set, but mkntfs is not installed")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "libntfs3g.img")
	must(t, os.WriteFile(img, nil, 0o644))
	must(t, os.Truncate(img, size))
	if out, err := exec.Command(mkntfs, "-q", "-F", "-Q", "-T", "-p", "2048", "-H", "255", "-S", "63", img).CombinedOutput(); err != nil {
		t.Fatalf("mkntfs: %v\n%s", err, out)
	}
	var b strings.Builder
	for i, ops := range phases {
		script := filepath.Join(dir, fmt.Sprintf("phase%d.txt", i+1))
		must(t, os.WriteFile(script, []byte(strings.Join(ops, "\n")+"\n"), 0o644))
		if out, err := exec.Command(harness, img, script).CombinedOutput(); err != nil {
			t.Fatalf("harness, phase %d: %v\n%s", i+1, err, out)
		}
		f, err := os.Open(img)
		must(t, err)
		fmt.Fprintf(&b, "== phase %d\n%s", i+1, indexShape(t, volume.NewDevice(f, 0, size)))
		f.Close()
	}
	return b.String()
}

// compareShapes reports the first line where fsagen's indexes differ from
// those of whose.
func compareShapes(t *testing.T, whose, ours, theirs string) {
	t.Helper()
	a, b := strings.Split(ours, "\n"), strings.Split(theirs, "\n")
	for i := range max(len(a), len(b)) {
		if i >= len(a) || i >= len(b) || a[i] != b[i] {
			at := func(l []string) string {
				if i < len(l) {
					return l[i]
				}
				return "(end)"
			}
			t.Fatalf("line %d differs from %s:\n ours:   %s\n theirs: %s", i+1, whose, at(a), at(b))
		}
	}
}

// A directory grows to several levels and shrinks back: every name reads
// back in order at every step, blocks freed by the shrinking are cleared
// in $BITMAP and left on disk with the names they held, and the lowest
// freed VCN is the next one taken.
func TestIndexGrowsAndShrinks(t *testing.T) {
	const size = 32 << 20
	v := newVolume(t, size, 0, volume.NextFit)
	long := strings.Repeat("long-name-", 8)
	name := func(i int) string { return fmt.Sprintf("d/%s-%04d.txt", long, i) }
	lists := func(want ...int) {
		t.Helper()
		r, err := Open(volume.NewDevice(v.file, 0, size))
		must(t, err)
		entries, err := r.ReadDirQuiet("d")
		must(t, err)
		var got []string
		for _, e := range entries {
			got = append(got, "d/"+e.Name())
		}
		var names []string
		for _, i := range want {
			names = append(names, name(i))
		}
		if !slices.Equal(got, names) {
			t.Fatalf("d lists %d names, not the %d written", len(got), len(names))
		}
	}
	var all []int
	for i := range 400 {
		must(t, v.WriteFile(name(i), nil, target.FileMode))
		all = append(all, i)
	}
	d := nodeOf(must2(v.Node("d"))).dir
	depth := 0
	for n := d.root; ; n = d.blocks[n.child(0)] {
		depth++
		if n.leaf() {
			break
		}
	}
	if depth < 3 || len(d.blocks) < 20 {
		t.Fatalf("400 long names: %d levels, %d blocks", depth, len(d.blocks))
	}
	lists(all...)
	before := len(d.blocks)
	ia := nodeOf(must2(v.Node("d"))).rec.find(atIndexAlloc, "$I30")
	for i := 399; i >= 10; i-- {
		must(t, v.Remove(name(i)))
	}
	all = all[:10]
	lists(all...)
	per := int64(v.fs.g.perIndexBlock())
	var lowest int64 = -1
	for bit := range int64(len(d.bitmap) * 8) {
		vcn := bit * per
		used := d.bitmap[bit/8]&(1<<(bit%8)) != 0
		if used != (d.blocks[vcn] != nil) {
			t.Errorf("block %d: marked in use %v", vcn, used)
		}
		if !used && lowest < 0 && v.fs.blockPos(vcn) < ia.size {
			lowest = vcn
		}
	}
	if len(d.blocks) >= before || lowest < 0 {
		t.Fatalf("%d blocks after removing 390 of 400 names, %d before; lowest free %d", len(d.blocks), before, lowest)
	}
	blk, _, err := v.fs.readRuns(ia.runs, v.fs.blockPos(lowest), indexSize)
	must(t, err)
	if !bytes.Contains(blk, utf16le(long)) {
		t.Errorf("freed block %d no longer holds the names it held", lowest)
	}
	for i := 1000; d.blocks[lowest] == nil; i++ {
		if i == 1400 {
			t.Fatalf("400 new names did not take block %d", lowest)
		}
		must(t, v.WriteFile(name(i), nil, target.FileMode))
		all = append(all, i)
	}
	lists(all...)
	for _, i := range all {
		must(t, v.Remove(name(i)))
	}
	lists()
	if !d.root.leaf() || len(d.blocks) != 0 {
		t.Errorf("an emptied directory: root a leaf %v, %d blocks", d.root.leaf(), len(d.blocks))
	}
	_, _ = v.finish(t)
}

// Removing an entry from a node with children brings up its successor;
// when the successor is longer than the node or the root has room for, the
// node is split, or the root's entries moved to a block, first, and the
// removal starts over.
func TestIndexSuccessorThatDoesNotFit(t *testing.T) {
	const size = 32 << 20
	v := newVolume(t, size, 0, volume.NextFit)
	var live []string
	for i := range 3000 {
		name := fmt.Sprintf("d/f%05d", (i*7919)%3000)
		must(t, v.WriteFile(name, nil, target.FileMode))
		live = append(live, name)
	}
	d := nodeOf(must2(v.Node("d"))).dir
	reads := func(step string) {
		t.Helper()
		r, err := Open(volume.NewDevice(v.file, 0, size))
		must(t, err)
		entries, err := r.ReadDirQuiet("d")
		must(t, err)
		var got []string
		for _, e := range entries {
			got = append(got, "d/"+e.Name())
		}
		want := slices.Sorted(slices.Values(live))
		if !slices.Equal(got, want) {
			t.Fatalf("%s: d lists %d names, not the %d written", step, len(got), len(want))
		}
	}
	// longAfter files a long name just after entry e, as the first entry
	// of the leftmost leaf after it: its successor.
	longAfter := func(e entry) string {
		name := "d/" + e.name + "~" + strings.Repeat("z", 200)
		must(t, v.WriteFile(name, nil, target.FileMode))
		live = append(live, name)
		return name
	}
	drop := func(name string) {
		must(t, v.Remove(name))
		live = slices.DeleteFunc(live, func(n string) bool { return n == name })
	}
	// A block with children with too little room for it.
	var full *inode
	for _, b := range d.blocks {
		if !b.leaf() && blockRoom-b.size() < 300 && (full == nil || b.vcn < full.vcn) {
			full = b
		}
	}
	if full == nil {
		t.Fatal("no block with children is nearly full")
	}
	e := full.es[0]
	longAfter(e)
	blocks := len(d.blocks)
	drop("d/" + e.name)
	if len(d.blocks) <= blocks {
		t.Errorf("the nearly full block %d was not split: %d blocks, %d before", full.vcn, len(d.blocks), blocks)
	}
	reads("after a block split for a successor")
	// The root, whose record has too little room for it.
	if len(d.root.es) == 0 {
		t.Fatal("the root has no entries")
	}
	e = d.root.es[0]
	longAfter(e)
	end := d.root.end
	drop("d/" + e.name)
	if d.root.end == end || len(d.root.es) != 0 {
		t.Errorf("the root's entries did not move to a block: %d entries, end %d, %d before", len(d.root.es), d.root.end, end)
	}
	reads("after the root moved for a successor")
	_, _ = v.finish(t)
}
