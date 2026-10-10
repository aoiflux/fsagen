package ext4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

var clock = time.Date(2022, 6, 1, 8, 0, 0, 0, time.UTC)

// testVolume is an ext4 volume in a file.
type testVolume struct {
	*volume.Volume
	fs   *FS
	file *os.File
}

func newVolume(t *testing.T, size int64, blockSize int, policy string) testVolume {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "ext4.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	res := &volume.Tracker{}
	fsys, err := Format(volume.NewDevice(f, 0, size), Options{
		BlockSize: blockSize, Label: "test", Clock: clock, Alloc: policy,
		UUID: [16]byte{1, 2, 3}, HashSeed: [16]byte{4, 5, 6}, Generations: prng.Root(1).Stream(),
	}, res)
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

func (v testVolume) raw(t *testing.T, off int64, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := v.file.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	return b
}

func (v testVolume) inode(t *testing.T, ino uint32) []byte {
	t.Helper()
	return v.raw(t, v.fs.g.inodeOffset(ino), inodeSize)
}

func (v testVolume) ino(t *testing.T, name string) uint32 {
	t.Helper()
	n, err := v.Node(name)
	must(t, err)
	return rec(n).ino
}

// finish finishes the volume and reads it back, and has e2fsck check it
// where e2fsprogs is installed.
func (v testVolume) finish(t *testing.T) (target.Reader, []target.Residue) {
	t.Helper()
	r, err := v.Finish()
	must(t, err)
	if e2fsck, err := exec.LookPath("e2fsck"); err == nil {
		if out, err := exec.Command(e2fsck, "-f", "-n", v.file.Name()).CombinedOutput(); err != nil {
			t.Errorf("e2fsck: %v\n%s", err, out)
		}
	}
	return r, v.Residue()
}

var le = binary.LittleEndian

// The geometry mke2fs 1.47 gave each size: its block count, inodes per
// group and reserved blocks, the last group dropped when too small.
func TestPlanMatchesMke2fs(t *testing.T) {
	const mib = 1 << 20
	for _, c := range []struct {
		size                 int64
		bs                   int
		blocks, ipg, reserve uint32
		groups               int
	}{
		{8 * mib, 0, 2048, 2048, 102, 1},
		{40 * mib, 0, 10240, 10240, 512, 1},
		{64 * mib, 0, 16384, 16384, 819, 1},
		{300 * mib, 0, 76800, 25600, 3840, 3},
		{512 * mib, 0, 131072, 8192, 6553, 4},
		{600 * mib, 0, 153600, 7680, 7680, 5},
	} {
		g, err := Plan(c.size, c.bs)
		must(t, err)
		if g.Blocks != c.blocks || g.InodesPerGroup != c.ipg || g.Reserved != c.reserve || g.Groups != c.groups {
			t.Errorf("%d MiB: %+v", c.size/mib, g)
		}
	}
	if _, err := Plan(64<<10, 0); err == nil {
		t.Error("64 KiB was accepted")
	}
	if _, err := Plan(8<<20, 3000); err == nil {
		t.Error("a 3000-byte block was accepted")
	}
}

// Group 0 and 1 and the powers of 3, 5 and 7 keep a superblock.
func TestSparseSuperGroups(t *testing.T) {
	var got []int
	for i := range 60 {
		if hasSuper(i) {
			got = append(got, i)
		}
	}
	if fmt.Sprint(got) != "[0 1 3 5 7 9 25 27 49]" {
		t.Errorf("groups with a superblock: %v", got)
	}
}

// An empty volume is mke2fs's, byte for byte, checksums included, when
// mke2fs is given the same UUID, hash seed and time; only the lifetime
// writes it counts, and so the superblock's checksum, differ. It runs where
// mkfs.ext4 is on the path.
func TestFormatMatchesMke2fs(t *testing.T) {
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		t.Skip("mkfs.ext4 is not installed")
	}
	const mib = 1 << 20
	for _, c := range []struct {
		size int64
		bs   int
	}{{8 * mib, 0}, {40 * mib, 0}, {300 * mib, 0}, {600 * mib, 0}, {48 * mib, 1024}, {100 * mib, 2048}, {1100 * mib, 0}, {300 * mib, 1024}, {2200 * mib, 0}} {
		t.Run(fmt.Sprintf("%dMiB-%d", c.size/mib, c.bs), func(t *testing.T) {
			v := newVolume(t, c.size, c.bs, volume.NextFit)
			_, _ = v.finish(t)
			ref := filepath.Join(t.TempDir(), "mkfs.img")
			must(t, os.WriteFile(ref, nil, 0o644))
			must(t, os.Truncate(ref, c.size))
			args := []string{"-q", "-F", "-L", "test", "-O", "^has_journal,^64bit,^resize_inode,^dir_index,^orphan_file,^huge_file,^ext_attr",
				"-U", "01020300-0000-0000-0000-000000000000", "-E", "nodiscard,lazy_itable_init=0,hash_seed=04050600-0000-0000-0000-000000000000"}
			if c.bs != 0 {
				args = append(args, "-b", fmt.Sprint(c.bs))
			}
			cmd := exec.Command(mkfs, append(args, ref)...)
			cmd.Env = append(os.Environ(), fmt.Sprintf("E2FSPROGS_FAKE_TIME=%d", clock.Unix()))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("mkfs.ext4: %v\n%s", err, out)
			}
			theirs, err := os.OpenFile(ref, os.O_RDWR, 0)
			must(t, err)
			defer theirs.Close()
			g := v.fs.g
			for _, img := range []*os.File{v.file, theirs} {
				normalize(t, img, g)
			}
			// Compared a chunk at a time: the largest volume is 2.2 GiB.
			const chunk = 1 << 20
			a, b := make([]byte, chunk), make([]byte, chunk)
			for off := int64(0); off < c.size; off += chunk {
				n := int(min(chunk, c.size-off))
				_, err := v.file.ReadAt(a[:n], off)
				must(t, err)
				_, err = theirs.ReadAt(b[:n], off)
				must(t, err)
				if i := firstDiff(a[:n], b[:n]); i >= 0 {
					at := off + int64(i)
					t.Fatalf("first difference at byte %d (block %d, +%d): ours % x, mke2fs's % x", at, at/int64(g.BlockSize), at%int64(g.BlockSize), window(a[:n], i), window(b[:n], i))
				}
			}
		})
	}
}

// normalize zeroes the lifetime writes mke2fs counts, and the superblock
// checksums that cover them.
func normalize(t *testing.T, img *os.File, g Geometry) {
	t.Helper()
	for i := range g.Groups {
		if !hasSuper(i) {
			continue
		}
		at := g.superAt(i)
		_, err := img.WriteAt(make([]byte, 8), at+0x178)
		must(t, err)
		_, err = img.WriteAt(make([]byte, 4), at+0x3FC)
		must(t, err)
	}
}

func firstDiff(a, b []byte) int {
	if bytes.Equal(a, b) {
		return -1
	}
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

func window(b []byte, i int) []byte { return b[i:min(i+16, len(b))] }

// A deleted file loses its directory entry entirely, folded into the one
// before it and zeroed. Its inode keeps its mode, times and the logical
// block of each extent, gains its deletion time, and loses its size, links
// and blocks; its bytes stay in the freed blocks.
func TestDeleteWipesEntryAndKeepsInode(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	data := bytes.Repeat([]byte("evidence "), 1000)
	must(t, v.WriteFile("dir/keep.txt", []byte("kept"), target.FileMode))
	must(t, v.WriteFile("dir/secret.docx", data, target.FileMode))
	ino := v.ino(t, "dir/secret.docx")
	dir := rec(mustNode(t, v, "dir"))
	when := time.Date(2023, 5, 6, 7, 8, 9, 123456789, time.UTC)
	v.BeginOp(3, when)
	must(t, v.Remove("dir/secret.docx"))
	v.BeginOp(0, time.Time{})
	r, res := v.finish(t)
	if _, err := r.Meta("dir/secret.docx"); err == nil {
		t.Fatal("the deleted file is still listed")
	}
	blk := v.raw(t, v.fs.g.offset(dir.blocks[0]), v.fs.g.BlockSize)
	// ".", "..", keep.txt (now running to the checksum), then zeros.
	if rl := le.Uint16(blk[24+4:]); int(rl) != v.fs.limit-24 {
		t.Errorf("keep.txt's record length %d", rl)
	}
	if bytes.Contains(blk, []byte("secret")) {
		t.Error("the deleted name is still in the directory block")
	}
	in := v.inode(t, ino)
	if le.Uint16(in[0:]) != modeFile|0o644 || le.Uint32(in[4:]) != 0 || le.Uint16(in[26:]) != 0 || le.Uint32(in[28:]) != 0 {
		t.Errorf("deleted inode: mode %o size %d links %d blocks %d", le.Uint16(in[0:]), le.Uint32(in[4:]), le.Uint16(in[26:]), le.Uint32(in[28:]))
	}
	if got := le.Uint32(in[20:]); got != uint32(when.Unix()) {
		t.Errorf("dtime %d, want %d", got, when.Unix())
	}
	if got := decodeTime(le.Uint32(in[12:]), le.Uint32(in[132:])); !got.Equal(when) {
		t.Errorf("ctime %s, want the deletion's %s", got, when)
	}
	// The extent header is empty and the extent keeps its logical block
	// alone.
	if le.Uint16(in[40:]) != extentMagic || le.Uint16(in[42:]) != 0 || le.Uint16(in[44:]) != rootEntries || !bytes.Equal(in[52:64], make([]byte, 12)) {
		t.Errorf("extent tree % x", in[40:64])
	}
	if len(res) != 1 || res[0].Cause != target.ResidueDelete || res[0].Entry == nil || res[0].Entry.Number != int64(ino) || res[0].Recoverable != target.RecoverableFull {
		t.Fatalf("residue %+v", res)
	}
	if res[0].Entry.Deleted != when.Format(time.RFC3339Nano) {
		t.Errorf("residue deleted at %s", res[0].Entry.Deleted)
	}
	var got []byte
	for _, x := range res[0].Extents {
		got = append(got, v.raw(t, x.Offset, int(x.Length))...)
	}
	if !bytes.Equal(got, data) {
		t.Error("the extents do not hold the deleted content")
	}
	for _, x := range res[0].Extents {
		if b := uint32(x.Offset / int64(v.fs.g.BlockSize)); v.fs.alloc.Used(int(b)) {
			t.Errorf("block %d is still in use", b)
		}
	}
}

func mustNode(t *testing.T, v testVolume, name string) *volume.Node {
	t.Helper()
	n, err := v.Node(name)
	must(t, err)
	return n
}

// The first entry of a block has no entry before it to fold into: it keeps
// its record length, and everything after that is zeroed.
func TestFirstEntryOfBlockKeepsItsLength(t *testing.T) {
	v := newVolume(t, 16<<20, 1024, volume.NextFit)
	// Fill the directory's first block, so the next name opens a second.
	for i := 0; ; i++ {
		must(t, v.WriteFile(fmt.Sprintf("d/name-%03d", i), nil, target.FileMode))
		if d := rec(mustNode(t, v, "d")); len(d.blocks) == 2 {
			break
		}
	}
	d := rec(mustNode(t, v, "d"))
	blk := d.data[1024:]
	name := string(blk[8 : 8+blk[6]])
	must(t, v.Remove("d/"+name))
	got := v.raw(t, v.fs.g.offset(d.blocks[1]), v.fs.limit)
	if le.Uint32(got[0:]) != 0 || int(le.Uint16(got[4:])) != v.fs.limit || !bytes.Equal(got[6:], make([]byte, v.fs.limit-6)) {
		t.Errorf("first entry after delete: % x", got[:24])
	}
}

// Linux prefers not to reuse an inode deleted within the last minute on a
// volume with no journal; after that, the lowest free inode is reused.
func TestRecentlyDeletedInodeWaits(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	t0 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	v.BeginOp(1, t0)
	must(t, v.WriteFile("a", nil, target.FileMode))
	old := v.ino(t, "a")
	v.BeginOp(2, t0.Add(time.Second))
	must(t, v.Remove("a"))
	v.BeginOp(3, t0.Add(30*time.Second))
	must(t, v.WriteFile("b", nil, target.FileMode))
	if v.ino(t, "b") == old {
		t.Error("an inode deleted 29 seconds ago was reused")
	}
	v.BeginOp(4, t0.Add(2*time.Minute))
	must(t, v.WriteFile("c", nil, target.FileMode))
	if got := v.ino(t, "c"); got != old {
		t.Errorf("c took inode %d, not the free %d", got, old)
	}
}

// A deleted directory goes as a file does, and its parent counts one link
// fewer; the block that held its entries is freed with them in it.
func TestDeleteDirectory(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.MkdirAll("a/b", target.DirMode))
	b := rec(mustNode(t, v, "a/b"))
	ino, blk := b.ino, b.blocks[0]
	must(t, v.Remove("a/b"))
	r, res := v.finish(t)
	if m, err := r.Meta("a"); err != nil || m.Links != 2 {
		t.Errorf("a: %+v, %v", m, err)
	}
	in := v.inode(t, ino)
	if le.Uint16(in[0:]) != modeDir|0o755 || le.Uint16(in[26:]) != 0 || le.Uint32(in[4:]) != 0 || le.Uint32(in[20:]) == 0 {
		t.Errorf("deleted directory inode % x", in[:32])
	}
	if len(res) != 1 || len(res[0].Extents) != 1 || res[0].Extents[0].Offset != v.fs.g.offset(blk) || res[0].Size != int64(v.fs.g.BlockSize) {
		t.Fatalf("residue %+v", res)
	}
	if got := v.raw(t, v.fs.g.offset(blk), 12); le.Uint32(got) != ino || got[8] != '.' {
		t.Errorf("the freed block no longer holds the directory's \".\": % x", got)
	}
}

// Hard links share an inode and count its names; a symlink to a short
// target lives in the inode, a longer one in a block.
func TestLinks(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.WriteFile("f", []byte("data"), target.FileMode))
	must(t, v.MkdirAll("sub", target.DirMode))
	must(t, v.Link("f", "g"))
	must(t, v.Link("f", "sub/h"))
	short, long := "../f", strings.Repeat("x/", 40)+"f"
	must(t, v.Symlink("s", short, false))
	must(t, v.Symlink("sub/l", long, false))
	must(t, v.Remove("g"))
	r, res := v.finish(t)
	if len(res) != 0 {
		t.Errorf("unlinking one name of three left residue %+v", res)
	}
	for _, name := range []string{"f", "sub/h"} {
		m, err := r.Meta(name)
		must(t, err)
		if m.Links != 2 || m.ID != fmt.Sprint(v.ino(t, "f")) {
			t.Errorf("%s: %+v", name, m)
		}
	}
	for name, want := range map[string]string{"s": short, "sub/l": long} {
		m, err := r.Meta(name)
		must(t, err)
		if m.Link != target.LinkSymlink || m.Target != want {
			t.Errorf("%s: %+v", name, m)
		}
	}
	if in := v.inode(t, v.ino(t, "s")); le.Uint32(in[32:])&flagExtents != 0 || string(in[40:40+len(short)]) != short {
		t.Errorf("fast symlink inode % x", in[32:64])
	}
	if rec(mustNode(t, v, "sub/l")).blocks == nil {
		t.Error("the long symlink has no block")
	}
	// The root counts ".", its entry in nothing and lost+found's and sub's
	// "..".
	if root := v.inode(t, rootIno); le.Uint16(root[26:]) != 4 {
		t.Errorf("root links %d", le.Uint16(root[26:]))
	}
}

// fragmented writes a file of eight blocks, each appended after another
// file took the block that followed, so it is in eight runs.
func fragmented(t *testing.T, v testVolume) ([]byte, *node) {
	t.Helper()
	var data []byte
	for i := range 8 {
		chunk := bytes.Repeat([]byte{'a' + byte(i)}, 1024)
		f, err := v.OpenFile("big", os.O_WRONLY|os.O_CREATE|os.O_APPEND, target.FileMode)
		must(t, err)
		_, err = f.Write(chunk)
		must(t, err)
		must(t, f.Close())
		data = append(data, chunk...)
		must(t, v.WriteFile(fmt.Sprintf("pad%d", i), chunk, target.FileMode))
	}
	return data, rec(mustNode(t, v, "big"))
}

// A file in more than four runs of blocks keeps its extents in a leaf
// block the inode indexes.
func TestFragmentedFileUsesALeaf(t *testing.T) {
	v := newVolume(t, 16<<20, 1024, volume.NextFit)
	data, big := fragmented(t, v)
	if len(big.leaves) != 1 {
		t.Fatalf("%d extents in %d leaves", len(extents(big.blocks)), len(big.leaves))
	}
	ino := big.ino
	r, _ := v.finish(t)
	got, err := r.ReadFile("big")
	must(t, err)
	if !bytes.Equal(got, data) {
		t.Error("the fragmented file reads back wrong")
	}
	if in := v.inode(t, ino); le.Uint16(in[46:]) != 1 || le.Uint32(in[28:]) != uint32((8+1)*1024/512) {
		t.Errorf("depth %d, i_blocks %d", le.Uint16(in[46:]), le.Uint32(in[28:]))
	}
}

// Deleting a fragmented file zeroes its leaf's extents and makes the
// inode's root an empty leaf again.
func TestDeleteZeroesLeaf(t *testing.T) {
	v := newVolume(t, 16<<20, 1024, volume.NextFit)
	_, big := fragmented(t, v)
	if len(big.leaves) != 1 {
		t.Fatalf("%d leaves", len(big.leaves))
	}
	leaf, ino := big.leaves[0], big.ino
	n := len(extents(big.blocks))
	must(t, v.Remove("big"))
	_, _ = v.finish(t)
	b := v.raw(t, v.fs.g.offset(leaf), 1024)
	if le.Uint16(b[2:]) != 0 {
		t.Errorf("leaf still counts %d extents", le.Uint16(b[2:]))
	}
	for i := range n {
		e := b[12+12*i:]
		if le.Uint16(e[4:]) != 0 || le.Uint32(e[8:]) != 0 || i > 0 && le.Uint32(e[0:]) == 0 {
			t.Errorf("leaf extent %d: % x", i, e[:12])
		}
	}
	in := v.inode(t, ino)
	if le.Uint16(in[42:]) != 0 || le.Uint16(in[46:]) != 0 || le.Uint32(in[56:]) != leaf {
		t.Errorf("inode root % x", in[40:64])
	}
}

// Directories count their subdirectories in their links, and a directory
// moved to another parent has its ".." repointed.
func TestDirectoryLinksAndRename(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.MkdirAll("a/x", target.DirMode))
	must(t, v.MkdirAll("b", target.DirMode))
	must(t, v.Rename("a/x", "b/y"))
	r, _ := v.finish(t)
	for name, want := range map[string]int{"a": 2, "b": 3, "b/y": 2} {
		m, err := r.Meta(name)
		must(t, err)
		if m.Links != want {
			t.Errorf("%s has %d links, want %d", name, m.Links, want)
		}
	}
	y := rec(mustNode(t, v, "b/y"))
	if got := le.Uint32(v.raw(t, v.fs.g.offset(y.blocks[0])+12, 4)); got != v.ino(t, "b") {
		t.Errorf(`".." names inode %d`, got)
	}
}

// Times keep their nanoseconds, before 1970 and after 2038 included.
func TestTimesKeepNanoseconds(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	want := target.Times{
		Atime: time.Date(1950, 3, 4, 5, 6, 7, 1, time.UTC),
		Mtime: time.Date(2100, 1, 2, 3, 4, 5, 999999999, time.UTC),
		Ctime: time.Date(2440, 12, 31, 0, 0, 0, 500, time.UTC),
		Btime: time.Date(2001, 2, 3, 4, 5, 6, 789, time.UTC),
	}
	must(t, v.WriteFile("f", []byte("x"), target.FileMode))
	must(t, v.SetTimes("f", want))
	r, _ := v.finish(t)
	got, err := r.Times("f")
	must(t, err)
	if got != want {
		t.Errorf("times %+v, want %+v", got, want)
	}
	for _, tm := range []time.Time{MinTime, MaxTime} {
		if d := decodeTime(encodeTime(tm)); !d.Equal(tm) {
			t.Errorf("%s comes back as %s", tm, d)
		}
	}
}

// Slack lands in the file's last block, past where its content ends; the
// rest of the block is zero, as the page cache wrote it.
func TestSlackIsOnDisk(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	must(t, v.WriteFile("f", bytes.Repeat([]byte("a"), 5000), target.FileMode))
	must(t, v.WriteSlack("f", 5000, []byte("SLACK")))
	_, _ = v.finish(t)
	last := rec(mustNode(t, v, "f")).blocks[1]
	b := v.raw(t, v.fs.g.offset(last), 4096)
	if string(b[5000-4096:5000-4096+5]) != "SLACK" || !bytes.Equal(b[5000-4096+5:], make([]byte, 4096-(5000-4096+5))) {
		t.Errorf("last block tail % x", b[900:920])
	}
}

// Rewriting a file from scratch frees its blocks with their bytes; with
// next-fit allocation the new content goes elsewhere.
func TestOverwriteLeavesResidue(t *testing.T) {
	v := newVolume(t, 16<<20, 0, volume.NextFit)
	old := bytes.Repeat([]byte("old "), 2000)
	must(t, v.WriteFile("f", old, target.FileMode))
	must(t, v.WriteFile("f", []byte("new"), target.FileMode))
	r, res := v.finish(t)
	if got, err := r.ReadFile("f"); err != nil || string(got) != "new" {
		t.Fatalf("f reads %q, %v", got, err)
	}
	if len(res) != 1 || res[0].Cause != target.ResidueOverwrite || res[0].Recoverable != target.RecoverableFull || res[0].Size != int64(len(old)) {
		t.Fatalf("residue %+v", res)
	}
}
