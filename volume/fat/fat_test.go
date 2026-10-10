package fat

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

var clock = time.Date(2022, 6, 1, 8, 0, 0, 0, time.UTC)

// testVolume is a 40 MiB FAT32 volume of 512-byte clusters in a file.
type testVolume struct {
	*volume.Volume
	fs   *FS
	file *os.File
}

func newVolume(t *testing.T, policy string) testVolume {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "fat.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	const size = 40 << 20
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	res := &volume.Tracker{}
	fsys, err := Format(volume.NewDevice(f, 0, size), Options{Label: "TEST", Serial: 0x1234ABCD, Clock: clock, Alloc: policy}, res)
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

// finish finishes the volume and reads it back.
func (v testVolume) finish(t *testing.T) (target.Reader, []target.Residue) {
	t.Helper()
	r, err := v.Finish()
	must(t, err)
	return r, v.Residue()
}

// Windows' cluster sizes, the 65525-cluster floor, and the FAT size
// Microsoft's formula gives.
func TestPlan(t *testing.T) {
	g, err := Plan(512<<20, 0)
	must(t, err)
	if g.ClusterSize != 4096 || g.Clusters < minClusters || int64(g.FATSectors)*sectorSize/4 < int64(g.Clusters+2) {
		t.Errorf("512 MiB: %+v", g)
	}
	if _, err := Plan(32<<20, 0); err == nil || !strings.Contains(err.Error(), "MiB") {
		t.Errorf("32 MiB: %v", err)
	}
	if _, err := Plan(100<<20, 4096); err == nil {
		t.Error("100 MiB of 4 KiB clusters is under the floor and was accepted")
	}
	if _, err := Plan(100<<20, 3000); err == nil {
		t.Error("a 3000-byte cluster was accepted")
	}
}

// A deleted file keeps its entries, but for 0xE5 over each first byte, and
// its bytes; only the FAT forgets its chain. The residue says where both are.
func TestDeleteLeavesEntryAndContent(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	data := bytes.Repeat([]byte("evidence "), 200) // 1800 bytes: 4 clusters
	must(t, v.WriteFile("dir/A Long Secret Name.docx", data, target.FileMode))
	must(t, v.Remove("dir/A Long Secret Name.docx"))
	r, res := v.finish(t)
	if _, err := r.Meta("dir/A Long Secret Name.docx"); err == nil {
		t.Fatal("the deleted file is still listed")
	}
	if len(res) != 1 || res[0].Cause != target.ResidueDelete || res[0].Recoverable != target.RecoverableFull || res[0].Entry == nil {
		t.Fatalf("residue %+v", res)
	}
	e := v.raw(t, res[0].Entry.Offset, entrySize)
	if e[0] != deleted || string(e[1:11]) != "LONGS~1DOC" || e[11] != attrArchive || le32(e[28:]) != uint32(len(data)) {
		t.Errorf("deleted short entry % x", e)
	}
	// The two long-name entries before it are deleted too.
	for k := 1; k <= 2; k++ {
		if lfn := v.raw(t, res[0].Entry.Offset-int64(k*entrySize), entrySize); lfn[0] != deleted || lfn[11] != attrLFN {
			t.Errorf("long entry %d before: % x", k, lfn)
		}
	}
	var got []byte
	for _, x := range res[0].Extents {
		got = append(got, v.raw(t, x.Offset, int(x.Length))...)
	}
	if !bytes.Equal(got, data) {
		t.Error("the extents do not hold the deleted content")
	}
	if first := firstCluster(e); v.fs.fat[first] != 0 {
		t.Errorf("cluster %d still chained: %#x", first, v.fs.fat[first])
	}
}

// Windows reuses deleted entries first, and a new name over a deleted one
// leaves its residue overwritten.
func TestDeletedEntriesAreReusedFirst(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	must(t, v.WriteFile("d/one.txt", []byte("1"), target.FileMode))
	must(t, v.WriteFile("d/two.txt", []byte("2"), target.FileMode))
	must(t, v.Remove("d/one.txt"))
	must(t, v.WriteFile("d/new.txt", []byte("3"), target.FileMode))
	_, res := v.finish(t)
	if len(res) != 1 || !res[0].Entry.Overwritten {
		t.Fatalf("residue %+v", res)
	}
	// "." and ".." take entries 0 and 1, so one.txt was entry 2.
	if v.raw(t, res[0].Entry.Offset, 1)[0] != 'N' {
		t.Errorf("entry 2 holds % x, want NEW.TXT", v.raw(t, res[0].Entry.Offset, 11))
	}
}

// Next-fit leaves freed clusters alone; first-fit takes them straight back,
// and the residue says how much of the deleted file is gone.
func TestAllocationPolicyDecidesRecovery(t *testing.T) {
	for _, c := range []struct {
		policy, want string
	}{
		{volume.NextFit, target.RecoverableFull},
		{volume.FirstFit, target.RecoverableNone},
	} {
		v := newVolume(t, c.policy)
		must(t, v.WriteFile("old.bin", bytes.Repeat([]byte{0xAA}, 1024), target.FileMode))
		must(t, v.Remove("old.bin"))
		must(t, v.WriteFile("new.bin", bytes.Repeat([]byte{0xBB}, 2048), target.FileMode))
		_, res := v.finish(t)
		if len(res) != 1 || res[0].Recoverable != c.want {
			t.Errorf("%s: residue %+v, want %s", c.policy, res, c.want)
		}
	}
}

// Rewriting a file after truncating it frees its clusters, whose bytes stay
// behind; a shorter rewrite in place frees only the tail.
func TestOverwriteLeavesOldContent(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	old := bytes.Repeat([]byte("old!"), 300) // 1200 bytes, 3 clusters
	must(t, v.WriteFile("f.txt", old, target.FileMode))
	must(t, v.WriteFile("f.txt", []byte("new"), target.FileMode))
	r, res := v.finish(t)
	if data, _ := r.ReadFile("f.txt"); string(data) != "new" {
		t.Errorf("content %q", data)
	}
	if len(res) != 1 || res[0].Cause != target.ResidueOverwrite || res[0].Size != 1200 || res[0].Recoverable != target.RecoverableFull || res[0].Entry != nil {
		t.Fatalf("residue %+v", res)
	}
}

// A directory grows a zeroed cluster at a time, and every name in it reads
// back.
func TestDirectoryGrows(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	for i := range 100 {
		must(t, v.WriteFile(fmt.Sprintf("many/entry number %03d.log", i), []byte{byte(i)}, target.FileMode))
	}
	r, _ := v.finish(t)
	entries, err := r.ReadDirQuiet("many")
	must(t, err)
	if len(entries) != 100 {
		t.Fatalf("%d entries read back", len(entries))
	}
	// 2 dot entries and 100 names of 3 entries each, 16 entries a cluster.
	d := rec(mustNode(t, v, "many"))
	if len(d.chain) != (2+300+15)/16 {
		t.Errorf("the directory has %d clusters", len(d.chain))
	}
}

// Times read back to FAT's resolution: the creation time to 10 ms, the
// write time to 2 s, the access date to the day, and no change time.
func TestTimesKeepFATResolution(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	must(t, v.WriteFile("t.txt", nil, target.FileMode))
	at := time.Date(2024, 2, 29, 23, 59, 59, 999_999_999, time.UTC)
	must(t, v.SetTimes("t.txt", target.Times{Atime: at, Mtime: at, Ctime: at, Btime: at}))
	r, _ := v.finish(t)
	got, err := r.Times("t.txt")
	must(t, err)
	want := target.Times{
		Atime: time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
		Mtime: time.Date(2024, 2, 29, 23, 59, 58, 0, time.UTC),
		Btime: time.Date(2024, 2, 29, 23, 59, 59, 990_000_000, time.UTC),
	}
	if got != want {
		t.Errorf("times %+v, want %+v", got, want)
	}
}

// Slack goes in the rest of the last cluster and the file is unchanged.
func TestSlackIsOnDisk(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	content := bytes.Repeat([]byte("c"), 700)
	must(t, v.WriteFile("s.bin", content, target.FileMode))
	slack := bytes.Repeat([]byte("S"), 1024-700)
	must(t, v.WriteSlack("s.bin", 700, slack))
	r, _ := v.finish(t)
	if data, _ := r.ReadFile("s.bin"); !bytes.Equal(data, content) {
		t.Error("the content changed")
	}
	n := rec(mustNode(t, v, "s.bin"))
	off := v.fs.g.clusterOffset(n.chain[1]) + 700 - 512
	if got := v.raw(t, off, len(slack)); !bytes.Equal(got, slack) {
		t.Errorf("slack on disk %q", got[:16])
	}
	if err := v.WriteSlack("s.bin", 600, slack); err == nil {
		t.Error("slack before the end of the content was written")
	}
}

func mustNode(t *testing.T, v testVolume, name string) *volume.Node {
	t.Helper()
	n, err := v.Node(name)
	must(t, err)
	return n
}

// A directory moved to another parent has its ".." entry repointed, and its
// old entries stay behind as rename residue.
func TestRenameDirectory(t *testing.T) {
	v := newVolume(t, volume.NextFit)
	must(t, v.WriteFile("a/sub/f.txt", []byte("x"), target.FileMode))
	must(t, v.MkdirAll("b", target.DirMode))
	must(t, v.Rename("a/sub", "b/Moved Sub"))
	r, res := v.finish(t)
	if data, err := r.ReadFile("b/Moved Sub/f.txt"); err != nil || string(data) != "x" {
		t.Fatalf("read after the move: %q %v", data, err)
	}
	sub, b := rec(mustNode(t, v, "b/Moved Sub")), rec(mustNode(t, v, "b"))
	if dotdot := v.raw(t, v.fs.g.clusterOffset(sub.chain[0])+entrySize, entrySize); firstCluster(dotdot) != b.chain[0] {
		t.Errorf(".. points at cluster %d, want %d", firstCluster(dotdot), b.chain[0])
	}
	if len(res) != 1 || res[0].Cause != target.ResidueRename {
		t.Errorf("residue %+v", res)
	}
}
