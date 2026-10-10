package conformance

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	diskfs "github.com/diskfs/go-diskfs"
	diskext4 "github.com/diskfs/go-diskfs/filesystem/ext4"
	goext4 "github.com/dsoprea/go-ext4"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/fsagen/volume/image"
)

// object is what a reader is asked about one name: a file's bytes, a
// symlink's target, and the inode and its link count.
type object struct {
	dir    bool
	data   []byte
	target string
	ino    string
	links  int
}

// ext4Images are the two ways the ext4 tests put the volume on disk: bare,
// and in an MBR partition of a VHD, offset bytes in.
var ext4Images = []struct {
	file, partition string
	index           int
	offset          int64
}{
	{"bare.img", container.PartitionNone, 0, 0},
	{"disk.vhd", container.PartitionMBR, 1, container.MBRStart * 512},
}

// buildExt4 writes testdata/image/ext4.yaml into an ext4 image at path,
// and returns its tree as fsagen's own reader saw it once finished.
func buildExt4(t *testing.T, path, partition string) map[string]object {
	t.Helper()
	prog, err := compile.Load(compile.ModeManifest, filepath.Join("..", "..", "testdata", "image", "ext4.yaml"), compile.Options{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	plan, err := image.NewPlan(image.Options{Path: path, FS: image.FSExt4, Size: 64 << 20, Partition: partition, Label: "evidence", Time: time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC), Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	img, err := image.Create(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Abort()
	_, read, err := manifest.Run(img, prog, false)
	if err != nil {
		t.Fatal(err)
	}
	ours := map[string]object{}
	err = read.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		m, err := read.Meta(name)
		if err != nil {
			return err
		}
		o := object{dir: d.IsDir(), target: m.Target, ino: m.ID, links: m.Links}
		if d.Type().IsRegular() {
			if o.data, err = read.ReadFile(name); err != nil {
				return err
			}
		}
		ours[name] = o
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := img.Close(); err != nil {
		t.Fatal(err)
	}
	return ours
}

// compare checks that a reader found what fsagen's own did. A name in
// shallow is checked for its kind and inode alone.
func compare(t *testing.T, reader string, ours, got map[string]object, shallow map[string]bool) {
	t.Helper()
	names := func(m map[string]object) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	if a, b := names(ours), names(got); !slices.Equal(a, b) {
		t.Fatalf("names differ:\nfsagen %q\n%s %q", a, reader, b)
	}
	links := 0
	for name, o := range ours {
		g := got[name]
		if shallow[name] {
			o = object{dir: o.dir, ino: o.ino}
		}
		if !bytes.Equal(o.data, g.data) || o.target != g.target || o.ino != g.ino || o.links != g.links || o.dir != g.dir {
			t.Errorf("%s: %s found %d bytes, target %q, inode %s with %d links; fsagen %d bytes, target %q, inode %s with %d links",
				name, reader, len(g.data), g.target, g.ino, g.links, len(o.data), o.target, o.ino, o.links)
		}
		if o.target != "" {
			links++
		}
	}
	if len(ours) < 70 || links == 0 {
		t.Errorf("only %d names and %d symlinks checked: the scenario did not run", len(ours), links)
	}
}

// TestExt4ReadByGoDiskfs: github.com/diskfs/go-diskfs opens an ext4 image
// fsagen wrote, bare and inside an MBR-partitioned VHD, checking every
// checksum it passes, and finds every name and every byte fsagen's own
// reader found, each symlink's target, and each name's inode and link
// count, hard links included.
func TestExt4ReadByGoDiskfs(t *testing.T) {
	for _, c := range ext4Images {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.file)
			ours := buildExt4(t, path, c.partition)
			disk, err := diskfs.Open(path, diskfs.WithOpenMode(diskfs.ReadOnly))
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			fsys, err := disk.GetFilesystem(c.index)
			if err != nil {
				t.Fatalf("go-diskfs: %v", err)
			}
			theirs, ok := fsys.(*diskext4.FileSystem)
			if !ok {
				t.Fatalf("go-diskfs found a %T", fsys)
			}
			got := map[string]object{}
			err = fs.WalkDir(theirs, ".", func(name string, d fs.DirEntry, err error) error {
				if err != nil || name == "." {
					return err
				}
				if name == "lost+found" {
					return fs.SkipDir
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				st, ok := info.Sys().(*diskext4.StatT)
				if !ok {
					return fmt.Errorf("%s: no inode", name)
				}
				o := object{dir: d.IsDir(), ino: fmt.Sprint(st.Ino), links: int(st.Nlink)}
				switch {
				case info.Mode()&fs.ModeSymlink != 0:
					if o.target, err = theirs.ReadLink(name); err != nil {
						return err
					}
				case info.Mode().IsRegular():
					if o.data, err = theirs.ReadFile(name); err != nil {
						return err
					}
				}
				got[name] = o
				return nil
			})
			if err != nil {
				t.Fatalf("go-diskfs walk: %v", err)
			}
			compare(t, "go-diskfs", ours, got, nil)
		})
	}
}

// TestExt4ReadByGoExt4: github.com/dsoprea/go-ext4, which reads only
// volumes with flex_bg, as fsagen's are, finds every name and every byte
// fsagen's own reader found, each long symlink's target, and each name's
// inode and link count. It refuses an inode without an extent tree, which
// a symlink short enough to live in its inode is, as Linux writes it, so
// such a symlink is checked by its entry alone.
func TestExt4ReadByGoExt4(t *testing.T) {
	for _, c := range ext4Images {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.file)
			ours := buildExt4(t, path, c.partition)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			got, fast, err := readGoExt4(io.NewSectionReader(f, c.offset, info.Size()-c.offset))
			if err != nil {
				t.Fatalf("go-ext4: %v", err)
			}
			for name := range fast {
				if o := ours[name]; o.target == "" || len(o.target) >= 60 {
					t.Errorf("go-ext4 could not read %s, which is not a short symlink", name)
				}
			}
			compare(t, "go-ext4", ours, got, fast)
		})
	}
}

// readGoExt4 walks the volume in rs with go-ext4, as its own tests do, and
// reads every file and long symlink through it. fast are the symlinks
// whose inodes it refuses.
func readGoExt4(rs io.ReadSeeker) (map[string]object, map[string]bool, error) {
	if _, err := rs.Seek(goext4.Superblock0Offset, io.SeekStart); err != nil {
		return nil, nil, err
	}
	sb, err := goext4.NewSuperblockWithReader(rs)
	if err != nil {
		return nil, nil, err
	}
	bgdl, err := goext4.NewBlockGroupDescriptorListWithReadSeeker(rs, sb)
	if err != nil {
		return nil, nil, err
	}
	bgd, err := bgdl.GetWithAbsoluteInode(goext4.InodeRootDirectory)
	if err != nil {
		return nil, nil, err
	}
	dw, err := goext4.NewDirectoryWalk(rs, bgd, goext4.InodeRootDirectory)
	if err != nil {
		return nil, nil, err
	}
	got, fast := map[string]object{}, map[string]bool{}
	for {
		name, de, err := dw.Next()
		if err == io.EOF {
			return got, fast, nil
		}
		if err != nil {
			return nil, nil, err
		}
		// go-ext4 yields what is not a name too: a wiped entry and the
		// entry that holds a block's checksum, both with no inode.
		ino := int(de.Data().Inode)
		if ino == 0 || name == "lost+found" {
			continue
		}
		o := object{dir: de.IsDirectory(), ino: fmt.Sprint(ino)}
		in, err := goext4.NewInodeWithReadSeeker(bgd, rs, ino)
		if err != nil && de.IsSymbolicLink() {
			fast[name] = true
			got[name] = o
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		o.links = int(in.Data().ILinksCount)
		if de.IsSymbolicLink() || de.IsRegular() {
			data := make([]byte, in.Size())
			if _, err := io.ReadFull(goext4.NewInodeReader(goext4.NewExtentNavigatorWithReadSeeker(rs, in)), data); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if de.IsSymbolicLink() {
				o.target = string(data)
			} else {
				o.data = data
			}
		}
		got[name] = o
	}
}
