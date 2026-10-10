package conformance

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume/image"
)

// ntfsObject is what go-ntfs is asked about one name: its kind, bytes,
// record, link count and times.
type ntfsObject struct {
	object
	times target.Times
}

// buildNTFS writes testdata/image/ntfs.yaml into an NTFS image at path,
// and returns its tree as fsagen's own reader saw it once finished, and
// the residue its writes left.
func buildNTFS(t *testing.T, path, partition string) (map[string]ntfsObject, []target.Residue) {
	t.Helper()
	prog, err := compile.Load(compile.ModeManifest, filepath.Join("..", "..", "testdata", "image", "ntfs.yaml"), compile.Options{Seed: 1, FoldCase: true})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	plan, err := image.NewPlan(image.Options{Path: path, FS: image.FSNTFS, Size: 64 << 20, Partition: partition, Label: "evidence", Time: time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC), Seed: 1})
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
	ours := map[string]ntfsObject{}
	err = read.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		m, err := read.Meta(name)
		if err != nil {
			return err
		}
		o := ntfsObject{object{dir: d.IsDir(), ino: m.ID, links: m.Links}, m.Times}
		if !o.dir {
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
	residue := img.Residue()
	if _, err := img.Close(); err != nil {
		t.Fatal(err)
	}
	return ours, residue
}

// TestNTFSReadByGoNTFS: www.velocidex.com/golang/go-ntfs opens an NTFS
// image fsagen wrote, bare and inside an MBR-partitioned VHD, walks it from
// the root through every directory's $I30 index, and finds every name and
// every byte fsagen's own reader found, each name's record and link count,
// and its four $STANDARD_INFORMATION times to the 100 ns; and it reads
// each deleted record the answer key names as deleted, with the sequence
// number and name the key gives.
func TestNTFSReadByGoNTFS(t *testing.T) {
	for _, c := range ext4Images {
		t.Run(c.file, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), c.file)
			ours, residue := buildNTFS(t, p, c.partition)
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			paged, err := ntfs.NewPagedReader(io.NewSectionReader(f, c.offset, info.Size()-c.offset), 1024, 10000)
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := ntfs.GetNTFSContext(paged, 0)
			if err != nil {
				t.Fatalf("go-ntfs: %v", err)
			}
			got := map[string]ntfsObject{}
			if err := walkGoNTFS(ctx, 5, "", got); err != nil {
				t.Fatalf("go-ntfs: %v", err)
			}
			plain := func(m map[string]ntfsObject) map[string]object {
				out := map[string]object{}
				for k, v := range m {
					out[k] = v.object
				}
				return out
			}
			compareNTFS(t, plain(ours), plain(got))
			for name, o := range ours {
				if g := got[name]; g.times != o.times {
					t.Errorf("%s: go-ntfs reads times %+v; fsagen %+v", name, g.times, o.times)
				}
			}
			n := 0
			for _, r := range residue {
				e := r.Entry
				if e == nil || e.Overwritten {
					continue
				}
				mft, err := ctx.GetMFT(e.Number)
				if err != nil {
					t.Fatalf("go-ntfs: record %d: %v", e.Number, err)
				}
				name := ""
				for _, a := range mft.EnumerateAttributes(ctx) {
					if a.Type().Value == ntfs.ATTR_TYPE_FILE_NAME {
						name = ctx.Profile.FILE_NAME(a.Data(ctx), 0).Name()
					}
				}
				if mft.Flags().IsSet("ALLOCATED") || int(mft.Sequence_value()) != e.Seq || name != path.Base(r.Path) {
					t.Errorf("deleted record %d: go-ntfs reads flags %v, sequence %d, name %q; the answer key says %s, sequence %d",
						e.Number, mft.Flags().Names, mft.Sequence_value(), name, r.Path, e.Seq)
				}
				n++
			}
			if n < 4 {
				t.Errorf("only %d deleted records checked", n)
			}
		})
	}
}

// walkGoNTFS lists the directory in record id, named dir, and every one
// under it, with go-ntfs, leaving out the system files at the root.
func walkGoNTFS(ctx *ntfs.NTFSContext, id int64, dir string, got map[string]ntfsObject) error {
	mft, err := ctx.GetMFT(id)
	if err != nil {
		return err
	}
	for _, fi := range ntfs.ListDir(ctx, mft) {
		var num int64
		if _, err := fmt.Sscanf(fi.MFTId, "%d-", &num); err != nil {
			return fmt.Errorf("%s: an MFT id %q", fi.Name, fi.MFTId)
		}
		if dir == "" && (num < 16 || fi.Name == ".") {
			continue
		}
		name := path.Join(dir, fi.Name)
		rec, err := ctx.GetMFT(num)
		if err != nil {
			return err
		}
		if !rec.Flags().IsSet("ALLOCATED") {
			continue
		}
		o := ntfsObject{object{dir: fi.IsDir, ino: fmt.Sprint(num), links: int(rec.Link_count())}, target.Times{Atime: fi.Atime, Mtime: fi.Mtime, Ctime: fi.Ctime, Btime: fi.Btime}}
		if _, dup := got[name]; dup {
			return fmt.Errorf("%s is listed twice", name)
		}
		if fi.IsDir {
			got[name] = o
			if err := walkGoNTFS(ctx, num, name, got); err != nil {
				return err
			}
			continue
		}
		data, err := ntfs.GetDataForPath(ctx, strings.ReplaceAll(name, "/", "\\"))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		o.data = make([]byte, fi.Size)
		if _, err := data.ReadAt(o.data, 0); err != nil && err != io.EOF {
			return fmt.Errorf("%s: %w", name, err)
		}
		got[name] = o
	}
	return nil
}

// compareNTFS checks that go-ntfs found what fsagen's own reader did.
func compareNTFS(t *testing.T, ours, got map[string]object) {
	t.Helper()
	if len(ours) < 25 {
		t.Fatalf("only %d names: the scenario did not run", len(ours))
	}
	for name, o := range ours {
		g, ok := got[name]
		if !ok {
			t.Errorf("go-ntfs does not list %s", name)
			continue
		}
		if string(o.data) != string(g.data) || o.ino != g.ino || o.links != g.links || o.dir != g.dir {
			t.Errorf("%s: go-ntfs found %d bytes, record %s with %d links; fsagen %d bytes, record %s with %d links",
				name, len(g.data), g.ino, g.links, len(o.data), o.ino, o.links)
		}
	}
	for name := range got {
		if _, ok := ours[name]; !ok {
			t.Errorf("go-ntfs lists %s, which fsagen does not", name)
		}
	}
}
