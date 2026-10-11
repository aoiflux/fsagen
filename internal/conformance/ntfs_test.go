package conformance

import (
	"bytes"
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
	"github.com/aoiflux/fsagen/internal/reparse"
	"github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume/image"
)

// ntfsObject is what go-ntfs is asked about one name: its kind, bytes,
// record, link count and times, the times of the name's $FILE_NAME, its
// named streams, and for a link its reparse data.
type ntfsObject struct {
	object
	times, fn target.Times
	streams   map[string]string
	reparse   []byte
}

// ntfsFixture is the NTFS image fixture.
var ntfsFixture = filepath.Join("..", "..", "testdata", "image", "ntfs.yaml")

// bigDirectory writes a manifest that fills a directory, and one inside
// it, with hundreds of long names, several levels of index blocks deep,
// and then deletes most of them, and returns its path.
func bigDirectory(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("start: \"2023-03-01T09:00:00Z\"\noperations:\n")
	name := func(i int) string {
		return fmt.Sprintf("Big/%s%04d-%s.dat", []string{"", "Sub/"}[i%2], i, strings.Repeat("evidence-", 1+i%13))
	}
	for i := range 700 {
		fmt.Fprintf(&b, "  - action: create\n    path: %q\n    content_len: %d\n", name(i), 1+i%3*700)
	}
	for i := 0; i < 700; i += 3 {
		fmt.Fprintf(&b, "  - action: delete\n    path: %q\n", name(i))
	}
	p := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// buildNTFS writes the manifest at fixture into an NTFS image at path, and
// returns its tree as fsagen's own reader saw it once finished, and the
// residue its writes left.
func buildNTFS(t *testing.T, fixture, path, partition string) (map[string]ntfsObject, []target.Residue) {
	t.Helper()
	prog, err := compile.Load(compile.ModeManifest, fixture, compile.Options{Seed: 1, FoldCase: true})
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
		o := ntfsObject{object: object{dir: d.IsDir(), ino: m.ID, links: m.Links}, times: m.Times, fn: *m.FileName, streams: map[string]string{}}
		switch m.Link {
		case target.LinkSymlink:
			o.reparse, err = reparse.Symlink(m.Target)
		case target.LinkJunction:
			o.reparse, err = reparse.Junction(`C:\` + strings.ReplaceAll(m.Target, "/", `\`))
		}
		if err != nil {
			return err
		}
		ours[name] = o
		if o.reparse != nil {
			return nil
		}
		if !o.dir {
			if o.data, err = read.ReadFile(name); err != nil {
				return err
			}
		}
		streams, err := read.Streams(name)
		if err != nil {
			return err
		}
		for _, st := range streams {
			data, err := read.ReadStream(name, st.Name)
			if err != nil {
				return err
			}
			o.streams[st.Name] = string(data)
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
// every byte fsagen's own reader found: each name's record and link count,
// so that a hard link's names share one record; its four
// $STANDARD_INFORMATION times and the four times of the name's own
// $FILE_NAME to the 100 ns; its named streams, byte for byte; and for a
// symlink or junction, its reparse data.
// It reads each deleted record the answer key names as deleted, with the
// sequence number and name the key gives, and finds each index entry the
// key says a delete or rename left, in the directory's index blocks.
// Besides the fixture, it reads a directory whose index is several levels
// of blocks deep, most of it deleted.
func TestNTFSReadByGoNTFS(t *testing.T) {
	type image struct {
		file, partition string
		offset          int64
		fixture         string
		// big names a directory whose index must span 20 blocks or more.
		big string
	}
	var images []image
	for _, c := range ext4Images {
		images = append(images, image{c.file, c.partition, c.offset, ntfsFixture, ""})
	}
	images = append(images, image{"big.img", ext4Images[0].partition, 0, bigDirectory(t), "Big"})
	for _, c := range images {
		t.Run(c.file, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), c.file)
			ours, residue := buildNTFS(t, c.fixture, p, c.partition)
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
			if c.big != "" {
				var num int64
				fmt.Sscan(got[c.big].ino, &num)
				mft, err := ctx.GetMFT(num)
				if err != nil {
					t.Fatalf("go-ntfs: %v", err)
				}
				var blocks int64
				for _, a := range mft.EnumerateAttributes(ctx) {
					if a.Type().Value == ntfs.ATTR_TYPE_INDEX_ALLOCATION {
						blocks = a.DataSize() / 4096
					}
				}
				if blocks < 20 {
					t.Errorf("go-ntfs reads %d index blocks in %s", blocks, c.big)
				}
			}
			links, streams := 0, 0
			for name, o := range ours {
				g := got[name]
				if g.times != o.times || g.fn != o.fn {
					t.Errorf("%s: go-ntfs reads times %+v and $FILE_NAME times %+v; fsagen %+v and %+v", name, g.times, g.fn, o.times, o.fn)
				}
				if !bytes.Equal(g.reparse, o.reparse) {
					t.Errorf("%s: go-ntfs reads reparse data % x; fsagen % x", name, g.reparse, o.reparse)
				}
				if fmt.Sprint(g.streams) != fmt.Sprint(o.streams) {
					t.Errorf("%s: go-ntfs reads streams %q; fsagen %q", name, g.streams, o.streams)
				}
				if o.reparse != nil {
					links++
				}
				streams += len(o.streams)
			}
			if c.big == "" && (links < 3 || streams < 3) {
				t.Errorf("only %d links and %d streams checked", links, streams)
			}
			checkDeleted(t, ctx, ours, residue, c.big == "")
		})
	}
}

// checkDeleted checks with go-ntfs what the answer key says deletes and
// renames left: each deleted record, and each index entry, among those
// go-ntfs carves from the directory's index blocks.
func checkDeleted(t *testing.T, ctx *ntfs.NTFSContext, ours map[string]ntfsObject, residue []target.Residue, entries bool) {
	t.Helper()
	records, carved := 0, 0
	for _, r := range residue {
		e := r.Entry
		if e == nil || e.Overwritten {
			continue
		}
		if e.Type == "ntfs_index_entry" {
			dir, ok := ours[path.Dir(r.Path)]
			if !ok {
				continue
			}
			var num int64
			fmt.Sscan(dir.ino, &num)
			mft, err := ctx.GetMFT(num)
			if err != nil {
				t.Fatalf("go-ntfs: %v", err)
			}
			found := false
			for _, fi := range ntfs.ExtractI30List(ctx, mft) {
				found = found || fi.MFTId == fmt.Sprint(e.Number) && fi.Name == path.Base(r.Path)
			}
			if !found {
				t.Errorf("go-ntfs finds no index entry for %s, record %d, in %s's index", r.Path, e.Number, path.Dir(r.Path))
			}
			carved++
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
		records++
	}
	if records < 4 || entries && carved < 1 {
		t.Errorf("only %d deleted records and %d index entries checked", records, carved)
	}
}

// walkGoNTFS lists the directory in record id, named dir, and every one
// under it, with go-ntfs, leaving out the system files at the root. go-ntfs
// lists a record once per directory, under one of its names; each of the
// record's names in the directory is taken from its own $FILE_NAME.
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
		if dir == "" && (num < 16 || fi.Name == ".") || strings.Contains(fi.Name, ":") {
			continue
		}
		rec, err := ctx.GetMFT(num)
		if err != nil {
			return err
		}
		if !rec.Flags().IsSet("ALLOCATED") {
			continue
		}
		var names []*ntfs.FILE_NAME
		var data []*ntfs.NTFS_ATTRIBUTE
		var rp []byte
		for _, a := range rec.EnumerateAttributes(ctx) {
			switch a.Type().Value {
			case ntfs.ATTR_TYPE_FILE_NAME:
				fn := ctx.Profile.FILE_NAME(a.Data(ctx), 0)
				if int64(fn.MftReference()) == id && fn.NameType().Name != "DOS" {
					names = append(names, fn)
				}
			case ntfs.ATTR_TYPE_DATA:
				if a.Name() != "" {
					data = append(data, a)
				}
			case attrReparsePoint:
				rp = make([]byte, a.DataSize())
				if _, err := a.Data(ctx).ReadAt(rp, 0); err != nil && err != io.EOF {
					return err
				}
			}
		}
		for _, fn := range names {
			name := path.Join(dir, fn.Name())
			if _, dup := got[name]; dup {
				return fmt.Errorf("%s is listed twice", name)
			}
			o := ntfsObject{
				object:  object{dir: fi.IsDir && rp == nil, ino: fmt.Sprint(num), links: int(rec.Link_count())},
				times:   target.Times{Atime: fi.Atime, Mtime: fi.Mtime, Ctime: fi.Ctime, Btime: fi.Btime},
				fn:      target.Times{Btime: fn.Created().Time, Mtime: fn.File_modified().Time, Ctime: fn.Mft_modified().Time, Atime: fn.File_accessed().Time},
				streams: map[string]string{},
				reparse: rp,
			}
			if rp != nil {
				got[name] = o
				continue
			}
			native := strings.ReplaceAll(name, "/", `\`)
			for _, a := range data {
				r, err := ntfs.GetDataForPath(ctx, native+":"+a.Name())
				if err != nil {
					return fmt.Errorf("%s:%s: %w", name, a.Name(), err)
				}
				b := make([]byte, a.DataSize())
				if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
					return fmt.Errorf("%s:%s: %w", name, a.Name(), err)
				}
				o.streams[a.Name()] = string(b)
			}
			if o.dir {
				got[name] = o
				if err := walkGoNTFS(ctx, num, name, got); err != nil {
					return err
				}
				continue
			}
			r, err := ntfs.GetDataForPath(ctx, native)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			o.data = make([]byte, fi.Size)
			if _, err := r.ReadAt(o.data, 0); err != nil && err != io.EOF {
				return fmt.Errorf("%s: %w", name, err)
			}
			got[name] = o
		}
	}
	return nil
}

// attrReparsePoint is $REPARSE_POINT's type, which go-ntfs names but
// keeps no constant for.
const attrReparsePoint = 0xC0

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
