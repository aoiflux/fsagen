package fat

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/libfat"
)

// Reader reads a FAT32 volume from disk through libfat, knowing nothing of
// how it was written. It opens the volume strict, so a chain that runs into
// a free cluster or disagrees with its size, a broken long name, a "." or
// ".." out of place, a duplicate name or FAT copies that differ are errors,
// not a tolerant reading.
type Reader struct {
	vol  *libfat.Volume
	root *entryNode
}

// entryNode is one object as its directory entry describes it.
type entryNode struct {
	e        libfat.DirEntry
	name     string
	dir, ro  bool
	size     int64
	times    target.Times
	addr     int64
	children []*entryNode
	byKey    map[string]*entryNode
}

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	vol, err := libfat.OpenWithOptions(dev, libfat.OpenOptions{CacheFAT: true, Strict: true})
	if err != nil {
		return nil, fmt.Errorf("fat: %w", err)
	}
	if vol.FATType() != libfat.FATType32 {
		return nil, fmt.Errorf("fat: a %s volume, not FAT32", vol.FATType())
	}
	r := &Reader{vol: vol, root: &entryNode{dir: true, addr: 2}}
	root, err := vol.GetRootDirectory()
	if err != nil {
		return nil, fmt.Errorf("fat: %w", err)
	}
	if err := r.load(r.root, root, "."); err != nil {
		return nil, err
	}
	return r, nil
}

// address is The Sleuth Kit's number for the directory entry at off: the
// entries of the data area counted from 3, root being 2.
func (r *Reader) address(off int64) int64 {
	g := r.vol.Geometry()
	return off/libfat.DirEntrySize - int64(g.FirstDataSector)*int64(g.BytesPerSector/libfat.DirEntrySize) + 3
}

// load reads directory d, open as f and named p, and every directory under
// it.
func (r *Reader) load(d *entryNode, f *libfat.File, p string) error {
	es, err := f.ReadDirWithOptions(libfat.ReadDirOptions{ExcludeDeleted: true})
	if err != nil {
		return fmt.Errorf("fat: %s: %w", p, err)
	}
	d.byKey = map[string]*entryNode{}
	for _, e := range es {
		n := &entryNode{
			e: e, name: e.Name, dir: e.IsDirectory, ro: e.Attributes&libfat.AttrReadOnly != 0, size: int64(e.Size),
			times: target.Times{Btime: e.CreatedAt, Mtime: e.ModifiedAt, Atime: e.AccessedAt},
			addr:  r.address(e.EntryAbsoluteOffset),
		}
		key := pathpolicy.FoldKey(n.name)
		if _, dup := d.byKey[key]; dup {
			return fmt.Errorf("fat: %s: two entries named %q", p, n.name)
		}
		d.byKey[key] = n
		d.children = append(d.children, n)
	}
	slices.SortFunc(d.children, func(a, b *entryNode) int { return strings.Compare(a.name, b.name) })
	for _, c := range d.children {
		if c.dir {
			cf, err := r.vol.OpenEntry(c.e)
			if err != nil {
				return fmt.Errorf("fat: %s: %w", path.Join(p, c.name), err)
			}
			if err := r.load(c, cf, path.Join(p, c.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, ignoring case as FAT does.
func (r *Reader) lookup(name string) (*entryNode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.dir {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byKey[pathpolicy.FoldKey(c)]
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = next
	}
	return n, nil
}

// dirEntry is a directory entry and its file information at once.
type dirEntry struct{ n *entryNode }

func (e dirEntry) Name() string               { return e.n.name }
func (e dirEntry) IsDir() bool                { return e.n.dir }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }

// Mode is what Go reports on Windows for the same attributes.
func (e dirEntry) Mode() fs.FileMode {
	switch {
	case e.n.dir:
		return fs.ModeDir | 0o777
	case e.n.ro:
		return 0o444
	}
	return 0o666
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && !n.dir {
		err = errors.New("not a directory")
	}
	if err != nil {
		return nil, perr("readdir", name, err)
	}
	out := make([]fs.DirEntry, len(n.children))
	for i, c := range n.children {
		out[i] = dirEntry{c}
	}
	return out, nil
}

// Meta reads an object's times and its entry's address.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	return target.Meta{Times: n.times, ID: strconv.FormatInt(n.addr, 10), Links: 1}, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely FAT keeps times.
func (r *Reader) Granularity() target.Granularity {
	return target.Granularity{Atime: 24 * time.Hour, Mtime: 2 * time.Second, Btime: 10 * time.Millisecond}
}

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && n.dir {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, perr("read", name, err)
	}
	f, err := r.vol.OpenEntry(n.e)
	if err != nil {
		return nil, perr("read", name, err)
	}
	data, err := f.ReadAll()
	if err != nil {
		return nil, perr("read", name, err)
	}
	return data, nil
}

// OpenQuiet opens a file for reading.
func (r *Reader) OpenQuiet(name string) (io.ReadCloser, error) {
	data, err := r.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Streams lists an object's named streams: FAT has none.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	if _, err := r.lookup(name); err != nil {
		return nil, perr("list streams", name, err)
	}
	return nil, nil
}

// ReadStream reads a named stream: FAT has none.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

// OpenStreamQuiet opens a named stream: FAT has none.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

var _ target.Reader = (*Reader)(nil)
