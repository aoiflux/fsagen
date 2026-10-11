package ext4

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

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/libext"
)

// Reader reads an ext4 volume from disk through libext, knowing nothing of
// how it was written. It opens the volume strict, so every checksum is
// checked, and a hole, an unwritten run or a short block map in what is
// read, a duplicate name, or a name whose inode is unlinked or deleted is
// an error. lost+found, the file system's own, is left out of the tree.
type Reader struct {
	fs   *libext.FS
	root *entryNode
}

// entryNode is one name and the inode it names.
type entryNode struct {
	name     string
	ino      uint32
	mode     uint16
	uid, gid uint32
	links    uint16
	size     int64
	times    target.Times
	target   string
	children []*entryNode
	byName   map[string]*entryNode
}

func (n *entryNode) isDir() bool { return n.mode&libext.ModeTypeMask == libext.ModeDir }

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	fsys, err := libext.OpenWithOptions(dev, libext.Options{Strict: true})
	if err != nil {
		return nil, fmt.Errorf("ext4: %w", err)
	}
	r := &Reader{fs: fsys}
	in, err := fsys.ReadInode(libext.RootInode)
	if err != nil {
		return nil, fmt.Errorf("ext4: %w", err)
	}
	if r.root, err = r.node(in, ""); err != nil {
		return nil, err
	}
	dirs := map[string]*entryNode{"/": r.root}
	err = fsys.WalkDirWithInode(libext.RootInode, func(p string, e libext.DirEntry, in libext.Inode) error {
		d := dirs[path.Dir(p)]
		if d == nil || d == r.root && e.Name == "lost+found" && e.Inode == lostFound {
			return nil // lost+found, or what is in it
		}
		if _, dup := d.byName[e.Name]; dup {
			return fmt.Errorf("%s: two entries named %q", path.Dir(p), e.Name)
		}
		n, err := r.node(in, e.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		d.byName[e.Name] = n
		d.children = append(d.children, n)
		if n.isDir() {
			dirs[p] = n
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ext4: %w", err)
	}
	for _, d := range dirs {
		slices.SortFunc(d.children, func(a, b *entryNode) int { return strings.Compare(a.name, b.name) })
	}
	return r, nil
}

// node is inode in, named name.
func (r *Reader) node(in libext.Inode, name string) (*entryNode, error) {
	n := &entryNode{
		name: name, ino: in.Number, mode: in.Mode, uid: in.UID, gid: in.GID, links: in.LinksCount, size: int64(in.Size),
		times: target.Times{Atime: unset(in.Atime), Ctime: unset(in.Ctime), Mtime: unset(in.Mtime)},
	}
	if in.HasCrtime {
		n.times.Btime = unset(in.Crtime)
	}
	if n.isDir() {
		n.byName = map[string]*entryNode{}
	}
	if in.IsSymlink {
		f, err := r.fs.Open(in.Number)
		if err != nil {
			return nil, err
		}
		if n.target, err = f.ReadLink(); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// unset is a time as the kernel reads it: libext reports a field whose
// words are both zero as no time, where the kernel reads 1970.
func unset(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t
}

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, without following any link.
func (r *Reader) lookup(name string) (*entryNode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.isDir() {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byName[c]
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
func (e dirEntry) IsDir() bool                { return e.n.isDir() }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }

// Mode is the inode's type and permission bits.
func (e dirEntry) Mode() fs.FileMode {
	perm := fs.FileMode(e.n.mode & 0o777)
	switch e.n.mode & libext.ModeTypeMask {
	case libext.ModeDir:
		return fs.ModeDir | perm
	case libext.ModeSymlink:
		return fs.ModeSymlink | perm
	}
	return perm
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && !n.isDir() {
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

// Meta reads an object's times, inode number, owner and links.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	m := target.Meta{Times: n.times, ID: strconv.FormatUint(uint64(n.ino), 10), UID: int(n.uid), GID: int(n.gid), Links: int(n.links)}
	if n.mode&libext.ModeTypeMask == libext.ModeSymlink {
		m.Link, m.Target = target.LinkSymlink, n.target
	}
	return m, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely ext4 keeps times.
func (r *Reader) Granularity() target.Granularity { return Granularity() }

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && n.mode&libext.ModeTypeMask != libext.ModeRegular {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, perr("read", name, err)
	}
	data, err := r.fs.ReadFile(n.ino)
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

// Streams lists an object's named streams: ext4 has none.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	if _, err := r.lookup(name); err != nil {
		return nil, perr("list streams", name, err)
	}
	return nil, nil
}

// ReadStream reads a named stream: ext4 has none.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

// OpenStreamQuiet opens a named stream: ext4 has none.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

var _ target.Reader = (*Reader)(nil)
