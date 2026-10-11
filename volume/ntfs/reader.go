package ntfs

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
	"github.com/aoiflux/libntfs"
)

// Reader reads an NTFS volume from disk through libntfs, knowing nothing of
// how it was written. It opens the volume strict, so a torn record or index
// block, an index out of collation order or out of step with its $BITMAP,
// an entry naming a record not in use, of another sequence number or with
// no $FILE_NAME for it, a directory flag out of step, or a $DATA whose runs
// do not cover it are errors, not a tolerant reading; and $Reparse's $R
// has to file exactly the volume's reparse points. The system files at the
// root are left out of the tree.
type Reader struct {
	vol  *libntfs.Volume
	root *rnode
}

// rnode is one name and the record it names.
type rnode struct {
	name  string
	num   uint64
	f     *libntfs.File
	dir   bool
	attrs uint32
	links int
	times target.Times
	// fn are the times of the name's $FILE_NAME in the record.
	fn   target.Times
	size int64
	// streams are the named $DATA attributes, sorted by name.
	streams []target.Stream
	// link is target.LinkSymlink or target.LinkJunction for a reparse
	// point of either kind, and target what it points at.
	link, target string
	children     []*rnode
	byName       map[string]*rnode
}

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	vol, err := libntfs.OpenWithOptions(dev, libntfs.Options{ReadOnly: true, Strict: true})
	if err != nil {
		return nil, fmt.Errorf("ntfs: %w", err)
	}
	r := &Reader{vol: vol}
	root, err := r.node(libntfs.MFTEntryRoot, ".", libntfs.MFTEntryRoot)
	if err != nil {
		return nil, err
	}
	r.root = root
	if err := r.load(root, "."); err != nil {
		return nil, err
	}
	if err := vol.VerifyReparseIndex(); err != nil {
		return nil, fmt.Errorf("ntfs: $Reparse: %w", err)
	}
	return r, nil
}

// when is a time as NTFS stores it: libntfs reads 0 as no time, and NTFS
// as 1601.
func when(t time.Time) time.Time {
	if t.IsZero() {
		return MinTime
	}
	return t
}

// node reads record num, named name in directory record parent.
func (r *Reader) node(num uint64, name string, parent uint64) (*rnode, error) {
	e, err := r.vol.GetMFTEntry(num)
	if err != nil {
		return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
	}
	f, err := r.vol.Open(num)
	if err != nil {
		return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
	}
	si, err := e.GetStandardInformation()
	if err != nil {
		return nil, fmt.Errorf("ntfs: record %d has no $STANDARD_INFORMATION: %w", num, err)
	}
	n := &rnode{
		name: name, num: num, f: f, dir: e.IsDirectory(), attrs: si.FileAttributes, links: int(e.HardLinkCount),
		times: target.Times{Btime: when(si.CreateTime), Mtime: when(si.ModifyTime), Ctime: when(si.MFTChangeTime), Atime: when(si.AccessTime)},
	}
	fns, err := e.FileNames()
	if err != nil {
		return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
	}
	i := slices.IndexFunc(fns, func(fn *libntfs.FileName) bool { return fn.ParentDirectory == parent && collate(fn.Name, name) == 0 })
	if i < 0 {
		return nil, fmt.Errorf("ntfs: record %d has no $FILE_NAME for %q", num, name)
	}
	fn := fns[i]
	n.fn = target.Times{Btime: when(fn.CreateTime), Mtime: when(fn.ModifyTime), Ctime: when(fn.MFTChangeTime), Atime: when(fn.AccessTime)}
	for _, s := range f.Streams() {
		if s.Name != "" {
			n.streams = append(n.streams, target.Stream{Name: s.Name, Size: int64(s.Size)})
		}
	}
	slices.SortFunc(n.streams, func(a, b target.Stream) int { return strings.Compare(a.Name, b.Name) })
	if e.FindAttribute(libntfs.AttrTypeReparsePoint, "") != nil {
		if n.attrs&libntfs.FileAttrReparsePoint == 0 {
			return nil, fmt.Errorf("ntfs: record %d has a reparse point, and its flags say it has none", num)
		}
		rp, err := f.ReparsePoint()
		if err != nil {
			return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
		}
		if err := n.readLink(rp); err != nil {
			return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
		}
	}
	if n.dir {
		return n, nil
	}
	if e.FindAttribute(libntfs.AttrTypeData, "") == nil {
		return nil, fmt.Errorf("ntfs: file record %d has no $DATA", num)
	}
	n.size = f.Size()
	return n, nil
}

// readLink reads a symlink's or junction's reparse point: a symlink's
// print name as stored, with '/' between names, and a junction's as a
// path on the volume when it is on junctionDrive.
func (n *rnode) readLink(rp *libntfs.ReparsePoint) error {
	_, t, ok := rp.Target()
	switch {
	case ok && rp.ReparseType == libntfs.ReparsePointSymlink:
		n.link, n.target = target.LinkSymlink, strings.ReplaceAll(t, `\`, "/")
	case ok && rp.ReparseType == libntfs.ReparsePointMountPoint:
		n.link, n.target = target.LinkJunction, t
		if rel, ok := strings.CutPrefix(t, junctionDrive+`\`); ok {
			n.target = strings.ReplaceAll(rel, `\`, "/")
			if n.target == "" {
				n.target = "."
			}
		}
	default:
		return fmt.Errorf("a reparse point of tag %#x, neither a symlink nor a junction", rp.ReparseType)
	}
	return nil
}

// load reads directory d, named p, and every directory under it. Names
// in the DOS namespace alone are left out, as are the system files at the
// root.
func (r *Reader) load(d *rnode, p string) error {
	es, err := d.f.ReadDir()
	if err != nil {
		return fmt.Errorf("ntfs: %s: %w", p, err)
	}
	d.byName = map[string]*rnode{}
	for _, e := range es {
		if e.Deleted || e.Namespace == libntfs.NamespaceDOS || d == r.root && e.EntryNum < 16 {
			continue
		}
		n, err := r.node(e.EntryNum, e.Name, d.num)
		if err != nil {
			return fmt.Errorf("%s: %w", path.Join(p, e.Name), err)
		}
		d.byName[n.name] = n
		d.children = append(d.children, n)
	}
	slices.SortFunc(d.children, func(a, b *rnode) int { return strings.Compare(a.name, b.name) })
	for _, c := range d.children {
		if c.dir && c.link == "" {
			if err := r.load(c, path.Join(p, c.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, as written or differing only in case.
func (r *Reader) lookup(name string) (*rnode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.dir || n.link != "" {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byName[c]
		if !ok {
			for k, v := range n.byName {
				if collate(k, c) == 0 {
					next, ok = v, true
				}
			}
		}
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = next
	}
	return n, nil
}

// dirEntry is a directory entry and its file information at once.
type dirEntry struct{ n *rnode }

func (e dirEntry) Name() string               { return e.n.name }
func (e dirEntry) IsDir() bool                { return e.n.dir && e.n.link == "" }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }
func (e dirEntry) Mode() fs.FileMode {
	if e.n.link != "" {
		return fs.ModeSymlink | 0o777
	}
	return mode(e.n.dir, e.n.attrs)
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && (!n.dir || n.link != "") {
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

// Meta reads an object's times, record number, links, and the times of
// the name's $FILE_NAME.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	fn := n.fn
	return target.Meta{Times: n.times, ID: strconv.FormatUint(n.num, 10), Links: n.links, FileName: &fn, Link: n.link, Target: n.target}, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely NTFS keeps times.
func (r *Reader) Granularity() target.Granularity { return Granularity() }

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && (n.dir || n.link != "") {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, perr("read", name, err)
	}
	data, err := n.f.ReadAll()
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

// Streams lists an object's named streams, sorted by name. A link has
// none of its own.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	n, err := r.lookup(name)
	if err != nil {
		return nil, perr("list streams", name, err)
	}
	if n.link != "" {
		return nil, nil
	}
	return slices.Clone(n.streams), nil
}

// ReadStream reads a named stream whole.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	n, err := r.lookup(name)
	if err != nil {
		return nil, perr("read stream", name+":"+stream, err)
	}
	if n.link != "" || !slices.ContainsFunc(n.streams, func(s target.Stream) bool { return s.Name == stream }) {
		return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
	}
	s, err := n.f.OpenStream(stream)
	if err != nil {
		return nil, perr("read stream", name+":"+stream, err)
	}
	data, err := s.ReadAll()
	if err != nil {
		return nil, perr("read stream", name+":"+stream, err)
	}
	return data, nil
}

// OpenStreamQuiet opens a named stream for reading.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	data, err := r.ReadStream(name, stream)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

var _ target.Reader = (*Reader)(nil)
