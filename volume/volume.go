package volume

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/target"
)

// ErrFinished is returned by a write after Finish.
var ErrFinished = errors.New("the image is finished; nothing more may be written")

// Kind is what a node is.
type Kind int

// The kinds of node.
const (
	File Kind = iota
	Dir
	Symlink
	Junction
)

// Node is one object of the tree as the scenario sees it. A file with hard
// links is one node under several names.
type Node struct {
	ID     int
	Kind   Kind
	Mode   fs.FileMode
	Data   []byte
	Times  target.Times
	Target string
	// Names is how many names the node has.
	Names int
	// Sys is the driver's own record of the node: where it is on disk.
	Sys      any
	children map[string]*child
}

// child is a name in a directory: as written, and the node it names.
type child struct {
	name string
	n    *Node
}

// Driver lays a tree out on disk the way one file system does. The Volume
// calls it after every change to the tree, with the tree already changed,
// and never with a change the driver's Caps do not claim. Every name it is
// given was accepted by its Caps' ValidName.
type Driver interface {
	Caps() target.Caps
	// Granularity is how finely the file system stores each time.
	Granularity() target.Granularity
	// Root is the record of the root directory.
	Root() any
	// Create gives the new node n the name in parent. A directory starts
	// empty and a file with no content.
	Create(parent *Node, name string, n *Node) error
	// Commit stores n's content, now n.Data. truncated says the content was
	// cut to nothing before it was written, as opening with O_TRUNC does,
	// rather than changed in place.
	Commit(n *Node, truncated bool) error
	// Remove takes name out of parent. n.Names is what n has left; at 0 the
	// node is gone.
	Remove(parent *Node, name string, n *Node) error
	// Rename moves n from oldName in from to newName in to. Anything that
	// was at newName has already been removed.
	Rename(from *Node, oldName string, to *Node, newName string, n *Node) error
	// SetTimes stores t's non-zero times on n.
	SetTimes(n *Node, t target.Times) error
	// Chmod stores n.Mode.
	Chmod(n *Node) error
	// WriteSlack writes data just past byte at of n's content, in its last
	// cluster.
	WriteSlack(n *Node, at int64, data []byte) error
	// Flush writes every structure not yet on disk. Nothing is changed
	// after it.
	Flush() error
	// Open reads the finished file system back from disk.
	Open() (target.Reader, error)
}

// Volume is a target built on a Driver.
type Volume struct {
	mu       sync.Mutex
	d        Driver
	caps     target.Caps
	fold     bool
	root     *Node
	nextID   int
	op       int
	res      *Tracker
	image    io.ReaderAt
	finished bool
	residue  []target.Residue
}

// New is an empty volume laid out by d. res is what d records residue in,
// and image reads the whole image file once it is finished.
func New(d Driver, res *Tracker, image io.ReaderAt) *Volume {
	v := &Volume{d: d, caps: d.Caps(), res: res, image: image}
	v.fold = v.caps.FoldsCase
	v.root = v.newNode(Dir, target.DirMode)
	v.root.Sys = d.Root()
	return v
}

func (v *Volume) newNode(k Kind, mode fs.FileMode) *Node {
	v.nextID++
	n := &Node{ID: v.nextID, Kind: k, Mode: mode.Perm()}
	if k == Dir {
		n.children = map[string]*child{}
	}
	return n
}

// key is the name a directory files leaf under.
func (v *Volume) key(leaf string) string {
	if v.fold {
		return pathpolicy.FoldKey(leaf)
	}
	return leaf
}

// Caps is what the file system can do.
func (v *Volume) Caps() target.Caps { return v.caps }

// Granularity is how finely the file system stores each time.
func (v *Volume) Granularity() target.Granularity { return v.d.Granularity() }

// BeginOp names the operation the following writes belong to.
func (v *Volume) BeginOp(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.op = n
}

// Finish writes what is not yet on disk, works out what residue survived,
// and returns the file system as read back from the image.
func (v *Volume) Finish() (target.Reader, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.finished {
		return nil, ErrFinished
	}
	v.finished = true
	if err := v.d.Flush(); err != nil {
		return nil, err
	}
	res, err := v.res.Resolve(v.image)
	if err != nil {
		return nil, fmt.Errorf("residue: %w", err)
	}
	v.residue = res
	return v.d.Open()
}

// Residue is what the run left on disk beyond the tree, once finished.
func (v *Volume) Residue() []target.Residue { return v.residue }

func pathErr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

func components(name string) []string {
	name = path.Clean(name)
	if name == "." || name == "" {
		return nil
	}
	return strings.Split(name, "/")
}

// lookup finds name without following any link.
func (v *Volume) lookup(name string) (*Node, error) {
	n := v.root
	for _, c := range components(name) {
		if n.Kind != Dir {
			return nil, fs.ErrNotExist
		}
		ch, ok := n.children[v.key(c)]
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = ch.n
	}
	return n, nil
}

// parent finds the directory that holds name, and name's last component.
func (v *Volume) parent(name string) (*Node, string, error) {
	cs := components(name)
	if len(cs) == 0 {
		return nil, "", fs.ErrInvalid
	}
	d, err := v.lookup(strings.Join(cs[:len(cs)-1], "/"))
	if err != nil {
		return nil, "", err
	}
	if d.Kind != Dir {
		return nil, "", fs.ErrNotExist
	}
	return d, cs[len(cs)-1], nil
}

// writable refuses a write after Finish and names the residue's source.
// It is called with the lock held.
func (v *Volume) writable(name string) error {
	if v.finished {
		return ErrFinished
	}
	v.res.Begin(v.op, name)
	return nil
}

// MkdirAll creates name and any missing parents.
func (v *Volume) MkdirAll(name string, perm fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.writable(name); err != nil {
		return pathErr("mkdir", name, err)
	}
	return v.mkdirAll(name, perm)
}

func (v *Volume) mkdirAll(name string, perm fs.FileMode) error {
	n := v.root
	for _, c := range components(name) {
		ch, ok := n.children[v.key(c)]
		if !ok {
			d := v.newNode(Dir, perm)
			if err := v.add(n, c, d); err != nil {
				return pathErr("mkdir", name, err)
			}
			ch = n.children[v.key(c)]
		}
		if ch.n.Kind != Dir {
			return pathErr("mkdir", name, fs.ErrExist)
		}
		n = ch.n
	}
	return nil
}

// add gives the new node n the name leaf in d.
func (v *Volume) add(d *Node, leaf string, n *Node) error {
	if err := v.d.Create(d, leaf, n); err != nil {
		return err
	}
	n.Names++
	d.children[v.key(leaf)] = &child{leaf, n}
	return nil
}

// WriteFile creates or truncates name, creating its parents, and writes
// data to it. An existing file keeps its mode.
func (v *Volume) WriteFile(name string, data []byte, perm fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.writable(name); err != nil {
		return pathErr("write", name, err)
	}
	if d := path.Dir(name); d != "." {
		if err := v.mkdirAll(d, target.DirMode); err != nil {
			return err
		}
	}
	n, err := v.create(name, perm, false)
	if err != nil {
		return err
	}
	n.Data = slices.Clone(data)
	return v.commit(name, n, true)
}

func (v *Volume) commit(name string, n *Node, truncated bool) error {
	if err := v.d.Commit(n, truncated); err != nil {
		return pathErr("write", name, err)
	}
	return nil
}

// create returns the file at name, making it if it is not there.
func (v *Volume) create(name string, perm fs.FileMode, excl bool) (*Node, error) {
	d, leaf, err := v.parent(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	if ch, ok := d.children[v.key(leaf)]; ok {
		if excl {
			return nil, pathErr("open", name, fs.ErrExist)
		}
		if ch.n.Kind != File {
			return nil, pathErr("open", name, errors.New("not a regular file"))
		}
		return ch.n, nil
	}
	n := v.newNode(File, perm)
	if err := v.add(d, leaf, n); err != nil {
		return nil, pathErr("open", name, err)
	}
	return n, nil
}

// OpenFile opens name with os.OpenFile's flags. What is written reaches
// the disk when the file is closed.
func (v *Volume) OpenFile(name string, flag int, perm fs.FileMode) (target.File, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	access := flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
	write := access != os.O_RDONLY || flag&(os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
	if write {
		if err := v.writable(name); err != nil {
			return nil, pathErr("open", name, err)
		}
	}
	var n *Node
	var err error
	if flag&os.O_CREATE != 0 {
		n, err = v.create(name, perm, flag&os.O_EXCL != 0)
	} else if n, err = v.lookup(name); err != nil {
		err = pathErr("open", name, err)
	} else if n.Kind != File {
		err = pathErr("open", name, errors.New("not a regular file"))
	}
	if err != nil {
		return nil, err
	}
	h := &handle{v: v, n: n, name: name, read: access != os.O_WRONLY, write: access != os.O_RDONLY, append: flag&os.O_APPEND != 0}
	if flag&os.O_TRUNC != 0 {
		n.Data, h.truncated, h.dirty = nil, true, true
	}
	return h, nil
}

// handle is an open file.
type handle struct {
	v                   *Volume
	n                   *Node
	name                string
	off                 int
	read, write, append bool
	truncated, dirty    bool
	closed              bool
}

func (h *handle) Read(p []byte) (int, error) {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	if !h.read {
		return 0, errors.New("not open for reading")
	}
	if h.off >= len(h.n.Data) {
		return 0, io.EOF
	}
	n := copy(p, h.n.Data[h.off:])
	h.off += n
	return n, nil
}

func (h *handle) Write(p []byte) (int, error) {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	if !h.write {
		return 0, errors.New("not open for writing")
	}
	if h.v.finished {
		return 0, ErrFinished
	}
	if h.append {
		h.off = len(h.n.Data)
	}
	if end := h.off + len(p); end > len(h.n.Data) {
		h.n.Data = append(h.n.Data, make([]byte, end-len(h.n.Data))...)
	}
	copy(h.n.Data[h.off:], p)
	h.off += len(p)
	h.dirty = true
	return len(p), nil
}

// Close puts what was written on disk.
func (h *handle) Close() error {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	if h.closed || !h.dirty {
		h.closed = true
		return nil
	}
	h.closed = true
	if err := h.v.writable(h.name); err != nil {
		return pathErr("close", h.name, err)
	}
	return h.v.commit(h.name, h.n, h.truncated)
}

// Remove deletes a file, a link or an empty directory. A file with another
// name keeps it.
func (v *Volume) Remove(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.writable(name); err != nil {
		return pathErr("remove", name, err)
	}
	d, leaf, err := v.parent(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	ch, ok := d.children[v.key(leaf)]
	if !ok {
		return pathErr("remove", name, fs.ErrNotExist)
	}
	if ch.n.Kind == Dir && len(ch.n.children) > 0 {
		return pathErr("remove", name, errors.New("directory not empty"))
	}
	return v.unlink(d, ch, name)
}

func (v *Volume) unlink(d *Node, ch *child, name string) error {
	delete(d.children, v.key(ch.name))
	ch.n.Names--
	if err := v.d.Remove(d, ch.name, ch.n); err != nil {
		return pathErr("remove", name, err)
	}
	return nil
}

// Rename moves a file, a link, or a directory and everything in it. A file
// already at newname is replaced, as Windows' MoveFileEx replaces it.
func (v *Volume) Rename(oldname, newname string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.writable(oldname); err != nil {
		return pathErr("rename", oldname, err)
	}
	od, oleaf, err := v.parent(oldname)
	if err != nil {
		return pathErr("rename", oldname, err)
	}
	ch, ok := od.children[v.key(oleaf)]
	if !ok {
		return pathErr("rename", oldname, fs.ErrNotExist)
	}
	nd, nleaf, err := v.parent(newname)
	if err != nil {
		return pathErr("rename", newname, err)
	}
	if old, ok := nd.children[v.key(nleaf)]; ok && old.n != ch.n {
		if old.n.Kind == Dir {
			return pathErr("rename", newname, fs.ErrExist)
		}
		v.res.Begin(v.op, newname)
		if err := v.unlink(nd, old, newname); err != nil {
			return err
		}
		v.res.Begin(v.op, oldname)
	}
	delete(od.children, v.key(oleaf))
	nd.children[v.key(nleaf)] = &child{nleaf, ch.n}
	if err := v.d.Rename(od, ch.name, nd, nleaf, ch.n); err != nil {
		return pathErr("rename", oldname, err)
	}
	return nil
}

// Chmod changes name's permission bits.
func (v *Volume) Chmod(name string, mode fs.FileMode) error {
	return v.change("chmod", name, func(n *Node) error {
		n.Mode = mode.Perm()
		return v.d.Chmod(n)
	})
}

// WriteStream creates or replaces a named stream.
func (v *Volume) WriteStream(name, stream string, data []byte) error {
	return pathErr("write stream", name, errors.ErrUnsupported)
}

// SetTimes sets name's times; zero times are left alone.
func (v *Volume) SetTimes(name string, t target.Times) error {
	if name == "." || name == "" {
		return errors.New("the output root's own times are not set")
	}
	return v.change("set times", name, func(n *Node) error {
		set := func(to *time.Time, from time.Time) {
			if !from.IsZero() {
				*to = from.UTC()
			}
		}
		set(&n.Times.Atime, t.Atime)
		set(&n.Times.Mtime, t.Mtime)
		set(&n.Times.Ctime, t.Ctime)
		set(&n.Times.Btime, t.Btime)
		return v.d.SetTimes(n, t)
	})
}

// WriteSlack writes data just past byte at of name, where its content ends.
func (v *Volume) WriteSlack(name string, at int64, data []byte) error {
	return v.change("write slack", name, func(n *Node) error {
		if n.Kind != File || int64(len(n.Data)) != at {
			return fmt.Errorf("slack must start where the content ends (%d bytes), not at %d", len(n.Data), at)
		}
		return v.d.WriteSlack(n, at, data)
	})
}

// change applies f to the object at name.
func (v *Volume) change(op, name string, f func(*Node) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.writable(name); err != nil {
		return pathErr(op, name, err)
	}
	n, err := v.lookup(name)
	if err != nil {
		return pathErr(op, name, err)
	}
	if err := f(n); err != nil {
		return pathErr(op, name, err)
	}
	return nil
}

// Link, Symlink and Junction are refused: no driver makes links yet, and
// pre-flight never asks one whose Caps do not claim them.
func (v *Volume) Link(oldname, newname string) error {
	return pathErr("link", newname, errors.ErrUnsupported)
}

// Symlink is refused; see Link.
func (v *Volume) Symlink(name, to string, _ bool) error {
	return pathErr("symlink", name, errors.ErrUnsupported)
}

// Junction is refused; see Link.
func (v *Volume) Junction(name, to string) error {
	return pathErr("junction", name, errors.ErrUnsupported)
}

// entry is a directory entry and its file information at once.
type entry struct {
	name string
	n    *Node
}

func (e entry) Name() string               { return e.name }
func (e entry) IsDir() bool                { return e.n.Kind == Dir }
func (e entry) Type() fs.FileMode          { return e.Mode().Type() }
func (e entry) Info() (fs.FileInfo, error) { return e, nil }
func (e entry) Size() int64                { return int64(len(e.n.Data)) }
func (e entry) ModTime() time.Time         { return e.n.Times.Mtime }
func (e entry) Sys() any                   { return nil }

// Mode is the entry's type and permissions; both kinds of link read as
// symlinks.
func (e entry) Mode() fs.FileMode {
	switch e.n.Kind {
	case Dir:
		return fs.ModeDir | e.n.Mode
	case Symlink, Junction:
		return fs.ModeSymlink | e.n.Mode
	}
	return e.n.Mode
}

// ReadDirQuiet lists a directory, sorted by name.
func (v *Volume) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, err := v.lookup(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	if d.Kind != Dir {
		return nil, pathErr("readdir", name, errors.New("not a directory"))
	}
	out := make([]fs.DirEntry, 0, len(d.children))
	for _, ch := range d.children {
		out = append(out, entry{ch.name, ch.n})
	}
	slices.SortFunc(out, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

// WalkDir walks the tree in lexical order, the root first, never
// descending through a link.
func (v *Volume) WalkDir(fn fs.WalkDirFunc) error { return Walk(v, fn) }

// Walk walks r in lexical order, the root first, as fs.WalkDir does, never
// descending through a link.
func Walk(r target.Reader, fn fs.WalkDirFunc) error {
	err := walk(r, ".", root{}, fn)
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}

// root is the walk's entry for the root directory.
type root struct{}

func (root) Name() string               { return "." }
func (root) IsDir() bool                { return true }
func (root) Type() fs.FileMode          { return fs.ModeDir }
func (root) Info() (fs.FileInfo, error) { return nil, errors.New("the root has no entry") }

func walk(r target.Reader, name string, d fs.DirEntry, fn fs.WalkDirFunc) error {
	if err := fn(name, d, nil); err != nil || !d.IsDir() {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			return nil
		}
		return err
	}
	entries, err := r.ReadDirQuiet(name)
	if err != nil {
		return fn(name, d, err)
	}
	for _, e := range entries {
		if err := walk(r, path.Join(name, e.Name()), e, fn); err != nil {
			if errors.Is(err, fs.SkipDir) {
				break
			}
			return err
		}
	}
	return nil
}

// Meta reads an object's times, identity and links as the scenario left
// them; the finished image's reader reports what is on disk.
func (v *Volume) Meta(name string) (target.Meta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.lookup(name)
	if err != nil {
		return target.Meta{}, pathErr("read metadata", name, err)
	}
	meta := target.Meta{Times: n.Times, ID: strconv.Itoa(n.ID), Links: n.Names, Target: n.Target}
	switch n.Kind {
	case Symlink:
		meta.Link = target.LinkSymlink
	case Junction:
		meta.Link = target.LinkJunction
	}
	return meta, nil
}

// Node is the object at name, for a driver's tests.
func (v *Volume) Node(name string) (*Node, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lookup(name)
}

// Times reads an object's times.
func (v *Volume) Times(name string) (target.Times, error) {
	meta, err := v.Meta(name)
	return meta.Times, err
}

// ReadFile reads a file whole.
func (v *Volume) ReadFile(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.lookup(name)
	if err == nil && n.Kind != File {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	return slices.Clone(n.Data), nil
}

// OpenQuiet opens a file for reading.
func (v *Volume) OpenQuiet(name string) (io.ReadCloser, error) {
	data, err := v.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Streams lists an object's named streams: none yet.
func (v *Volume) Streams(name string) ([]target.Stream, error) {
	if _, err := v.Meta(name); err != nil {
		return nil, err
	}
	return nil, nil
}

// ReadStream reads a named stream; there are none yet.
func (v *Volume) ReadStream(name, stream string) ([]byte, error) {
	return nil, pathErr("read stream", name+":"+stream, fs.ErrNotExist)
}

// OpenStreamQuiet opens a named stream; there are none yet.
func (v *Volume) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	return nil, pathErr("read stream", name+":"+stream, fs.ErrNotExist)
}

var (
	_ target.Target     = (*Volume)(nil)
	_ target.Linker     = (*Volume)(nil)
	_ target.Slacker    = (*Volume)(nil)
	_ target.Finisher   = (*Volume)(nil)
	_ target.OpObserver = (*Volume)(nil)
	_ target.Forensic   = (*Volume)(nil)
)
