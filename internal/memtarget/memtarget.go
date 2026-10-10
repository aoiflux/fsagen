// Package memtarget is a target held in memory: every name, byte, stream,
// link and time the executor writes, kept exactly as written and read back
// as kept. It does what any target must and nothing a file system adds of
// its own: no time moves unless it is set.
//
// It is how the tests prove the target interfaces carry a whole scenario.
// Run with Windows' capabilities, every shipped example reproduces its
// Windows goldens byte for byte, on any platform. It is also a Finisher, so
// the tests run the order an image takes: settle, finish, verify, digest.
package memtarget

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

	"github.com/aoiflux/fsagen/target"
)

// ErrFinished is returned by a write after Finish.
var ErrFinished = errors.New("the target is finished; nothing more may be written")

// Tick is the resolution Mem keeps times at by default: a Windows FILETIME's.
const Tick = 100 * time.Nanosecond

type kind int

const (
	file kind = iota
	dir
	symlink
	junction
)

// node is one object. A file with hard links is one node under several
// names.
type node struct {
	id       int
	kind     kind
	mode     fs.FileMode
	data     []byte
	streams  map[string][]byte
	times    target.Times
	target   string
	names    int
	children map[string]*node
}

// Mem is a target in memory.
type Mem struct {
	mu       sync.Mutex
	root     *node
	caps     target.Caps
	gran     target.Granularity
	nextID   int
	finished bool
	// Finishes counts the calls to Finish, and WritesAfterFinish the writes
	// refused after it.
	Finishes, WritesAfterFinish int
}

// New is an empty target claiming caps, keeping times to Tick.
func New(caps target.Caps) *Mem {
	m := &Mem{caps: caps, gran: target.Granularity{Atime: Tick, Mtime: Tick, Ctime: Tick, Btime: Tick}}
	m.root = m.newNode(dir, target.DirMode)
	return m
}

// WindowsCaps are what a live NTFS volume on Windows offers with Developer
// Mode on, which is what the Windows goldens were recorded with; no slack,
// which no shipped example asks for.
var WindowsCaps = target.Caps{
	NamedStreams: true, BirthTime: true, ChangeTime: true, Slack: target.SlackNone,
	Hardlinks: true, Symlinks: true, Junctions: true,
}

func (m *Mem) newNode(k kind, mode fs.FileMode) *node {
	m.nextID++
	n := &node{id: m.nextID, kind: k, mode: mode.Perm()}
	if k == dir {
		n.children = map[string]*node{}
	}
	return n
}

// Caps is what the target was made to claim.
func (m *Mem) Caps() target.Caps { return m.caps }

// Granularity is how finely times are kept.
func (m *Mem) Granularity() target.Granularity { return m.gran }

// Finish ends writing. The target reads itself back afterwards.
func (m *Mem) Finish() (target.Reader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Finishes++
	m.finished = true
	return m, nil
}

func pathErr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

func components(name string) []string {
	name = path.Clean(name)
	if name == "." || name == "" {
		return nil
	}
	return strings.Split(name, "/")
}

// lookup finds name without following any link.
func (m *Mem) lookup(name string) (*node, error) {
	n := m.root
	for _, c := range components(name) {
		if n.kind != dir {
			return nil, fs.ErrNotExist
		}
		next, ok := n.children[c]
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = next
	}
	return n, nil
}

// parent finds the directory that holds name, and name's last component.
func (m *Mem) parent(name string) (*node, string, error) {
	cs := components(name)
	if len(cs) == 0 {
		return nil, "", fs.ErrInvalid
	}
	d, err := m.lookup(strings.Join(cs[:len(cs)-1], "/"))
	if err != nil {
		return nil, "", err
	}
	if d.kind != dir {
		return nil, "", fs.ErrNotExist
	}
	return d, cs[len(cs)-1], nil
}

// writable refuses a write after Finish. It is called with the lock held.
func (m *Mem) writable() error {
	if m.finished {
		m.WritesAfterFinish++
		return ErrFinished
	}
	return nil
}

// MkdirAll creates name and any missing parents.
func (m *Mem) MkdirAll(name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr("mkdir", name, err)
	}
	return m.mkdirAll(name, perm)
}

func (m *Mem) mkdirAll(name string, perm fs.FileMode) error {
	n := m.root
	for _, c := range components(name) {
		next, ok := n.children[c]
		if !ok {
			next = m.newNode(dir, perm)
			next.names = 1
			n.children[c] = next
		}
		if next.kind != dir {
			return pathErr("mkdir", name, fs.ErrExist)
		}
		n = next
	}
	return nil
}

// WriteFile creates or truncates name, creating its parents, and writes
// data to it. An existing file keeps its mode.
func (m *Mem) WriteFile(name string, data []byte, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr("write", name, err)
	}
	if d := path.Dir(name); d != "." {
		if err := m.mkdirAll(d, target.DirMode); err != nil {
			return err
		}
	}
	n, err := m.create(name, perm, false)
	if err != nil {
		return err
	}
	n.data = slices.Clone(data)
	return nil
}

// create returns the file at name, making it if it is not there.
func (m *Mem) create(name string, perm fs.FileMode, excl bool) (*node, error) {
	d, leaf, err := m.parent(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	if n, ok := d.children[leaf]; ok {
		if excl {
			return nil, pathErr("open", name, fs.ErrExist)
		}
		if n.kind != file {
			return nil, pathErr("open", name, errors.New("not a regular file"))
		}
		return n, nil
	}
	n := m.newNode(file, perm)
	n.names = 1
	d.children[leaf] = n
	return n, nil
}

// OpenFile opens name with os.OpenFile's flags.
func (m *Mem) OpenFile(name string, flag int, perm fs.FileMode) (target.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	access := flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
	write := access != os.O_RDONLY || flag&(os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
	if write {
		if err := m.writable(); err != nil {
			return nil, pathErr("open", name, err)
		}
	}
	var n *node
	var err error
	if flag&os.O_CREATE != 0 {
		n, err = m.create(name, perm, flag&os.O_EXCL != 0)
	} else if n, err = m.lookup(name); err != nil {
		err = pathErr("open", name, err)
	} else if n.kind != file {
		err = pathErr("open", name, errors.New("not a regular file"))
	}
	if err != nil {
		return nil, err
	}
	if flag&os.O_TRUNC != 0 {
		n.data = nil
	}
	return &handle{m: m, n: n, read: access != os.O_WRONLY, write: access != os.O_RDONLY, append: flag&os.O_APPEND != 0}, nil
}

// handle is an open file.
type handle struct {
	m                   *Mem
	n                   *node
	off                 int
	read, write, append bool
}

func (h *handle) Read(p []byte) (int, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.read {
		return 0, errors.New("not open for reading")
	}
	if h.off >= len(h.n.data) {
		return 0, io.EOF
	}
	n := copy(p, h.n.data[h.off:])
	h.off += n
	return n, nil
}

func (h *handle) Write(p []byte) (int, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.write {
		return 0, errors.New("not open for writing")
	}
	if err := h.m.writable(); err != nil {
		return 0, err
	}
	if h.append {
		h.off = len(h.n.data)
	}
	if end := h.off + len(p); end > len(h.n.data) {
		h.n.data = append(h.n.data, make([]byte, end-len(h.n.data))...)
	}
	copy(h.n.data[h.off:], p)
	h.off += len(p)
	return len(p), nil
}

func (h *handle) Close() error { return nil }

// Remove deletes a file, a link or an empty directory. A file with another
// name keeps it.
func (m *Mem) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr("remove", name, err)
	}
	d, leaf, err := m.parent(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	n, ok := d.children[leaf]
	if !ok {
		return pathErr("remove", name, fs.ErrNotExist)
	}
	if n.kind == dir && len(n.children) > 0 {
		return pathErr("remove", name, errors.New("directory not empty"))
	}
	delete(d.children, leaf)
	n.names--
	return nil
}

// Rename moves a file, a link, or a directory and everything in it. A file
// already at newname is replaced, as Windows' MoveFileEx replaces it.
func (m *Mem) Rename(oldname, newname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr("rename", oldname, err)
	}
	od, oleaf, err := m.parent(oldname)
	if err != nil {
		return pathErr("rename", oldname, err)
	}
	n, ok := od.children[oleaf]
	if !ok {
		return pathErr("rename", oldname, fs.ErrNotExist)
	}
	nd, nleaf, err := m.parent(newname)
	if err != nil {
		return pathErr("rename", newname, err)
	}
	if old, ok := nd.children[nleaf]; ok {
		if old.kind == dir {
			return pathErr("rename", newname, fs.ErrExist)
		}
		old.names--
	}
	delete(od.children, oleaf)
	nd.children[nleaf] = n
	return nil
}

// Chmod changes name's permission bits.
func (m *Mem) Chmod(name string, mode fs.FileMode) error {
	return m.change("chmod", name, func(n *node) error {
		n.mode = mode.Perm()
		return nil
	})
}

// WriteStream creates or replaces a named stream.
func (m *Mem) WriteStream(name, stream string, data []byte) error {
	if !m.caps.NamedStreams {
		return pathErr("write stream", name, errors.ErrUnsupported)
	}
	return m.change("write stream", name, func(n *node) error {
		if n.streams == nil {
			n.streams = map[string][]byte{}
		}
		n.streams[stream] = slices.Clone(data)
		return nil
	})
}

// SetTimes sets name's times; zero times are left alone.
func (m *Mem) SetTimes(name string, t target.Times) error {
	if name == "." || name == "" {
		return errors.New("the output root's own times are not set")
	}
	return m.change("set times", name, func(n *node) error {
		set := func(to *time.Time, from time.Time) {
			if !from.IsZero() {
				*to = from.UTC()
			}
		}
		set(&n.times.Atime, t.Atime)
		set(&n.times.Mtime, t.Mtime)
		set(&n.times.Ctime, t.Ctime)
		set(&n.times.Btime, t.Btime)
		return nil
	})
}

// change applies f to the object at name.
func (m *Mem) change(op, name string, f func(*node) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr(op, name, err)
	}
	n, err := m.lookup(name)
	if err != nil {
		return pathErr(op, name, err)
	}
	return f(n)
}

// Link gives the file oldname a second name.
func (m *Mem) Link(oldname, newname string) error {
	return m.addName("link", newname, func() (*node, error) {
		n, err := m.lookup(oldname)
		if err != nil {
			return nil, err
		}
		if n.kind != file {
			return nil, errors.New("not a regular file")
		}
		return n, nil
	})
}

// Symlink makes name a symlink to target.
func (m *Mem) Symlink(name, to string, _ bool) error {
	return m.addName("symlink", name, func() (*node, error) {
		n := m.newNode(symlink, 0o777)
		n.target = to
		return n, nil
	})
}

// Junction makes name a junction to a directory in the output.
func (m *Mem) Junction(name, to string) error {
	return m.addName("junction", name, func() (*node, error) {
		n := m.newNode(junction, 0o777)
		n.target = to
		return n, nil
	})
}

// addName puts the node made gives at name, creating its parents.
func (m *Mem) addName(op, name string, made func() (*node, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writable(); err != nil {
		return pathErr(op, name, err)
	}
	if d := path.Dir(name); d != "." {
		if err := m.mkdirAll(d, target.DirMode); err != nil {
			return err
		}
	}
	d, leaf, err := m.parent(name)
	if err != nil {
		return pathErr(op, name, err)
	}
	if _, ok := d.children[leaf]; ok {
		return pathErr(op, name, fs.ErrExist)
	}
	n, err := made()
	if err != nil {
		return pathErr(op, name, err)
	}
	n.names++
	d.children[leaf] = n
	return nil
}

// entry is a directory entry and its file information at once.
type entry struct {
	name string
	n    *node
}

func (e entry) Name() string               { return e.name }
func (e entry) IsDir() bool                { return e.n.kind == dir }
func (e entry) Type() fs.FileMode          { return e.Mode().Type() }
func (e entry) Info() (fs.FileInfo, error) { return e, nil }
func (e entry) Size() int64                { return int64(len(e.n.data)) }
func (e entry) ModTime() time.Time         { return e.n.times.Mtime }
func (e entry) Sys() any                   { return nil }

// Mode is the entry's type and permissions. Both kinds of link read as
// symlinks: neither is ever descended into or read through.
func (e entry) Mode() fs.FileMode {
	switch e.n.kind {
	case dir:
		return fs.ModeDir | e.n.mode
	case symlink, junction:
		return fs.ModeSymlink | e.n.mode
	}
	return e.n.mode
}

// ReadDirQuiet lists a directory, sorted by name.
func (m *Mem) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readDir(name)
}

func (m *Mem) readDir(name string) ([]fs.DirEntry, error) {
	d, err := m.lookup(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	if d.kind != dir {
		return nil, pathErr("readdir", name, errors.New("not a directory"))
	}
	names := make([]string, 0, len(d.children))
	for c := range d.children {
		names = append(names, c)
	}
	slices.Sort(names)
	out := make([]fs.DirEntry, len(names))
	for i, c := range names {
		out[i] = entry{c, d.children[c]}
	}
	return out, nil
}

// WalkDir walks the tree in lexical order, the root first, as fs.WalkDir
// does, never descending through a link.
func (m *Mem) WalkDir(fn fs.WalkDirFunc) error {
	err := m.walk(".", entry{".", m.root}, fn)
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}

func (m *Mem) walk(name string, d fs.DirEntry, fn fs.WalkDirFunc) error {
	if err := fn(name, d, nil); err != nil || !d.IsDir() {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			return nil
		}
		return err
	}
	entries, err := m.ReadDirQuiet(name)
	if err != nil {
		return fn(name, d, err)
	}
	for _, e := range entries {
		if err := m.walk(path.Join(name, e.Name()), e, fn); err != nil {
			if errors.Is(err, fs.SkipDir) {
				break
			}
			return err
		}
	}
	return nil
}

// Meta reads an object's times, identity and links.
func (m *Mem) Meta(name string) (target.Meta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := m.lookup(name)
	if err != nil {
		return target.Meta{}, pathErr("read metadata", name, err)
	}
	meta := target.Meta{Times: n.times, ID: strconv.Itoa(n.id), Links: n.names, Target: n.target}
	switch n.kind {
	case symlink:
		meta.Link = target.LinkSymlink
	case junction:
		meta.Link = target.LinkJunction
	}
	return meta, nil
}

// Times reads an object's times.
func (m *Mem) Times(name string) (target.Times, error) {
	meta, err := m.Meta(name)
	return meta.Times, err
}

// ReadFile reads a file whole.
func (m *Mem) ReadFile(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := m.lookup(name)
	if err == nil && n.kind != file {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	return slices.Clone(n.data), nil
}

// OpenQuiet opens a file for reading.
func (m *Mem) OpenQuiet(name string) (io.ReadCloser, error) {
	data, err := m.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Streams lists an object's named streams, sorted by name.
func (m *Mem) Streams(name string) ([]target.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := m.lookup(name)
	if err != nil {
		return nil, pathErr("list streams", name, err)
	}
	out := make([]target.Stream, 0, len(n.streams))
	for s, data := range n.streams {
		out = append(out, target.Stream{Name: s, Size: int64(len(data))})
	}
	slices.SortFunc(out, func(a, b target.Stream) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// ReadStream reads a named stream whole.
func (m *Mem) ReadStream(name, stream string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := m.lookup(name)
	if err != nil {
		return nil, pathErr("read stream", name, err)
	}
	data, ok := n.streams[stream]
	if !ok {
		return nil, pathErr("read stream", fmt.Sprintf("%s:%s", name, stream), fs.ErrNotExist)
	}
	return slices.Clone(data), nil
}

// OpenStreamQuiet opens a named stream for reading.
func (m *Mem) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	data, err := m.ReadStream(name, stream)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

var (
	_ target.Target   = (*Mem)(nil)
	_ target.Linker   = (*Mem)(nil)
	_ target.Finisher = (*Mem)(nil)
)
