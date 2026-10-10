// Package model is an in-memory picture of the output tree that compile-time
// validation runs the scenario against before anything touches the disk. It
// is how "delete of a file that never existed", "update of a missing file",
// "a stream on a missing base" and "ref to a deleted file" become errors that
// name the operation, instead of silent no-ops or half-built corpora.
//
// Objects have an identity that survives renames, so an id given when a file
// is created still names it after it has been moved. An object has one or
// more names: a hard-linked file has several, each a path to the same bytes
// and times, and goes only when the last of them does.
//
// Each object also carries the four times the scenario intends it to have.
// The tree's Clock is the time of the operation being simulated; creating an
// object stamps all four with it, and adding, removing or renaming an entry
// stamps the parent directory's modification and change times. The caller
// applies the per-action rules (what an update or a copy does to a file's
// own times) on top. A zero time means the scenario does not control it.
//
// Beside those, each name carries the times NTFS keeps in its $FILE_NAME
// attribute, which Windows sets itself: all four at the clock when the name
// is made, copied from the object's own times when it is renamed. Nothing
// else moves them, which is why a timestomp that sets only the first set
// gives itself away.
package model

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

// Times are an object's intended access, modification, change and birth
// times. A zero time is not controlled by the scenario.
type Times struct {
	Atime, Mtime, Ctime, Btime time.Time
}

// All returns Times with every field set to t.
func All(t time.Time) Times { return Times{t, t, t, t} }

// Kind distinguishes files, directories and links.
type Kind uint8

const (
	File Kind = iota + 1
	Dir
	// Symlink and Junction are links: an entry whose content is a path to
	// something else, which fsagen writes and never follows.
	Symlink
	Junction
)

// IsLink reports whether k is a symlink or a junction.
func (k Kind) IsLink() bool { return k == Symlink || k == Junction }

// Object is one file, directory or link.
type Object struct {
	Serial int
	Kind   Kind
	// Path is the object's first live name, or for a removed object the
	// name it had when it went.
	Path string
	// Names are the object's live names, in the order they were made.
	Names   []*Name
	Streams map[string]bool
	Times   Times
	// Mode is the permission set fsagen gives the object; zero means its
	// default for the kind (the caller knows what that is).
	Mode fs.FileMode
	// Target is what a symlink or junction points at, as written.
	Target  string
	removed bool
}

// Name is one name of an object: where it is, and the times of the
// $FILE_NAME attribute that holds it.
type Name struct {
	Path    string
	Obj     *Object
	FN      Times
	removed bool
}

// Tree is the simulated namespace. The root itself is implicit.
type Tree struct {
	// Fold, when set, maps a path to the key a case-insensitive file system
	// stores it under; two different paths with the same key are refused.
	Fold func(string) string

	// Clock is the time of the operation being simulated, or zero when it
	// has none. New objects and directory events are stamped with it.
	Clock time.Time

	byPath  map[string]*Name
	byFold  map[string]string
	ids     map[string][]*Name
	serial  int
	removed []*Object
}

// New returns an empty tree.
func New() *Tree {
	return &Tree{byPath: map[string]*Name{}, byFold: map[string]string{}, ids: map[string][]*Name{}}
}

// collides reports an existing different path that p would collide with.
func (t *Tree) collides(p string) error {
	if t.Fold == nil {
		return nil
	}
	if other, ok := t.byFold[t.Fold(p)]; ok && other != p {
		return fmt.Errorf("%s collides with %s on case-insensitive file systems (NTFS, APFS); rename one, or pass --allow-nonportable for a Linux-only scenario", p, other)
	}
	return nil
}

func (t *Tree) index(p string) {
	if t.Fold != nil {
		t.byFold[t.Fold(p)] = p
	}
}

func (t *Tree) unindex(p string) {
	if t.Fold != nil {
		if t.byFold[t.Fold(p)] == p {
			delete(t.byFold, t.Fold(p))
		}
	}
}

// Errors returned by tree operations. Callers wrap them with the operation.
var (
	ErrNotExist = errors.New("does not exist")
	ErrExist    = errors.New("already exists")
)

// Get returns the object at p, or nil.
func (t *Tree) Get(p string) *Object {
	if n := t.byPath[p]; n != nil {
		return n.Obj
	}
	return nil
}

// Name returns the name at p, or nil.
func (t *Tree) Name(p string) *Name { return t.byPath[p] }

// SetFold turns on collision checking with the given key function and indexes
// everything already in the tree.
func (t *Tree) SetFold(f func(string) string) {
	t.Fold = f
	t.byFold = map[string]string{}
	for p := range t.byPath {
		t.index(p)
	}
}

// Add records an object found on disk (used to seed --into-existing), and
// for a link what it points at. Its times are not controlled until an
// operation touches it.
func (t *Tree) Add(p string, k Kind, target string) {
	if _, ok := t.byPath[p]; ok {
		return
	}
	t.insert(p, k).Target = target
}

// AddName records a further name found on disk for the object at p: a file
// hard-linked to it.
func (t *Tree) AddName(p, other string) {
	if o := t.Get(p); o != nil && t.byPath[other] == nil {
		t.addName(o, other)
	}
}

func (t *Tree) insert(p string, k Kind) *Object {
	t.serial++
	o := &Object{Serial: t.serial, Kind: k, Path: p, Streams: map[string]bool{}}
	t.addName(o, p)
	return o
}

func (t *Tree) addName(o *Object, p string) *Name {
	n := &Name{Path: p, Obj: o}
	o.Names = append(o.Names, n)
	t.byPath[p] = n
	t.index(p)
	return n
}

// add creates a new object at p, refusing a case-insensitive collision. It
// is born at the clock, and its parent directory changes.
func (t *Tree) add(p string, k Kind) (*Object, error) {
	if err := t.collides(p); err != nil {
		return nil, err
	}
	o := t.insert(p, k)
	o.Times = All(t.Clock)
	o.Names[0].FN = o.Times
	t.touchDir(path.Dir(p))
	return o, nil
}

// touchDir records an entry added to, removed from or renamed within dir:
// its modification and change times move to the clock. The root is not
// modelled; its times belong to whoever made it.
func (t *Tree) touchDir(dir string) {
	if o := t.Get(dir); o != nil && o.Kind == Dir {
		o.Times.Mtime, o.Times.Ctime = t.Clock, t.Clock
	}
}

// MkdirAll creates p and any missing parents as directories.
func (t *Tree) MkdirAll(p string) error {
	if p == "." || p == "" {
		return nil
	}
	if o := t.Get(p); o != nil {
		switch o.Kind {
		case Dir:
			return nil
		case Symlink, Junction:
			return fmt.Errorf("%s is a link; fsagen never follows one, so nothing can be made through it", p)
		}
		return fmt.Errorf("%s is a file, not a directory", p)
	}
	if err := t.MkdirAll(path.Dir(p)); err != nil {
		return err
	}
	_, err := t.add(p, Dir)
	return err
}

// CreateFile creates the file at p, creating parent directories, and leaves a
// file already there in place: the operation that calls this is about to write
// over it, and the model only tracks that the path is a file.
func (t *Tree) CreateFile(p string) error {
	if err := t.MkdirAll(path.Dir(p)); err != nil {
		return err
	}
	if o := t.Get(p); o != nil {
		switch o.Kind {
		case Dir:
			return fmt.Errorf("%s is a directory", p)
		case Symlink, Junction:
			return fmt.Errorf("%s is a link; writing to it would write through it, and fsagen never follows one", p)
		}
		return nil
	}
	_, err := t.add(p, File)
	return err
}

// CreateLink creates a symlink or junction at p pointing at target, which
// is recorded as written and never resolved here. p must not exist.
func (t *Tree) CreateLink(p string, k Kind, target string) error {
	if t.byPath[p] != nil {
		return fmt.Errorf("%s %w", p, ErrExist)
	}
	if err := t.MkdirAll(path.Dir(p)); err != nil {
		return err
	}
	o, err := t.add(p, k)
	if err != nil {
		return err
	}
	o.Target = target
	return nil
}

// Link gives the file at oldp a further name, newp, which must not exist:
// a hard link. The file's metadata changes (it has one more link), and the
// new name is written with the times the file has by then.
func (t *Tree) Link(oldp, newp string) error {
	o := t.Get(oldp)
	switch {
	case o == nil:
		return fmt.Errorf("%s %w", oldp, ErrNotExist)
	case o.Kind != File:
		return fmt.Errorf("%s is not a file; only a file can be hard-linked", oldp)
	case t.byPath[newp] != nil:
		return fmt.Errorf("%s %w", newp, ErrExist)
	}
	if err := t.collides(newp); err != nil {
		return err
	}
	if err := t.MkdirAll(path.Dir(newp)); err != nil {
		return err
	}
	n := t.addName(o, newp)
	o.Times.Ctime = t.Clock
	n.FN = o.Times
	t.touchDir(path.Dir(newp))
	return nil
}

// Remove deletes one name: a file's, an empty directory's or a link's. The
// object goes with its last name; a hard-linked file that keeps another
// name stays, with one link fewer, which changes its metadata.
func (t *Tree) Remove(p string) error {
	n := t.byPath[p]
	if n == nil {
		return fmt.Errorf("%s %w", p, ErrNotExist)
	}
	o := n.Obj
	if o.Kind == Dir {
		if kids := t.children(p); len(kids) > 0 {
			return fmt.Errorf("directory %s is not empty (it holds %s)", p, kids[0])
		}
	}
	n.removed = true
	o.Names = slices.DeleteFunc(o.Names, func(m *Name) bool { return m == n })
	delete(t.byPath, p)
	t.unindex(p)
	if len(o.Names) == 0 {
		o.removed = true
		t.removed = append(t.removed, o)
	} else {
		o.Path = o.Names[0].Path
		o.Times.Ctime = t.Clock
	}
	t.touchDir(path.Dir(p))
	return nil
}

// Rename moves the name oldp (and, for a directory, every name under it) to
// newp, which must not exist.
func (t *Tree) Rename(oldp, newp string) error {
	n := t.byPath[oldp]
	if n == nil {
		return fmt.Errorf("%s %w", oldp, ErrNotExist)
	}
	o := n.Obj
	if t.byPath[newp] != nil {
		return fmt.Errorf("%s %w", newp, ErrExist)
	}
	if o.Kind == Dir && strings.HasPrefix(newp+"/", oldp+"/") {
		return fmt.Errorf("cannot move directory %s inside itself", oldp)
	}
	if err := t.MkdirAll(path.Dir(newp)); err != nil {
		return err
	}
	moved := []*Name{n}
	if o.Kind == Dir {
		for _, k := range t.children(oldp) {
			moved = append(moved, t.byPath[k])
		}
	}
	// The old entries come out first, so a move within one directory does not
	// collide with itself, and the old paths are remembered so a refused move
	// can be undone: a rename that fails half way would otherwise leave objects
	// at neither path.
	was := make([]string, len(moved))
	for i, m := range moved {
		was[i] = m.Path
		delete(t.byPath, m.Path)
		t.unindex(m.Path)
	}
	for i, m := range moved {
		to := newp + strings.TrimPrefix(was[i], oldp)
		if err := t.collides(to); err != nil {
			t.putBack(moved, was, i)
			return err
		}
		t.setPath(m, to)
	}
	// A rename changes the object's metadata and both directories' entries,
	// and writes the object's new name with the times it has by then.
	o.Times.Ctime = t.Clock
	n.FN = o.Times
	t.touchDir(path.Dir(oldp))
	t.touchDir(path.Dir(newp))
	return nil
}

// setPath moves a name to p, keeping its object's Path its first name.
func (t *Tree) setPath(n *Name, p string) {
	n.Path = p
	t.byPath[p] = n
	t.index(p)
	n.Obj.Path = n.Obj.Names[0].Path
}

// Copy creates a new file at dst from the file at src, with its streams (as
// the Windows CopyFile does). dst must not exist. The copy is born at the
// clock but keeps the source's modification time, which is what copying
// tools preserve.
func (t *Tree) Copy(src, dst string) error {
	o := t.Get(src)
	if o == nil {
		return fmt.Errorf("%s %w", src, ErrNotExist)
	}
	if o.Kind != File {
		return fmt.Errorf("%s is not a file; copy works on files", src)
	}
	if t.byPath[dst] != nil {
		return fmt.Errorf("%s %w", dst, ErrExist)
	}
	if err := t.CreateFile(dst); err != nil {
		return err
	}
	c := t.Get(dst)
	c.Times.Mtime = o.Times.Mtime
	for s := range o.Streams {
		c.Streams[s] = true
	}
	return nil
}

// AddStream records a named stream on an existing object.
func (t *Tree) AddStream(p, name string) error {
	o := t.Get(p)
	if o == nil {
		return fmt.Errorf("%s %w", p, ErrNotExist)
	}
	o.Streams[name] = true
	return nil
}

// Tag attaches id to the name at p.
func (t *Tree) Tag(p, id string) {
	if n := t.byPath[p]; n != nil {
		t.ids[id] = append(t.ids[id], n)
	}
}

// Live returns the current paths of the names tagged id that still exist,
// in the order they were tagged. known reports whether id was ever used.
func (t *Tree) Live(id string) (paths []string, known bool) {
	names, known := t.ids[id]
	seen := map[*Name]bool{}
	for _, n := range names {
		if !n.removed && !seen[n] {
			seen[n] = true
			paths = append(paths, n.Path)
		}
	}
	return paths, known
}

// Settle lists every object in the order its final times must be applied:
// files and links first, by path, then directories deepest first, so
// stamping a directory is never undone by a later change inside it. A
// hard-linked file is listed once, under its first name.
func (t *Tree) Settle() []*Object {
	var files, dirs []*Object
	seen := map[*Object]bool{}
	for _, n := range t.byPath {
		o := n.Obj
		if seen[o] {
			continue
		}
		seen[o] = true
		if o.Kind == Dir {
			dirs = append(dirs, o)
		} else {
			files = append(files, o)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(dirs, func(i, j int) bool {
		di, dj := strings.Count(dirs[i].Path, "/"), strings.Count(dirs[j].Path, "/")
		if di != dj {
			return di > dj
		}
		return dirs[i].Path < dirs[j].Path
	})
	return append(files, dirs...)
}

// Removed lists the objects that were deleted, in the order they were, each
// with the path and times it had when it went.
func (t *Tree) Removed() []*Object { return t.removed }

// Paths lists every path in the tree, sorted: every name of every object.
func (t *Tree) Paths() []string {
	out := make([]string, 0, len(t.byPath))
	for p := range t.byPath {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (t *Tree) children(dir string) []string {
	var out []string
	prefix := dir + "/"
	for p := range t.byPath {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// putBack undoes a rename that was refused part way through: the first n
// names have already moved, and the rest are out of the tree entirely. It
// leaves the tree exactly as the rename found it.
func (t *Tree) putBack(moved []*Name, was []string, n int) {
	for i, m := range moved {
		if i < n {
			delete(t.byPath, m.Path)
			t.unindex(m.Path)
		}
		t.setPath(m, was[i])
	}
}
