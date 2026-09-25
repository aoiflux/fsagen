// Package model is an in-memory picture of the output tree that compile-time
// validation runs the scenario against before anything touches the disk. It
// is how "delete of a file that never existed", "update of a missing file",
// "a stream on a missing base" and "ref to a deleted file" become errors that
// name the operation, instead of silent no-ops or half-built corpora.
//
// Objects have an identity that survives renames, so an id given when a file
// is created still names it after it has been moved.
//
// Each object also carries the four times the scenario intends it to have.
// The tree's Clock is the time of the operation being simulated; creating an
// object stamps all four with it, and adding, removing or renaming an entry
// stamps the parent directory's modification and change times. The caller
// applies the per-action rules (what an update or a copy does to a file's
// own times) on top. A zero time means the scenario does not control it.
package model

import (
	"errors"
	"fmt"
	"path"
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

// Kind distinguishes files from directories.
type Kind uint8

const (
	File Kind = iota + 1
	Dir
)

// Object is one file or directory.
type Object struct {
	Serial  int
	Kind    Kind
	Path    string
	Streams map[string]bool
	Times   Times
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

	byPath map[string]*Object
	byFold map[string]string
	ids    map[string][]*Object
	serial int
}

// New returns an empty tree.
func New() *Tree {
	return &Tree{byPath: map[string]*Object{}, byFold: map[string]string{}, ids: map[string][]*Object{}}
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
func (t *Tree) Get(p string) *Object { return t.byPath[p] }

// SetFold turns on collision checking with the given key function and indexes
// everything already in the tree.
func (t *Tree) SetFold(f func(string) string) {
	t.Fold = f
	t.byFold = map[string]string{}
	for p := range t.byPath {
		t.index(p)
	}
}

// Add records an object found on disk (used to seed --into-existing). Its
// times are not controlled until an operation touches it.
func (t *Tree) Add(p string, k Kind) {
	if _, ok := t.byPath[p]; ok {
		return
	}
	t.insert(p, k)
}

func (t *Tree) insert(p string, k Kind) *Object {
	t.serial++
	o := &Object{Serial: t.serial, Kind: k, Path: p, Streams: map[string]bool{}}
	t.byPath[p] = o
	t.index(p)
	return o
}

// add creates a new object at p, refusing a case-insensitive collision. It
// is born at the clock, and its parent directory changes.
func (t *Tree) add(p string, k Kind) error {
	if err := t.collides(p); err != nil {
		return err
	}
	o := t.insert(p, k)
	o.Times = All(t.Clock)
	t.touchDir(path.Dir(p))
	return nil
}

// touchDir records an entry added to, removed from or renamed within dir:
// its modification and change times move to the clock. The root is not
// modelled; its times belong to whoever made it.
func (t *Tree) touchDir(dir string) {
	if o := t.byPath[dir]; o != nil && o.Kind == Dir {
		o.Times.Mtime, o.Times.Ctime = t.Clock, t.Clock
	}
}

// MkdirAll creates p and any missing parents as directories.
func (t *Tree) MkdirAll(p string) error {
	if p == "." || p == "" {
		return nil
	}
	if o := t.byPath[p]; o != nil {
		if o.Kind != Dir {
			return fmt.Errorf("%s is a file, not a directory", p)
		}
		return nil
	}
	if err := t.MkdirAll(path.Dir(p)); err != nil {
		return err
	}
	return t.add(p, Dir)
}

// CreateFile creates or replaces the file at p, creating parent directories.
// replaced reports that a file was already there.
func (t *Tree) CreateFile(p string) (replaced bool, err error) {
	if err := t.MkdirAll(path.Dir(p)); err != nil {
		return false, err
	}
	if o := t.byPath[p]; o != nil {
		if o.Kind == Dir {
			return false, fmt.Errorf("%s is a directory", p)
		}
		return true, nil
	}
	return false, t.add(p, File)
}

// Remove deletes a file or an empty directory.
func (t *Tree) Remove(p string) error {
	o := t.byPath[p]
	if o == nil {
		return fmt.Errorf("%s %w", p, ErrNotExist)
	}
	if o.Kind == Dir {
		if kids := t.children(p); len(kids) > 0 {
			return fmt.Errorf("directory %s is not empty (it holds %s)", p, kids[0])
		}
	}
	o.removed = true
	delete(t.byPath, p)
	t.unindex(p)
	t.touchDir(path.Dir(p))
	return nil
}

// Rename moves the object at oldp (and, for a directory, everything under
// it) to newp, which must not exist.
func (t *Tree) Rename(oldp, newp string) error {
	o := t.byPath[oldp]
	if o == nil {
		return fmt.Errorf("%s %w", oldp, ErrNotExist)
	}
	if t.byPath[newp] != nil {
		return fmt.Errorf("%s %w", newp, ErrExist)
	}
	if o.Kind == Dir && strings.HasPrefix(newp+"/", oldp+"/") {
		return fmt.Errorf("cannot move directory %s inside itself", oldp)
	}
	if err := t.MkdirAll(path.Dir(newp)); err != nil {
		return err
	}
	moved := []*Object{o}
	if o.Kind == Dir {
		for _, k := range t.children(oldp) {
			moved = append(moved, t.byPath[k])
		}
	}
	for _, m := range moved {
		delete(t.byPath, m.Path)
		t.unindex(m.Path)
	}
	for _, m := range moved {
		m.Path = newp + strings.TrimPrefix(m.Path, oldp)
		if err := t.collides(m.Path); err != nil {
			return err
		}
		t.byPath[m.Path] = m
		t.index(m.Path)
	}
	// A rename changes the object's metadata and both directories' entries.
	o.Times.Ctime = t.Clock
	t.touchDir(path.Dir(oldp))
	t.touchDir(path.Dir(newp))
	return nil
}

// Copy creates a new file at dst from the file at src, with its streams (as
// the Windows CopyFile does). dst must not exist. The copy is born at the
// clock but keeps the source's modification time, which is what copying
// tools preserve.
func (t *Tree) Copy(src, dst string) error {
	o := t.byPath[src]
	if o == nil {
		return fmt.Errorf("%s %w", src, ErrNotExist)
	}
	if o.Kind != File {
		return fmt.Errorf("%s is a directory; copy works on files", src)
	}
	if t.byPath[dst] != nil {
		return fmt.Errorf("%s %w", dst, ErrExist)
	}
	if _, err := t.CreateFile(dst); err != nil {
		return err
	}
	c := t.byPath[dst]
	c.Times.Mtime = o.Times.Mtime
	for s := range o.Streams {
		c.Streams[s] = true
	}
	return nil
}

// AddStream records a named stream on an existing object.
func (t *Tree) AddStream(p, name string) error {
	o := t.byPath[p]
	if o == nil {
		return fmt.Errorf("%s %w", p, ErrNotExist)
	}
	o.Streams[name] = true
	return nil
}

// Tag attaches id to the object at p.
func (t *Tree) Tag(p, id string) {
	if o := t.byPath[p]; o != nil {
		t.ids[id] = append(t.ids[id], o)
	}
}

// Live returns the current paths of the objects tagged id that still exist,
// in the order they were tagged. known reports whether id was ever used.
func (t *Tree) Live(id string) (paths []string, known bool) {
	objs, known := t.ids[id]
	seen := map[*Object]bool{}
	for _, o := range objs {
		if !o.removed && !seen[o] {
			seen[o] = true
			paths = append(paths, o.Path)
		}
	}
	return paths, known
}

// Settle lists every object in the order its final times must be applied:
// files first, by path, then directories deepest first, so stamping a
// directory is never undone by a later change inside it.
func (t *Tree) Settle() []*Object {
	var files, dirs []*Object
	for _, o := range t.byPath {
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

// Paths lists every path in the tree, sorted.
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
