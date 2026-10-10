package memtarget

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/target"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func content(t *testing.T, m *Mem, name string) string {
	t.Helper()
	data, err := m.ReadFile(name)
	must(t, err)
	return string(data)
}

// The open flags the executor uses do what os.OpenFile does with them.
func TestOpenFlags(t *testing.T) {
	m := New(WindowsCaps)
	must(t, m.WriteFile("d/a.txt", []byte("hello"), target.FileMode))
	f, err := m.OpenFile("d/a.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, target.FileMode)
	must(t, err)
	_, err = io.WriteString(f, " world")
	must(t, err)
	must(t, f.Close())
	if got := content(t, m, "d/a.txt"); got != "hello world" {
		t.Errorf("append: %q", got)
	}
	f, err = m.OpenFile("d/a.txt", os.O_WRONLY|os.O_TRUNC, 0)
	must(t, err)
	must(t, f.Close())
	if got := content(t, m, "d/a.txt"); got != "" {
		t.Errorf("truncate: %q", got)
	}
	if _, err := m.OpenFile("d/missing", os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("open missing: %v", err)
	}
	if _, err := m.OpenFile("d/a.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0); !errors.Is(err, fs.ErrExist) {
		t.Errorf("exclusive create of an existing file: %v", err)
	}
	r, err := m.OpenFile("d/a.txt", os.O_RDONLY, 0)
	must(t, err)
	if _, err := r.Write([]byte("x")); err == nil {
		t.Error("a file opened read-only took a write")
	}
}

// A hard link is one object under two names: one write shows under both,
// both report two links and one ID, and removing a name leaves the other.
func TestHardLinks(t *testing.T) {
	m := New(WindowsCaps)
	must(t, m.WriteFile("a", []byte("1"), target.FileMode))
	must(t, m.Link("a", "sub/b"))
	must(t, m.WriteFile("sub/b", []byte("2"), target.FileMode))
	if got := content(t, m, "a"); got != "2" {
		t.Errorf("a = %q after writing b", got)
	}
	ma, err := m.Meta("a")
	must(t, err)
	mb, err := m.Meta("sub/b")
	must(t, err)
	if ma.Links != 2 || ma.ID != mb.ID {
		t.Errorf("a %+v, b %+v", ma, mb)
	}
	must(t, m.Remove("a"))
	if mb, _ = m.Meta("sub/b"); mb.Links != 1 {
		t.Errorf("b keeps %d link(s)", mb.Links)
	}
}

// A directory renames with everything in it, refuses removal while it holds
// anything, and a link is never walked into.
func TestDirectoriesAndLinks(t *testing.T) {
	m := New(WindowsCaps)
	must(t, m.WriteFile("x/y/z.txt", []byte("z"), target.FileMode))
	must(t, m.Symlink("x/link", "y", true))
	must(t, m.Junction("j", "x/y"))
	must(t, m.Rename("x", "w"))
	if got := content(t, m, "w/y/z.txt"); got != "z" {
		t.Errorf("w/y/z.txt = %q", got)
	}
	if err := m.Remove("w/y"); err == nil {
		t.Error("removed a directory that is not empty")
	}
	var walked []string
	must(t, m.WalkDir(func(name string, d fs.DirEntry, err error) error {
		walked = append(walked, name)
		return err
	}))
	if want := []string{".", "j", "w", "w/link", "w/y", "w/y/z.txt"}; !slices.Equal(walked, want) {
		t.Errorf("walked %q, want %q", walked, want)
	}
	meta, err := m.Meta("j")
	must(t, err)
	if meta.Link != target.LinkJunction || meta.Target != "x/y" {
		t.Errorf("junction: %+v", meta)
	}
}

// Times are kept as set and no others move; once finished, nothing more is
// written and each refusal is counted.
func TestTimesAndFinish(t *testing.T) {
	m := New(WindowsCaps)
	must(t, m.WriteFile("a", nil, target.FileMode))
	at := time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC)
	must(t, m.SetTimes("a", target.Times{Mtime: at}))
	must(t, m.SetTimes("a", target.Times{Btime: at}))
	got, err := m.Times("a")
	must(t, err)
	if want := (target.Times{Mtime: at, Btime: at}); got != want {
		t.Errorf("times %+v, want %+v", got, want)
	}
	if err := m.SetTimes(".", target.Times{Mtime: at}); err == nil {
		t.Error("the root's times were set")
	}
	read, err := m.Finish()
	must(t, err)
	if err := m.WriteFile("b", nil, target.FileMode); !errors.Is(err, ErrFinished) {
		t.Errorf("write after finish: %v", err)
	}
	if _, err := read.ReadFile("a"); err != nil || m.WritesAfterFinish != 1 {
		t.Errorf("read after finish: %v; %d write(s) refused", err, m.WritesAfterFinish)
	}
}
