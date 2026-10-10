package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenameMovesSubtreeAndIDsFollow(t *testing.T) {
	tr := New()
	if err := tr.CreateFile("stage/a.txt"); err != nil {
		t.Fatal(err)
	}
	tr.Tag("stage/a.txt", "doc")
	if err := tr.Rename("stage", "exfil"); err != nil {
		t.Fatal(err)
	}
	if tr.Get("exfil/a.txt") == nil || tr.Get("stage/a.txt") != nil {
		t.Fatalf("subtree not moved: %v", tr.Paths())
	}
	if live, _ := tr.Live("doc"); len(live) != 1 || live[0] != "exfil/a.txt" {
		t.Errorf("id should follow the rename, got %v", live)
	}
}

func TestRemoveRetiresIDs(t *testing.T) {
	tr := New()
	for _, p := range []string{"s/1", "s/2"} {
		if err := tr.CreateFile(p); err != nil {
			t.Fatal(err)
		}
		tr.Tag(p, "staging")
	}
	if err := tr.Remove("s/1"); err != nil {
		t.Fatal(err)
	}
	live, known := tr.Live("staging")
	if !known || len(live) != 1 || live[0] != "s/2" {
		t.Errorf("Live = %v, %v", live, known)
	}
	if _, known := tr.Live("never"); known {
		t.Error("an unused id should be unknown")
	}
}

func TestPreconditions(t *testing.T) {
	tr := New()
	if err := tr.Remove("missing"); !errors.Is(err, ErrNotExist) {
		t.Errorf("remove missing: %v", err)
	}
	tr.CreateFile("d/f")
	if err := tr.Remove("d"); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("remove non-empty dir: %v", err)
	}
	tr.CreateFile("g")
	if err := tr.Rename("g", "d/f"); !errors.Is(err, ErrExist) {
		t.Errorf("rename onto existing: %v", err)
	}
	if err := tr.CreateFile("d/f/x"); err == nil {
		t.Error("a file cannot be a parent directory")
	}
	if err := tr.AddStream("missing", "s"); !errors.Is(err, ErrNotExist) {
		t.Errorf("stream on missing base: %v", err)
	}
}

func TestFoldCollision(t *testing.T) {
	tr := New()
	tr.SetFold(strings.ToLower)
	tr.CreateFile("Docs/Report.txt")
	if err := tr.CreateFile("docs/other.txt"); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("case-variant directory should collide: %v", err)
	}
	if err := tr.CreateFile("Docs/REPORT.txt"); err == nil {
		t.Error("case-variant file should collide")
	}
	if err := tr.CreateFile("Docs/Report.txt"); err != nil {
		t.Errorf("recreating the same path is not a collision: %v", err)
	}
}

// A hard link is a second name for one object: the object is listed once,
// each name keeps its own $FILE_NAME times and ids, a rename moves one name
// only, and the object goes with its last name. The change time moves each
// time a name comes or goes, as the link count does.
func TestHardLinkNames(t *testing.T) {
	tr := New()
	at := func(m int) time.Time { return time.Date(2026, 3, 11, 9, m, 0, 0, time.UTC) }
	tr.Clock = at(1)
	if err := tr.CreateFile("a/f.txt"); err != nil {
		t.Fatal(err)
	}
	tr.Tag("a/f.txt", "first")
	tr.Clock = at(2)
	if err := tr.Link("a/f.txt", "b/g.txt"); err != nil {
		t.Fatal(err)
	}
	tr.Tag("b/g.txt", "second")
	o := tr.Get("a/f.txt")
	if tr.Get("b/g.txt") != o || len(o.Names) != 2 || o.Times.Ctime != at(2) || o.Times.Btime != at(1) {
		t.Fatalf("after the link: %+v", o)
	}
	if fn := tr.Name("b/g.txt").FN; fn != o.Times {
		t.Errorf("the new name's $FILE_NAME times %+v, want the file's %+v", fn, o.Times)
	}
	if fn := tr.Name("a/f.txt").FN; fn != All(at(1)) {
		t.Errorf("the first name's $FILE_NAME times moved: %+v", fn)
	}
	settled := 0
	for _, s := range tr.Settle() {
		if s == o {
			settled++
		}
	}
	if settled != 1 {
		t.Errorf("the file is settled %d times", settled)
	}

	tr.Clock = at(3)
	if err := tr.Rename("b/g.txt", "c/h.txt"); err != nil {
		t.Fatal(err)
	}
	if live, _ := tr.Live("second"); len(live) != 1 || live[0] != "c/h.txt" {
		t.Errorf("the second name's id follows it: %v", live)
	}
	if live, _ := tr.Live("first"); len(live) != 1 || live[0] != "a/f.txt" {
		t.Errorf("the first name's id stays: %v", live)
	}

	tr.Clock = at(4)
	if err := tr.Remove("a/f.txt"); err != nil {
		t.Fatal(err)
	}
	if len(tr.Removed()) != 0 || o.Path != "c/h.txt" || o.Times.Ctime != at(4) {
		t.Errorf("unlinking one name: removed %v, path %s, ctime %v", tr.Removed(), o.Path, o.Times.Ctime)
	}
	if live, _ := tr.Live("first"); len(live) != 0 {
		t.Errorf("a removed name's id is still live: %v", live)
	}
	if err := tr.Remove("c/h.txt"); err != nil {
		t.Fatal(err)
	}
	if r := tr.Removed(); len(r) != 1 || r[0] != o || o.Path != "c/h.txt" {
		t.Errorf("the last name took the file with it: %v", r)
	}
}

// A link is written and never followed: nothing is made through it or
// written to it, and only a file can be hard-linked.
func TestLinksAreNotFollowed(t *testing.T) {
	tr := New()
	if err := tr.MkdirAll("real"); err != nil {
		t.Fatal(err)
	}
	if err := tr.CreateLink("via", Symlink, "real"); err != nil {
		t.Fatal(err)
	}
	if err := tr.CreateLink("jn", Junction, "real"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{tr.CreateFile("via/x.txt"), "is a link"},
		{tr.MkdirAll("jn/sub"), "is a link"},
		{tr.CreateFile("via"), "write through it"},
		{tr.CreateLink("via", Symlink, "elsewhere"), "already exists"},
		{tr.Link("real", "r2"), "only a file can be hard-linked"},
		{tr.Link("via", "v2"), "only a file can be hard-linked"},
		{tr.Copy("via", "c"), "copy works on files"},
	} {
		if tc.err == nil || !strings.Contains(tc.err.Error(), tc.want) {
			t.Errorf("%v, want %q", tc.err, tc.want)
		}
	}
	if o := tr.Get("via"); o.Kind != Symlink || o.Target != "real" || !o.Kind.IsLink() {
		t.Errorf("symlink %+v", o)
	}
	if err := tr.Remove("real"); err != nil {
		t.Errorf("a link's target can be removed under it: %v", err)
	}
}
