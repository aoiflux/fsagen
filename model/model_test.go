package model

import (
	"errors"
	"strings"
	"testing"
)

func TestRenameMovesSubtreeAndIDsFollow(t *testing.T) {
	tr := New()
	if _, err := tr.CreateFile("stage/a.txt"); err != nil {
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
		if _, err := tr.CreateFile(p); err != nil {
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
	if _, err := tr.CreateFile("d/f/x"); err == nil {
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
	if _, err := tr.CreateFile("docs/other.txt"); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("case-variant directory should collide: %v", err)
	}
	if _, err := tr.CreateFile("Docs/REPORT.txt"); err == nil {
		t.Error("case-variant file should collide")
	}
	if _, err := tr.CreateFile("Docs/Report.txt"); err != nil {
		t.Errorf("recreating the same path is not a collision: %v", err)
	}
}
