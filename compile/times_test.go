package compile

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/model"
)

// An explicit creation or change time is a pre-flight error where it cannot
// be set, naming the operation, line and field; with skip, the operation
// still runs and the field is recorded as dropped.
func TestExplicitCrtimeUnsupportedPreflight(t *testing.T) {
	body := "operations:\n  - action: create\n    path: a.txt\n    content: x\n    crtime: 2020-01-01T00:00:00Z\n    ctime: 2020-01-01T00:00:00Z\n"
	p, err := load(t, ModeManifest, body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = Preflight(p, Caps{NamedStreams: true}, false)
	if err == nil {
		t.Fatal("an explicit crtime passed pre-flight without birth-time support")
	}
	for _, want := range []string{"input.yaml:5:5", "crtime", "creation time cannot be set", "input.yaml:6:5", "change time cannot be set"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}

	p, _ = load(t, ModeManifest, body, Options{})
	if err := Preflight(p, Caps{}, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Ops[0].Dropped, ","); got != "ctime,crtime" || p.Ops[0].Skip != "" {
		t.Errorf("dropped %q, skip %q", got, p.Ops[0].Skip)
	}

	p, _ = load(t, ModeManifest, body, Options{})
	if err := Preflight(p, Caps{BirthTime: true, ChangeTime: true}, false); err != nil {
		t.Errorf("Windows capabilities: %v", err)
	}
}

// A delete stamps the object with its final intended times before removing
// it, so what is left of it on disk carries scenario times; its own times
// describe the directory it leaves.
func TestDeleteStampsBeforeRemoval(t *testing.T) {
	p, err := load(t, ModePlaybook, pbHead+`  - { actor: u, offset: 1m, actions: [ { action: create, path: d/a.txt, content: x } ] }
  - { actor: u, offset: 2m, actions: [ { action: mace, path: d/a.txt, mtime: "2019-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 3m, actions: [ { action: delete, path: d/a.txt, atime: "2018-01-01T00:00:00Z" } ] }
`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	del := p.Ops[2]
	created := time.Date(2026, 3, 11, 9, 1, 0, 0, time.UTC)
	stomped := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if len(del.Pre) != 1 || del.Pre[0].Path != "home/d/a.txt" || !del.Pre[0].Times.Mtime.Equal(stomped) || !del.Pre[0].Times.Btime.Equal(created) {
		t.Errorf("pre-stamp = %+v", del.Pre)
	}
	dir := p.Model.Get("home/d")
	removed := time.Date(2026, 3, 11, 9, 3, 0, 0, time.UTC)
	if want := (model.Times{Atime: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC), Mtime: removed, Ctime: removed, Btime: created}); dir.Times != want {
		t.Errorf("directory times = %+v, want %+v", dir.Times, want)
	}
}

// A delete's times describe the directory it leaves, and the output root's
// own times are never part of the scenario.
func TestDeleteTimesAtRootRefused(t *testing.T) {
	mustFail(t, ModeManifest, "operations:\n  - { action: create, path: a.txt, content: x }\n  - { action: delete, path: a.txt, mtime: 2020-01-01T00:00:00Z }\n",
		"output root's own times are not part of the scenario")
}

// In a manifest an operation happens at its mtime, else its atime, else the
// manifest's start; with none of them its times are left to the file
// system.
func TestManifestReferenceTime(t *testing.T) {
	p, err := load(t, ModeManifest, `start: 2021-01-01T00:00:00Z
operations:
  - { action: create, path: a.txt, content: x, mtime: 2022-01-01T00:00:00Z }
  - { action: create, path: b.txt, content: x, atime: 2023-01-01T00:00:00Z }
  - { action: create, path: c.txt, content: x }
`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"2022-01-01T00:00:00Z", "2023-01-01T00:00:00Z", "2021-01-01T00:00:00Z"} {
		if got := p.Ops[i].Times.Btime.Format(time.RFC3339); got != want {
			t.Errorf("op %d born at %s, want %s", i+1, got, want)
		}
	}

	p, err = load(t, ModeManifest, "operations:\n  - { action: create, path: a.txt, content: x }\n", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ops[0].Times != (model.Times{}) {
		t.Errorf("an operation with no time has intended times %+v", p.Ops[0].Times)
	}
}

// Playbook actions no longer copy the scheduled time into atime and mtime:
// those fields hold only what the author wrote, which is what explicit
// means for mace and for jitter.
func TestScheduledTimeIsNotExplicit(t *testing.T) {
	p, err := load(t, ModePlaybook, pbHead+"  - { actor: u, offset: 1m, actions: [ { action: create, path: a.txt, content: x } ] }\n", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if op := p.Ops[0]; op.Atime != "" || op.Mtime != "" || !op.When.Equal(op.At) {
		t.Errorf("atime %q mtime %q when %v at %v", op.Atime, op.Mtime, op.When, op.At)
	}
}
