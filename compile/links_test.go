package compile

import (
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/model"
)

// TestLinkRules: each link action says what it needs, a symlink's target
// leaves the output only when the scenario says so, a junction points only
// at a directory that is there, and nothing is written, copied or streamed
// through a link once it exists.
func TestLinkRules(t *testing.T) {
	const head = "operations:\n  - { action: create, path: d/f.txt, content: x }\n  - { action: create, path: dir/ }\n"
	for _, tc := range []struct{ name, body, want string }{
		{"hardlink needs new_path", "  - { action: hardlink, path: d/f.txt }\n", "hardlink needs new_path"},
		{"hardlink of a directory", "  - { action: hardlink, path: dir, new_path: d2 }\n", "only a file can be hard-linked"},
		{"hardlink onto a name", "  - { action: hardlink, path: d/f.txt, new_path: dir }\n", "dir already exists"},
		{"hardlink of nothing", "  - { action: hardlink, path: nope, new_path: x }\n", "nope does not exist"},
		{"hardlink takes no times", "  - { action: hardlink, path: d/f.txt, new_path: x, mtime: 2020-01-01T00:00:00Z }\n", "does not apply to hardlink"},
		{"symlink needs target", "  - { action: symlink, path: l }\n", "symlink needs target"},
		{"symlink outside", "  - { action: symlink, path: d/l, target: ../../etc/passwd }\n", "allow_external_target: true"},
		{"symlink absolute", "  - { action: symlink, path: l, target: /etc/passwd }\n", "points outside the output"},
		{"symlink drive", "  - { action: symlink, path: l, target: 'C:\\Windows\\System32' }\n", "points outside the output"},
		{"allow inside", "  - { action: symlink, path: l, target: d/f.txt, allow_external_target: true }\n", "has no effect"},
		{"backslash", "  - { action: symlink, path: l, target: 'd\\f.txt' }\n", "uses '/'"},
		{"target type", "  - { action: symlink, path: l, target: d, target_type: folder }\n", "unknown target_type"},
		{"type disagrees", "  - { action: symlink, path: l, target: dir, target_type: file }\n", "dir is a directory"},
		{"symlink onto a name", "  - { action: symlink, path: d/f.txt, target: x }\n", "symlink: d/f.txt already exists"},
		{"junction to a file", "  - { action: junction, path: j, target: d/f.txt }\n", "is not a directory in the output"},
		{"junction to nothing", "  - { action: junction, path: j, target: later }\n", "is not a directory in the output"},
		{"junction outside", "  - { action: junction, path: j, target: ../out }\n", "escapes the output root"},
		{"write through", "  - { action: symlink, path: l, target: d/f.txt }\n  - { action: update, path: l, content: y }\n", "is a link; fsagen never follows one"},
		{"append through", "  - { action: symlink, path: l, target: d/f.txt }\n  - { action: append, path: l, content: y }\n", "is a link"},
		{"copy through", "  - { action: symlink, path: l, target: d/f.txt }\n  - { action: copy, path: l, new_path: c }\n", "is a link"},
		{"stream through", "  - { action: symlink, path: l, target: d/f.txt }\n  - { action: ads, path: l, stream: s, content: y }\n", "is a link"},
		{"create through", "  - { action: junction, path: j, target: dir }\n  - { action: create, path: j/new.txt, content: y }\n", "nothing can be made through it"},
		{"create over", "  - { action: symlink, path: l, target: d/f.txt }\n  - { action: create, path: l, content: y }\n", "write through it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}

// A symlink's type follows its target when the scenario does not say, a
// file for one that is not there; deleting one name of a hard-linked file
// leaves the others; and a junction's target, like a path, sits under the
// actor's base while a symlink's stays relative to the link.
func TestLinkSimulation(t *testing.T) {
	p := mustLoad(t, ModeManifest, `operations:
  - { action: create, path: d/f.txt, content: x }
  - { action: create, path: dir/ }
  - { action: symlink, path: to-dir, target: dir }
  - { action: symlink, path: d/dangling, target: ../nowhere }
  - { action: symlink, path: d/ext, target: /etc/hosts, allow_external_target: true }
  - { action: hardlink, path: d/f.txt, new_path: e/g.txt }
  - { action: delete, path: d/f.txt }
  - { action: mace, path: to-dir, mtime: 2020-01-01T00:00:00Z }
`)
	for i, want := range []string{"", "", "dir", "file", "file"} {
		if got := p.Ops[i].TargetType; got != want {
			t.Errorf("op %d target_type %q, want %q", i+1, got, want)
		}
	}
	if link := p.Ops[5]; link.Links != 2 || link.NewPath != "e/g.txt" {
		t.Errorf("hardlink: links %d", link.Links)
	}
	if del := p.Ops[6]; del.Links != 1 || p.Model.Get("e/g.txt") == nil {
		t.Errorf("deleting one of two names: links %d", del.Links)
	}
	if o := p.Model.Get("to-dir"); o.Kind != model.Symlink || o.Times.Mtime.Year() != 2020 {
		t.Errorf("a mace on a link sets the link's own times: %+v", o)
	}

	pb := mustLoad(t, ModePlaybook, pbHead+`  - actor: u
    actions:
      - { action: create, path: Documents/ }
      - { action: junction, path: Links/docs, target: Documents }
      - { action: symlink, path: Links/up, target: ../Documents }
`)
	if j := pb.Ops[1]; j.Path != "home/Links/docs" || j.Target != "home/Documents" {
		t.Errorf("junction %s -> %s", j.Path, j.Target)
	}
	if s := pb.Ops[2]; s.Target != "../Documents" || s.TargetType != "dir" {
		t.Errorf("symlink -> %s (%s)", s.Target, s.TargetType)
	}
}

// A link the platform cannot make stops the run, with skip too: later
// actions and the settle pass would act on a name that is not there.
func TestLinksCannotBeSkipped(t *testing.T) {
	body := "operations:\n  - { action: create, path: f.txt, content: x }\n  - { action: hardlink, path: f.txt, new_path: g.txt }\n  - { action: create, path: dir/ }\n  - { action: symlink, path: s, target: f.txt }\n  - { action: junction, path: j, target: dir }\n"
	for _, skip := range []bool{false, true} {
		p, err := load(t, ModeManifest, body, Options{})
		if err != nil {
			t.Fatal(err)
		}
		err = Preflight(p, Caps{}, skip)
		for _, want := range []string{"input.yaml:3:5", "hard links", "input.yaml:5:5", "symlinks cannot be made", "input.yaml:6:5", "junctions are an NTFS feature", "a link cannot be skipped"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("skip %v: %v, want %q", skip, err, want)
			}
		}
	}
	p, _ := load(t, ModeManifest, body, Options{})
	if err := Preflight(p, Caps{Hardlinks: true, Symlinks: true, Junctions: true}, false); err != nil {
		t.Error(err)
	}
}
