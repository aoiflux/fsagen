package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/timeline"
)

// linkCaps is what the volume holding the test's temporary directories can
// do, so a test can skip what it cannot have.
func linkCaps(t *testing.T) sandbox.LinkCaps {
	t.Helper()
	fsys, err := sandbox.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	return fsys.LinkCaps()
}

// readJSONL decodes every line of a JSON-lines file into a map.
func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// TestHardLinksEndToEnd: a hard link is one file under two names on disk,
// with one file ID and a link count of two; SHA256SUMS lists each name; the
// answer key says it was linked, then modified through either name, and that
// deleting one name only unlinked it; the modelled timeline has an entry for
// each name, with the same object number.
func TestHardLinksEndToEnd(t *testing.T) {
	if !linkCaps(t).Hard {
		t.Skip("this volume stores no hard links")
	}
	dir := t.TempDir()
	in := writeYAML(t, dir, "m.yaml", `start: 2026-03-11T09:00:00Z
operations:
  - { action: create, path: a/report.txt, content: first }
  - { action: hardlink, path: a/report.txt, new_path: b/report.txt }
  - { action: hardlink, path: a/report.txt, new_path: c/report.txt }
  - { action: update, path: b/report.txt, content: second, mtime: 2026-03-11T10:00:00Z }
  - { action: delete, path: a/report.txt, mtime: 2026-03-11T11:00:00Z }
`)
	out := filepath.Join(dir, "out")
	tl := filepath.Join(dir, "model.jsonl")
	if code, _, stderr := runCLI(t, "--manifest", in, "--seed", "1", "--timeline-source", "modelled", "--timeline", tl, out); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fsys, err := sandbox.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	b, _ := fsys.Meta("b/report.txt")
	c, _ := fsys.Meta("c/report.txt")
	if b.ID == "" || b.ID != c.ID || b.Links != 2 || c.Links != 2 {
		t.Errorf("b: id %s links %d; c: id %s links %d", b.ID, b.Links, c.ID, c.Links)
	}
	if data, _ := fsys.ReadFile("c/report.txt"); string(data) != "second" {
		t.Errorf("c/report.txt = %q; an update through one name is seen through the other", data)
	}

	sums, _ := os.ReadFile(filepath.Join(out+".fsagen", runinfo.SumsFileName))
	if strings.Count(string(sums), "\n") != 2 || !strings.Contains(string(sums), "  b/report.txt\n") || !strings.Contains(string(sums), "  c/report.txt\n") {
		t.Errorf("SHA256SUMS:\n%s", sums)
	}

	var events []string
	for _, f := range readJSONL(t, filepath.Join(out+".fsagen", ledger.AnswerKeyFileName)) {
		events = append(events, f["event"].(string)+" "+f["path"].(string))
		if f["event"] == ledger.Linked && (f["from"] != "a/report.txt" || f["links"] == nil) {
			t.Errorf("linked fact %v", f)
		}
		if f["event"] == ledger.Unlinked && f["links"] != float64(2) {
			t.Errorf("unlinked fact %v", f)
		}
	}
	want := []string{"created a/report.txt", "linked b/report.txt", "linked c/report.txt", "modified b/report.txt", "unlinked a/report.txt"}
	if !slices.Equal(events, want) {
		t.Errorf("answer key %v, want %v", events, want)
	}

	var names []string
	inode := ""
	for _, e := range readJSONL(t, tl) {
		if e["type"] != "file" {
			continue
		}
		names = append(names, e["path"].(string))
		if inode == "" {
			inode = e["inode"].(string)
		}
		if e["inode"] != inode || e["links"] != float64(2) || e["md5"] == nil {
			t.Errorf("modelled entry %v", e)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"b/report.txt", "c/report.txt"}) {
		t.Errorf("modelled timeline names %v", names)
	}
}

// TestSymlinksEndToEnd: a symlink is written with its target as given,
// pointing at a file, at a directory that is not there yet, or outside the
// output, and never followed: a mace on the link moves the link's own
// times and not its target's, SHA256SUMS counts it rather than reading it,
// and the observed timeline reads it as a link with its target.
func TestSymlinksEndToEnd(t *testing.T) {
	if !linkCaps(t).Sym {
		t.Skip("this process or volume cannot make symlinks")
	}
	dir := t.TempDir()
	in := writeYAML(t, dir, "m.yaml", `start: 2026-03-11T09:00:00Z
operations:
  - { action: create, path: data/target.txt, content: x, mtime: 2020-01-01T00:00:00Z }
  - { action: symlink, path: data/latest, target: target.txt }
  - { action: symlink, path: data/later, target: ../archive, target_type: dir }
  - { action: symlink, path: data/hosts, target: /etc/hosts, allow_external_target: true }
  - { action: mace, path: data/latest, mtime: 2019-06-01T00:00:00Z }
`)
	out := filepath.Join(dir, "out")
	obs := filepath.Join(dir, "observed.jsonl")
	if code, _, stderr := runCLI(t, "--manifest", in, "--seed", "1", "--timeline", obs, out); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fsys, err := sandbox.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	for name, target := range map[string]string{"data/latest": "target.txt", "data/later": "../archive", "data/hosts": "/etc/hosts"} {
		if m, err := fsys.Meta(name); err != nil || m.Link != sandbox.LinkSymlink || m.Target != target {
			t.Errorf("%s: %+v %v, want a symlink to %s", name, m, err, target)
		}
	}
	link, _ := fsys.Times("data/latest")
	target, _ := fsys.Times("data/target.txt")
	if link.Mtime.Year() != 2019 || target.Mtime.Year() != 2020 {
		t.Errorf("link mtime %v, target mtime %v: the mace went through the link", link.Mtime, target.Mtime)
	}

	m := readManifest(t, out+".fsagen")
	if m.Outputs.Files != 1 || m.Outputs.Links != 3 {
		t.Errorf("outputs: %d files, %d links", m.Outputs.Files, m.Outputs.Links)
	}
	links := 0
	for _, e := range readJSONL(t, obs) {
		if e["type"] == "link" {
			links++
			if e["link_target"] == nil || e["md5"] != nil {
				t.Errorf("observed link %v", e)
			}
		}
	}
	if links != 3 {
		t.Errorf("observed timeline has %d links, want 3", links)
	}
}

// TestLinkLoopsTerminate: symlinks that point at each other, at their own
// directory, and (on Windows) a junction inside the directory it points at
// are written; every walk fsagen makes over the output (SHA256SUMS, an
// observed timeline, the fingerprint the goldens use, and --clean on the
// next run) lists each link once and never follows it.
func TestLinkLoopsTerminate(t *testing.T) {
	caps := linkCaps(t)
	if !caps.Sym {
		t.Skip("this process or volume cannot make symlinks")
	}
	body := `start: 2026-03-11T09:00:00Z
operations:
  - { action: create, path: a/f.txt, content: x }
  - { action: symlink, path: a/x, target: y }
  - { action: symlink, path: a/y, target: x }
  - { action: symlink, path: a/self, target: . }
`
	wantLinks := []string{"l . a/self", "l x a/y", "l y a/x"}
	if caps.Junction {
		body += "  - { action: junction, path: a/loop, target: a }\n"
		wantLinks = append(wantLinks, "l a a/loop")
	}
	dir := t.TempDir()
	in := writeYAML(t, dir, "m.yaml", body)
	out := filepath.Join(dir, "out")
	for _, args := range [][]string{{"--manifest", in, out}, {"--manifest", in, "--clean", out}} {
		if code, _, stderr := runCLI(t, args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, stderr)
		}
	}
	fp, err := testutil.Fingerprint(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range wantLinks {
		if strings.Count(fp, l+"\n") != 1 {
			t.Errorf("fingerprint lacks %q:\n%s", l, fp)
		}
	}
	tl, err := timeline.Generate(out, timeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tl.Entries); n != 2+len(wantLinks) {
		t.Errorf("observed timeline has %d entries, want %d", n, 2+len(wantLinks))
	}
	if m := readManifest(t, out+".fsagen"); m.Outputs.Files != 1 || m.Outputs.Links != len(wantLinks) {
		t.Errorf("outputs: %d files, %d links", m.Outputs.Files, m.Outputs.Links)
	}
}

// TestIntoExistingSeedsLinks: a tree that already holds a hard-linked file
// and a symlink is seeded with both as they are, so a run into it can
// unlink one name of the file, and refuses to write through the link.
func TestIntoExistingSeedsLinks(t *testing.T) {
	caps := linkCaps(t)
	if !caps.Hard || !caps.Sym {
		t.Skip("this volume or process cannot make both kinds of link")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	first := writeYAML(t, dir, "first.yaml", `start: 2026-03-11T09:00:00Z
operations:
  - { action: create, path: f.txt, content: x }
  - { action: hardlink, path: f.txt, new_path: g.txt }
  - { action: symlink, path: l, target: f.txt }
`)
	if code, _, stderr := runCLI(t, "--manifest", first, out); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	meta := filepath.Join(dir, "second-meta")
	unlink := writeYAML(t, dir, "unlink.yaml", "start: 2026-03-12T09:00:00Z\noperations:\n  - { action: delete, path: g.txt }\n")
	if code, _, stderr := runCLI(t, "--manifest", unlink, "--into-existing", "--meta", meta, out); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	facts := readJSONL(t, filepath.Join(meta, ledger.AnswerKeyFileName))
	if len(facts) != 1 || facts[0]["event"] != ledger.Unlinked {
		t.Errorf("answer key %v, want g.txt unlinked from the seeded file", facts)
	}
	through := writeYAML(t, dir, "through.yaml", "start: 2026-03-12T09:00:00Z\noperations:\n  - { action: update, path: l, content: y }\n")
	code, _, stderr := runCLI(t, "--manifest", through, "--into-existing", "--meta", filepath.Join(dir, "third-meta"), out)
	if code == 0 || !strings.Contains(stderr, "is a link") {
		t.Errorf("writing through a seeded link: exit %d: %s", code, stderr)
	}
}
