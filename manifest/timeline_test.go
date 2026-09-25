package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/timeline"
)

// runRes generates a playbook into a fresh root and returns the root and
// the run's result.
func runRes(t *testing.T, body string) (string, Result) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	p := writeFile(t, dir, "pb.yaml", body)
	res, err := ExecuteFile(compile.ModePlaybook, root, p, compile.Options{Seed: 1})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return root, res
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func format(t *testing.T, tl *timeline.Timeline, f string) string {
	t.Helper()
	var b bytes.Buffer
	if err := tl.Write(&b, f); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// F-TL-5: the answer key lists what a tool should find: what was created,
// modified, renamed, stomped, deleted and streamed, in ledger order, then
// the objects that end with a modification time before their creation time.
func TestAnswerKeyEntries(t *testing.T) {
	caps, streams := volume(t)
	ads := ""
	if streams {
		ads = "  - { actor: u, offset: 6m, actions: [ { action: ads, path: d/b.txt, stream: quill, content: payload } ] }\n"
	}
	_, res := runRes(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: d/a.txt, content: hello } ] }
  - { actor: u, offset: 2m, actions: [ { action: update, path: d/a.txt, content: world } ] }
  - { actor: u, offset: 3m, actions: [ { action: rename, path: d/a.txt, new_path: d/b.txt } ] }
  - { actor: u, offset: 4m, actions: [ { action: mace, path: d/b.txt, mtime: "2019-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 5m, actions: [ { action: append, path: logs/app.log, content: "x\n" } ] }
`+ads+`  - { actor: u, offset: 7m, actions: [ { action: rotate, path: logs/app.log, new_path: logs/app.log.1 } ] }
  - { actor: u, offset: 8m, actions: [ { action: copy, path: d/b.txt, new_path: d/c.txt } ] }
  - { actor: u, offset: 9m, actions: [ { action: delete, path: d/b.txt } ] }
  - { actor: u, offset: 9m, actions: [ { action: truncate, path: logs/app.log } ] }
`)
	facts := res.AnswerKey()
	var got []string
	byEvent := map[string][]ledger.Fact{}
	for _, f := range facts {
		got = append(got, f.Event+" "+f.Path)
		byEvent[f.Event] = append(byEvent[f.Event], f)
	}
	want := []string{
		"created d/a.txt", "modified d/a.txt", "renamed d/b.txt", "stomped d/b.txt", "created logs/app.log",
	}
	if streams {
		want = append(want, "stream d/b.txt")
	}
	want = append(want, "renamed logs/app.log.1", "created logs/app.log", "created d/c.txt")
	if streams {
		want = append(want, "stream d/c.txt")
	}
	// The truncate empties a file that is already empty: nothing to find.
	want = append(want, "deleted d/b.txt")
	if caps.Birth {
		// A copy keeps its source's (stomped) mtime and is born later; the
		// stomped file was deleted with its mtime before its birth.
		want = append(want, "mtime_before_crtime d/b.txt", "mtime_before_crtime d/c.txt")
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("answer key:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	created, modified, renamed := byEvent[ledger.Created][0], byEvent[ledger.Modified][0], byEvent[ledger.Renamed]
	if created.SHA256 != sha("hello") || *created.Size != 5 || created.Kind != "file" || created.At != "2021-03-01T09:01:00Z" {
		t.Errorf("created: %+v", created)
	}
	if modified.SHA256Before != sha("hello") || modified.SHA256 != sha("world") || modified.Object != created.Object {
		t.Errorf("modified: %+v", modified)
	}
	if renamed[0].From != "d/a.txt" || renamed[0].Object != created.Object {
		t.Errorf("rename: %+v", renamed[0])
	}
	logObj := byEvent[ledger.Created][1].Object
	if renamed[1].From != "logs/app.log" || renamed[1].Object != logObj || byEvent[ledger.Created][2].Object == logObj {
		t.Errorf("rotate: the moved file is object %d (want %d), the new one %d", renamed[1].Object, logObj, byEvent[ledger.Created][2].Object)
	}
	if st := byEvent[ledger.Stomped][0]; strings.Join(st.Fields, ",") != "mtime" || st.Times.Mtime != "2019-01-01T00:00:00Z" {
		t.Errorf("stomped: %+v", st)
	}
	if d := byEvent[ledger.Deleted][0]; d.SHA256 != sha("world") || d.Object != created.Object || d.Kind != "file" {
		t.Errorf("deleted: %+v", d)
	}
	if streams {
		for _, s := range byEvent[ledger.StreamWritten] {
			if s.Stream != "quill" || *s.Size != 7 || s.SHA256 != sha("payload") {
				t.Errorf("stream: %+v", s)
			}
		}
	}
	if caps.Birth {
		if m := byEvent[ledger.MtimeBeforeCrtime][0]; !m.Deleted || m.Mtime != "2019-01-01T00:00:00Z" || m.Crtime != "2021-03-01T09:01:00Z" {
			t.Errorf("mtime_before_crtime: %+v", m)
		}
	}
}

const recreate = pb + `  - { actor: u, offset: 1m, actions: [ { action: create, path: d/a.txt, content: first } ] }
  - { actor: u, offset: 2m, actions: [ { action: delete, path: d/a.txt } ] }
  - { actor: u, offset: 3m, actions: [ { action: create, path: d/a.txt, content: second } ] }
`

// F-TL-5: the modelled timeline shows what the scenario deleted, as The
// Sleuth Kit marks it, beside what took its name later.
func TestModelledBodyfileMarksDeleted(t *testing.T) {
	_, res := runRes(t, recreate)
	body := format(t, res.Timeline(), "bodyfile")
	gone := "|/d/a.txt (deleted)|"
	if strings.Count(body, gone) != 1 || strings.Count(body, "|/d/a.txt|") != 1 {
		t.Fatalf("want one deleted and one live d/a.txt:\n%s", body)
	}
	for _, l := range strings.Split(body, "\n") {
		f := strings.Split(l, "|")
		switch {
		case strings.Contains(l, gone):
			if f[8] != itoa(at(1)) || f[0] != "8b04d5e3775d298e78455efc5ca404d5" {
				t.Errorf("deleted entry has mtime %s md5 %s, want its last state: %s", f[8], f[0], l)
			}
		case strings.Contains(l, "|/d/a.txt|"):
			if f[8] != itoa(at(3)) {
				t.Errorf("live entry: %s", l)
			}
		}
	}
}

func itoa(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// F-TL-5: what is read back from disk never shows a deleted object.
func TestObservedBodyfileHasNoDeleted(t *testing.T) {
	root, _ := runRes(t, recreate)
	tl, err := timeline.Generate(root, timeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	body := format(t, tl, "bodyfile")
	if strings.Contains(body, "(deleted)") || strings.Count(body, "|/d/a.txt|") != 1 {
		t.Errorf("observed bodyfile:\n%s", body)
	}
}

// A scenario with a bit of everything: jittered times, directories, a
// rename, a delete, a timestomp and (where there are streams) a stream.
func everything(t *testing.T) string {
	_, streams := volume(t)
	ads := ""
	if streams {
		ads = "  - { actor: u, offset: 4m, actions: [ { action: motw, path: d/e/b.exe, zone_id: 3 } ] }\n"
	}
	return "subsecond_jitter: true\n" + pb + `  - { actor: u, offset: 1m, actions: [ { action: create, path: d/a.txt, content: one }, { action: create, path: d/e/b.exe, content: MZ } ] }
  - { actor: u, offset: 2m, actions: [ { action: rename, path: d/a.txt, new_path: d/c.txt } ] }
  - { actor: u, offset: 3m, actions: [ { action: mace, path: d/c.txt, mtime: "2019-01-01T00:00:00.5Z" } ] }
` + ads + `  - { actor: u, offset: 5m, actions: [ { action: create, path: tmp/x.log, content: y }, { action: delete, path: tmp/x.log } ] }
`
}

// F-DET-4: a modelled timeline is the same bytes on every run, in every
// format.
func TestModelledTimelineIdenticalAcrossRuns(t *testing.T) {
	body := everything(t)
	_, a := runRes(t, body)
	_, b := runRes(t, body)
	for _, f := range timeline.Formats {
		x, y := format(t, a.Timeline(), f), format(t, b.Timeline(), f)
		if x != y {
			t.Errorf("%s differs between runs:\n%s\n%s", f, x, y)
		}
	}
	if !bytes.Equal(ledger.FactBytes(a.AnswerKey()), ledger.FactBytes(b.AnswerKey())) {
		t.Error("answer keys differ between runs")
	}
}

// The modelled timeline is what the observed one finds: for everything
// left on disk, the same size and digest, and the same times wherever the
// run controls them.
func TestModelledMatchesObserved(t *testing.T) {
	root, res := runRes(t, everything(t))
	observed, err := timeline.Generate(root, timeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	g := fsys.Granularity()
	fsys.Close()
	res1 := map[string]time.Duration{"atime": g.Atime, "mtime": g.Mtime, "ctime": g.Ctime, "crtime": g.Btime}
	key := func(e timeline.Entry) string { return e.Path + ":" + e.Stream }
	modelled := map[string]timeline.Entry{}
	for _, e := range res.Timeline().Entries {
		if !e.Deleted {
			modelled[key(e)] = e
		}
	}
	if len(modelled) != len(observed.Entries) {
		t.Errorf("%d modelled entries left, %d observed", len(modelled), len(observed.Entries))
	}
	for _, o := range observed.Entries {
		m, ok := modelled[key(o)]
		if !ok {
			t.Errorf("%s observed but not modelled", key(o))
			continue
		}
		// (A directory's size is whatever its file system makes it; the
		// scenario has no say in it.)
		if o.Type != m.Type || o.MD5 != m.MD5 || (o.Type != timeline.TypeDir && o.Size != m.Size) {
			t.Errorf("%s: observed %s %d %s, modelled %s %d %s", key(o), o.Type, o.Size, o.MD5, m.Type, m.Size, m.MD5)
		}
		for _, c := range []struct {
			name string
			o, m time.Time
		}{{"atime", o.Atime, m.Atime}, {"mtime", o.Mtime, m.Mtime}, {"ctime", o.Ctime, m.Ctime}, {"crtime", o.Btime, m.Btime}} {
			if d := c.o.Sub(c.m); !c.m.IsZero() && (d >= res1[c.name] || d <= -res1[c.name]) {
				t.Errorf("%s %s: observed %s, modelled %s", key(o), c.name, c.o.Format(time.RFC3339Nano), c.m.Format(time.RFC3339Nano))
			}
		}
	}
}

// The modelled timeline carries the mode fsagen requests: an explicit one on
// the object that names it, the defaults elsewhere (including a directory
// made as a missing parent).
func TestModelledModes(t *testing.T) {
	_, res := runRes(t, pb+`  - { actor: u, actions: [ { action: create, path: keys/id_rsa, content: k, mode: "0600" }, { action: create, path: a/b/, type: dir, mode: "0700" }, { action: create, path: plain.txt, content: x } ] }
  - { actor: u, offset: 1m, actions: [ { action: append, path: logs/app.log, content: "x\n" } ] }
  - { actor: u, offset: 2m, actions: [ { action: rotate, path: logs/app.log, new_path: logs/app.log.1, mode: "0640" } ] }
`)
	want := map[string]string{
		"keys/id_rsa": "r/rrw-------", "keys": "d/drwxr-xr-x", "a/b": "d/drwx------", "a": "d/drwxr-xr-x",
		"plain.txt": "r/rrw-r--r--", "logs/app.log": "r/rrw-r-----", "logs/app.log.1": "r/rrw-r--r--",
	}
	for _, e := range res.Timeline().Entries {
		if w, ok := want[e.Path]; ok && e.TSKMode() != w {
			t.Errorf("%s: mode %s, want %s", e.Path, e.TSKMode(), w)
		}
		delete(want, e.Path)
	}
	if len(want) != 0 {
		t.Errorf("missing from the modelled timeline: %v", want)
	}
}
