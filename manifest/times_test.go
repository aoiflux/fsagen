package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/sandbox"
)

// runPB generates a playbook into a fresh root, settles and verifies it, and
// returns the root and the ledger.
func runPB(t *testing.T, body string) (*sandbox.FS, []ledger.Entry) {
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
	entries := res.Ledger
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })
	return fsys, entries
}

const pb = "start: 2021-03-01T09:00:00Z\nactors: [ { name: u } ]\nsteps:\n"

var t0 = time.Date(2021, 3, 1, 9, 0, 0, 0, time.UTC)

func at(minutes int) time.Time { return t0.Add(time.Duration(minutes) * time.Minute) }

func timesOf(t *testing.T, fsys *sandbox.FS, name string) sandbox.Times {
	t.Helper()
	got, err := fsys.Times(name)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// expect compares the times the platform can set with want; zero fields of
// want are not checked.
func expect(t *testing.T, fsys *sandbox.FS, name string, want sandbox.Times) {
	t.Helper()
	got, caps := timesOf(t, fsys, name), fsys.TimeCaps()
	check := func(field string, g, w time.Time, settable bool) {
		if settable && !w.IsZero() && !g.Equal(w) {
			t.Errorf("%s %s = %s, want %s", name, field, g.Format(time.RFC3339Nano), w.Format(time.RFC3339Nano))
		}
	}
	check("atime", got.Atime, want.Atime, true)
	check("mtime", got.Mtime, want.Mtime, true)
	check("ctime", got.Ctime, want.Ctime, caps.Change)
	check("crtime", got.Btime, want.Btime, caps.Birth)
}

func all(t time.Time) sandbox.Times { return sandbox.Times{Atime: t, Mtime: t, Ctime: t, Btime: t} }

// volume reports what the volume holding the test's temporary directories
// can do, so a test can skip before it asks for what it cannot have (an
// explicit creation time on Linux is refused before anything is written).
func volume(t *testing.T) (sandbox.TimeCaps, bool) {
	t.Helper()
	fsys, err := sandbox.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	return fsys.TimeCaps(), fsys.SupportsStreams()
}

func needWindowsTimes(t *testing.T) {
	t.Helper()
	if c, _ := volume(t); !c.Birth || !c.Change {
		t.Skip("creation and change times can only be set on Windows NTFS/ReFS")
	}
}

func needStreams(t *testing.T) {
	t.Helper()
	if _, ok := volume(t); !ok {
		t.Skip("no named streams on this volume")
	}
}

// F-TIME-1: a created file is born at its scheduled time, and so is the
// directory created to hold it. Creating a file that already exists makes it
// anew: it is born again.
func TestCreateSetsCreationTime(t *testing.T) {
	needWindowsTimes(t)
	fsys, _ := runPB(t, pb+`  - { actor: u, offset: 5m, actions: [ { action: create, path: d/a.txt, content: x } ] }
  - { actor: u, offset: 6m, actions: [ { action: create, path: d/b.txt, content: x } ] }
  - { actor: u, offset: 9m, actions: [ { action: create, path: d/b.txt, content: y } ] }
`)
	expect(t, fsys, "d/a.txt", all(at(5)))
	expect(t, fsys, "d/b.txt", all(at(9)))
	expect(t, fsys, "d", sandbox.Times{Atime: at(5), Mtime: at(6), Ctime: at(6), Btime: at(5)})
}

// F-TIME-2: mace sets exactly the times it names, all four of them.
func TestMaceSetsFourTimes(t *testing.T) {
	needWindowsTimes(t)
	fsys, _ := runPB(t, pb+`  - { actor: u, actions: [ { action: create, path: a.txt, content: x } ] }
  - actor: u
    offset: 10m
    actions:
      - { action: mace, path: a.txt, atime: "2019-01-01T01:00:00Z", mtime: "2019-01-01T02:00:00Z", ctime: "2019-01-01T03:00:00Z", crtime: "2019-01-01T04:00:00Z" }
`)
	ts := func(h int) time.Time { return time.Date(2019, 1, 1, h, 0, 0, 0, time.UTC) }
	expect(t, fsys, "a.txt", sandbox.Times{Atime: ts(1), Mtime: ts(2), Ctime: ts(3), Btime: ts(4)})
}

// A mace that names one time leaves the others as the scenario had them.
func TestMaceLeavesUnnamedTimes(t *testing.T) {
	fsys, _ := runPB(t, pb+`  - { actor: u, actions: [ { action: create, path: a.txt, content: x } ] }
  - { actor: u, offset: 10m, actions: [ { action: mace, path: a.txt, mtime: "2019-01-01T00:00:00Z" } ] }
`)
	want := all(t0)
	want.Mtime = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	expect(t, fsys, "a.txt", want)
}

// F-TIME-1 / CR-6: a timestomped file is exactly one whose modification time
// is earlier than its creation time. Four of six files are stomped, so
// exactly four show mtime < crtime.
func TestQuilldropLiteStompCount(t *testing.T) {
	needWindowsTimes(t)
	var b strings.Builder
	b.WriteString(pb + "  - actor: u\n    batch_count: 6\n    actions: [ { action: create, path: 'stage/doc-${BATCH}.docx', content: x } ]\n")
	b.WriteString("  - actor: u\n    offset: 30m\n    actions:\n")
	for _, n := range []int{0, 2, 3, 5} {
		b.WriteString("      - { action: mace, path: stage/doc-" + string(rune('0'+n)) + ".docx, mtime: \"2019-06-01T00:00:00Z\" }\n")
	}
	fsys, _ := runPB(t, b.String())
	stomped := 0
	for i := 0; i < 6; i++ {
		got := timesOf(t, fsys, "stage/doc-"+string(rune('0'+i))+".docx")
		if got.Mtime.Before(got.Btime) {
			stomped++
		}
	}
	if stomped != 4 {
		t.Errorf("%d files have mtime < crtime, want exactly the 4 stomped", stomped)
	}
}

// F-TIME-3: writing a stream does not undo a timestomp, and neither does a
// mark of the web.
func TestAdsAndMotwKeepTimes(t *testing.T) {
	needWindowsTimes(t)
	needStreams(t)
	fsys, _ := runPB(t, pb+`  - { actor: u, actions: [ { action: create, path: a.exe, content: MZ } ] }
  - { actor: u, offset: 10m, actions: [ { action: mace, path: a.exe, mtime: "2019-01-01T00:00:00Z", crtime: "2019-01-01T00:00:00Z" } ] }
  - actor: u
    offset: 20m
    actions:
      - { action: ads, path: a.exe, stream: quill, content: payload }
      - { action: motw, path: a.exe, zone_id: 3, host_url: "https://evil.test/a.exe" }
`)
	old := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	expect(t, fsys, "a.exe", sandbox.Times{Atime: t0, Mtime: old, Ctime: t0, Btime: old})
	if b, err := fsys.ReadStream("a.exe", "quill"); err != nil || string(b) != "payload" {
		t.Errorf("stream = %q, %v", b, err)
	}
}

// F-TIME-3: a directory's modification and change times follow the last
// entry added, removed or renamed in it; its birth and access times stay
// with its creation. An explicit mace on it holds until a later child event.
func TestDirTimesFollowLastChildEvent(t *testing.T) {
	fsys, _ := runPB(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: d/a.txt, content: x } ] }
  - { actor: u, offset: 2m, actions: [ { action: create, path: d/b.txt, content: x } ] }
  - { actor: u, offset: 3m, actions: [ { action: delete, path: d/a.txt } ] }
  - { actor: u, offset: 4m, actions: [ { action: update, path: d/b.txt, content: y } ] }
  - { actor: u, offset: 5m, actions: [ { action: create, path: e/, type: dir } ] }
  - { actor: u, offset: 6m, actions: [ { action: mace, path: e, mtime: "2019-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 7m, actions: [ { action: create, path: e/c.txt, content: x } ] }
  - { actor: u, offset: 8m, actions: [ { action: create, path: f/, type: dir } ] }
  - { actor: u, offset: 9m, actions: [ { action: create, path: f/c.txt, content: x } ] }
  - { actor: u, offset: 10m, actions: [ { action: mace, path: f, mtime: "2018-01-01T00:00:00Z" } ] }
`)
	// d: born at 1m; entries added at 1m and 2m, removed at 3m; the update
	// at 4m does not touch the directory.
	expect(t, fsys, "d", sandbox.Times{Atime: at(1), Mtime: at(3), Ctime: at(3), Btime: at(1)})
	// e: the mace at 6m is overtaken by the child added at 7m.
	expect(t, fsys, "e", sandbox.Times{Atime: at(5), Mtime: at(7), Ctime: at(7), Btime: at(5)})
	// f: the mace at 10m comes after its last child event, so it holds.
	expect(t, fsys, "f", sandbox.Times{Atime: at(8), Mtime: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC), Ctime: at(9), Btime: at(8)})
}

// N-7: rotating keeps the rotated file's own times (with the change time of
// the rename); the empty file that replaces it is new.
func TestRotateKeepsRotatedTimes(t *testing.T) {
	fsys, _ := runPB(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: append, path: app.log, content: "a\n" } ] }
  - { actor: u, offset: 2m, actions: [ { action: append, path: app.log, content: "b\n" } ] }
  - { actor: u, offset: 3m, actions: [ { action: rotate, path: app.log, new_path: app.log.1 } ] }
`)
	expect(t, fsys, "app.log.1", sandbox.Times{Atime: at(2), Mtime: at(2), Ctime: at(3), Btime: at(1)})
	expect(t, fsys, "app.log", all(at(3)))
}

// N-7: a copy is a new file, born when copied, that keeps its source's
// modification time and (where there are streams) its streams.
func TestCopySemantics(t *testing.T) {
	fsys, _ := runPB(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: a.txt, content: x } ] }
  - { actor: u, offset: 2m, actions: [ { action: update, path: a.txt, content: y } ] }
  - { actor: u, offset: 5m, actions: [ { action: copy, path: a.txt, new_path: b.txt } ] }
`)
	expect(t, fsys, "b.txt", sandbox.Times{Atime: at(5), Mtime: at(2), Ctime: at(5), Btime: at(5)})
	expect(t, fsys, "a.txt", sandbox.Times{Atime: at(2), Mtime: at(2), Ctime: at(2), Btime: at(1)})
}

func TestCopyCarriesStreams(t *testing.T) {
	needStreams(t)
	fsys, entries := runPB(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: a.exe, content: MZ } ] }
  - { actor: u, offset: 2m, actions: [ { action: motw, path: a.exe, zone_id: 3 } ] }
  - { actor: u, offset: 3m, actions: [ { action: copy, path: a.exe, new_path: b.exe } ] }
`)
	if b, err := fsys.ReadStream("b.exe", "Zone.Identifier"); err != nil || !strings.Contains(string(b), "ZoneId=3") {
		t.Errorf("copied Zone.Identifier = %q, %v", b, err)
	}
	if last := entries[len(entries)-1]; len(last.Streams) != 1 || last.Streams[0].Name != "Zone.Identifier" {
		t.Errorf("ledger streams for the copy = %+v", last.Streams)
	}
}

// F-TIME-5: times keep their fraction of a second, to the 100 ns NTFS
// stores.
func TestNanoPrecisionRoundTrip(t *testing.T) {
	// An explicit creation time only where it can be set: elsewhere it is
	// refused before anything is written.
	crtime, want := "", sandbox.Times{Mtime: time.Date(2021, 3, 1, 9, 0, 0, 123456700, time.UTC)}
	if c, _ := volume(t); c.Birth {
		crtime = `, crtime: "2021-03-01T08:59:59.7654321Z"`
		want.Btime = time.Date(2021, 3, 1, 8, 59, 59, 765432100, time.UTC)
	}
	fsys, _ := runPB(t, pb+`  - { actor: u, actions: [ { action: create, path: a.txt, content: x, mtime: "2021-03-01T09:00:00.1234567Z"`+crtime+` } ] }
`)
	// Compared to the volume's resolution: 100 ns on NTFS, nanoseconds on
	// most Linux file systems (checked to a microsecond).
	g, got := fsys.Granularity(), timesOf(t, fsys, "a.txt")
	if g.Mtime >= time.Second {
		t.Skipf("%s keeps whole seconds", fsys.Dir())
	}
	within := func(field string, got, want time.Time, res time.Duration) {
		if d := got.Sub(want); !want.IsZero() && (d >= res || d <= -res) {
			t.Errorf("%s = %s, want %s (resolution %v)", field, got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano), res)
		}
	}
	within("mtime", got.Mtime, want.Mtime, g.Mtime)
	within("crtime", got.Btime, want.Btime, g.Btime)
	if got.Mtime.Nanosecond() == 0 {
		t.Errorf("mtime %v lost its fraction of a second", got.Mtime)
	}
}

// F-TIME-5: sub-second jitter is seeded (the same on every run), is applied
// to times derived from the schedule, and never to an explicit time.
func TestJitterDeterministicAndNeverOnExplicit(t *testing.T) {
	body := "subsecond_jitter: true\n" + pb + `  - actor: u
    offset: 1m
    actions:
      - { action: create, path: a.txt, content: x }
      - { action: create, path: b.txt, content: x, mtime: "2020-01-01T00:00:00Z" }
`
	// The intended times are read from the ledger, which keeps their
	// fractions on any volume; the verify pass has already checked the disk
	// against them, to the volume's resolution.
	_, ea := runPB(t, body)
	_, eb := runPB(t, body)
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	a1, a2 := ea[0].Times, eb[0].Times
	if *a1 != *a2 {
		t.Errorf("jitter differs between runs: %+v vs %+v", a1, a2)
	}
	if m := ts(a1.Mtime); m.Nanosecond() == 0 || m.Truncate(time.Second) != at(1) {
		t.Errorf("derived mtime %v has no jitter within its second", m)
	}
	b := ea[1].Times
	if !ts(b.Mtime).Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("explicit mtime was jittered: %v", b.Mtime)
	}
	if ts(b.Atime).Nanosecond() == 0 {
		t.Errorf("derived atime of b.txt %v has no jitter", b.Atime)
	}
}

// The ledger follows one object through create, timestomp, rename and
// delete: same object number, content digests before and after, and the
// intended times at each step.
func TestLedgerCreateStompRenameDelete(t *testing.T) {
	_, entries := runPB(t, pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: a.txt, content: hello } ] }
  - { actor: u, offset: 2m, actions: [ { action: mace, path: a.txt, mtime: "2019-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 3m, actions: [ { action: rename, path: a.txt, new_path: b.txt } ] }
  - { actor: u, offset: 4m, actions: [ { action: delete, path: b.txt } ] }
`)
	if len(entries) != 4 {
		t.Fatalf("%d entries", len(entries))
	}
	hello := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	obj := entries[0].Object
	for i, e := range entries {
		if e.Object != obj || e.Outcome != ledger.Done {
			t.Errorf("entry %d: object %d outcome %s, want object %d done", i+1, e.Object, e.Outcome, obj)
		}
	}
	if e := entries[0]; e.SHA256Before != "" || e.SHA256After != hello || e.Times.Crtime != "2021-03-01T09:01:00Z" {
		t.Errorf("create: %+v", e)
	}
	if e := entries[1]; e.SHA256Before != hello || e.SHA256After != hello || e.Times.Mtime != "2019-01-01T00:00:00Z" || e.Times.Crtime != "2021-03-01T09:01:00Z" {
		t.Errorf("mace: %+v %+v", e, e.Times)
	}
	if e := entries[2]; e.NewPath != "b.txt" || e.Times.Mtime != "2019-01-01T00:00:00Z" || (e.Times.Ctime != "" && e.Times.Ctime != "2021-03-01T09:03:00Z") {
		t.Errorf("rename: %+v %+v", e, e.Times)
	}
	if e := entries[3]; e.SHA256Before != hello || e.SHA256After != "" || e.Times.Mtime != "2019-01-01T00:00:00Z" {
		t.Errorf("delete: %+v", e)
	}
}

// An explicit creation or change time the platform cannot set, and every
// time the scenario leaves open, is listed as uncontrolled; the ledger never
// claims a time it did not set.
func TestDefaultCrtimeRecordedUncontrolled(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	os.Mkdir(root, 0o755)
	p := writeFile(t, dir, "pb.yaml", pb+"  - { actor: u, actions: [ { action: create, path: a.txt, content: x } ] }\n")
	prog, err := compile.Load(compile.ModePlaybook, p, compile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	linux := compile.Caps{}
	if err := compile.Preflight(prog, linux, false); err != nil {
		t.Fatalf("an implied creation time is not an error: %v", err)
	}
	ctx := ExecContext{FS: fsys, Sources: prog.Sources, Caps: linux}
	entries, err := Execute(ctx, prog.Ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := SettleAndVerify(ctx, prog.Model); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(entries[0].Uncontrolled, ","); got != "ctime,crtime" {
		t.Errorf("uncontrolled = %q, want ctime,crtime", got)
	}
	// Nor does the modelled timeline: those columns are unknown.
	for _, e := range ModelledTimeline(prog.Model, entries, linux).Entries {
		if !e.Ctime.IsZero() || !e.Btime.IsZero() || e.Mtime.IsZero() {
			t.Errorf("modelled %s: ctime %v crtime %v mtime %v", e.Path, e.Ctime, e.Btime, e.Mtime)
		}
	}
}

// Verify reads every time back and names each one that differs.
func TestVerifyPassMatchesModel(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	os.Mkdir(root, 0o755)
	p := writeFile(t, dir, "pb.yaml", pb+"  - { actor: u, actions: [ { action: create, path: d/a.txt, content: x } ] }\n")
	prog, err := compile.Load(compile.ModePlaybook, p, compile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	fsys, _ := sandbox.Open(root)
	defer fsys.Close()
	ctx := ExecContext{FS: fsys, Sources: prog.Sources, Caps: Caps(fsys)}
	if _, err := Execute(ctx, prog.Ops); err != nil {
		t.Fatal(err)
	}
	if err := SettleAndVerify(ctx, prog.Model); err != nil {
		t.Fatalf("a clean run does not verify: %v", err)
	}
	moved := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := fsys.SetTimes("d/a.txt", sandbox.Times{Mtime: moved}); err != nil {
		t.Fatal(err)
	}
	err = Verify(ctx, prog.Model)
	var ve *VerifyError
	// (Setting a time is itself a metadata change, so on NTFS the change
	// time moved too.)
	if !errors.As(err, &ve) || ve.Mismatches[0].Path != "d/a.txt" || ve.Mismatches[0].Field != "mtime" {
		t.Fatalf("verify = %v", err)
	}
	if !strings.Contains(err.Error(), "d/a.txt mtime: want 2021-03-01T09:00:00Z, got 2030-01-01T00:00:00Z") {
		t.Errorf("message: %v", err)
	}
}

// An email file carries its Date: born at the first message of an mbox,
// modified at the last.
func TestEmailTimesFromDate(t *testing.T) {
	fsys, _ := runPB(t, pb+`  - actor: u
    actions:
      - { action: email, path: a.eml, email: { from: a@x.test, to: [b@x.test], subject: s, date: "2020-05-05T05:05:05Z", body_text: hi } }
  - actor: u
    offset: 1m
    every: 1h
    repeat: 2
    actions:
      - { action: email, path: box.mbox, email: { from: a@x.test, to: [b@x.test], subject: s, body_text: hi } }
`)
	d := time.Date(2020, 5, 5, 5, 5, 5, 0, time.UTC)
	expect(t, fsys, "a.eml", all(d))
	expect(t, fsys, "box.mbox", sandbox.Times{Atime: at(61), Mtime: at(61), Ctime: at(61), Btime: at(1)})
}

// When only access times moved after settling (another process read the
// output), the tree is settled again; when they keep moving, the error says
// why. Any other time that moved fails at once.
func TestSettleRetriesOnlyForAccessTimes(t *testing.T) {
	// Real pauses, taken through an injected clock: the test asserts which of
	// them were waited out without waiting any of them, which it could not do
	// while the only way to keep it quick was to declare them all zero.
	retries := []time.Duration{time.Hour, 2 * time.Hour}

	run := func(move func(fsys *sandbox.FS, round int)) (error, int, []time.Duration) {
		dir := t.TempDir()
		root := filepath.Join(dir, "out")
		os.Mkdir(root, 0o755)
		p := writeFile(t, dir, "pb.yaml", pb+"  - { actor: u, actions: [ { action: create, path: a.txt, content: x } ] }\n")
		prog, err := compile.Load(compile.ModePlaybook, p, compile.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer prog.Close()
		fsys, _ := sandbox.Open(root)
		defer fsys.Close()
		ctx := ExecContext{FS: fsys, Sources: prog.Sources, Caps: Caps(fsys), SettleRetries: retries}
		if _, err := Execute(ctx, prog.Ops); err != nil {
			t.Fatal(err)
		}
		rounds := 0
		var waited []time.Duration
		ctx.AfterSettle = func(round int) { rounds++; move(fsys, round) }
		ctx.Sleep = func(d time.Duration) { waited = append(waited, d) }
		return SettleAndVerify(ctx, prog.Model), rounds, waited
	}
	later := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	touch := func(fsys *sandbox.FS, field string) {
		ts := sandbox.Times{Atime: later}
		if field == "mtime" {
			ts = sandbox.Times{Mtime: later}
		}
		// Keep the change time, so only the named time differs.
		ts.Ctime = t0
		if err := fsys.SetTimes("a.txt", ts); err != nil {
			t.Fatal(err)
		}
	}

	err, rounds, waited := run(func(fsys *sandbox.FS, round int) {
		if round == 0 {
			touch(fsys, "atime")
		}
	})
	if err != nil || rounds != 2 {
		t.Errorf("one read after settling: err %v after %d settles, want success after 2", err, rounds)
	}
	if !slices.Equal(waited, retries[:1]) {
		t.Errorf("one read after settling: waited %v, want only the first pause %v", waited, retries[:1])
	}

	err, rounds, waited = run(func(fsys *sandbox.FS, round int) { touch(fsys, "atime") })
	if err == nil || rounds != 3 || !strings.Contains(err.Error(), "another process") {
		t.Errorf("reads that never stop: err %v after %d settles", err, rounds)
	}
	if !slices.Equal(waited, retries) {
		t.Errorf("reads that never stop: waited %v, want every pause %v", waited, retries)
	}

	err, rounds, waited = run(func(fsys *sandbox.FS, round int) { touch(fsys, "mtime") })
	if err == nil || rounds != 1 || strings.Contains(err.Error(), "another process") {
		t.Errorf("a moved mtime: err %v after %d settles, want a plain failure after 1", err, rounds)
	}
	if len(waited) != 0 {
		t.Errorf("a moved mtime: waited %v, want no pause at all: only access times are worth retrying", waited)
	}
}
