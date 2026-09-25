package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
)

// sidecar reads one file from a run's sidecar directory.
func sidecar(t *testing.T, out, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out+".fsagen", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// genRun runs the CLI into dir/name and returns the output path.
func genRun(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	if runtime.GOOS != "windows" {
		args = append(args, "--on-unsupported=skip")
	}
	if code, _, errOut := runCLI(t, append(args, out)...); code != exitOK {
		t.Fatalf("%v: exit %d: %s", args, code, errOut)
	}
	return out
}

func dryRun(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errOut := runCLI(t, append(args, "--dry-run")...)
	if code != exitOK {
		t.Fatalf("dry run: %d %s", code, errOut)
	}
	return out
}

// TestDeterminismHarness is the determinism contract, checked on every
// shipped example and on bulk mode: two runs with the same seed into
// different directories give identical SHA256SUMS, run manifests and dry-run
// listings, and another seed gives different output.
func TestDeterminismHarness(t *testing.T) {
	type scenario struct {
		name string
		args []string
	}
	var scenarios []scenario
	for _, path := range exampleFiles(t) {
		scenarios = append(scenarios, scenario{strings.TrimSuffix(filepath.Base(path), ".yaml"), []string{"--" + string(exampleMode(path)), path}})
	}
	scenarios = append(scenarios, scenario{"bulk", []string{"--bulk", "1", "--depth", "2"}})

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			seeded := func(seed int) []string { return append([]string{"--seed", fmt.Sprint(seed)}, sc.args...) }
			a := genRun(t, dir, "a", seeded(42)...)
			b := genRun(t, filepath.Join(dir, "elsewhere"), "b", seeded(42)...)
			c := genRun(t, dir, "c", seeded(43)...)

			files := []string{runinfo.SumsFileName, runinfo.FileName}
			if sc.name != "bulk" {
				files = append(files, ledger.FileName)
			}
			for _, name := range files {
				if !bytes.Equal(sidecar(t, a, name), sidecar(t, b, name)) {
					t.Errorf("%s differs between two runs with the same seed:\n%s\n%s", name, sidecar(t, a, name), sidecar(t, b, name))
				}
			}
			if sc.name != "bulk" {
				if dryRun(t, seeded(42)...) != dryRun(t, seeded(42)...) {
					t.Error("dry-run listings differ")
				}
			}
			// A scenario that ends with no files (log-tampering deletes all
			// it makes) is the same under any seed.
			randomised := sc.name == "bulk" || usesRandom(t, sc.args)
			if randomised && len(sidecar(t, a, runinfo.SumsFileName)) > 0 && bytes.Equal(sidecar(t, a, runinfo.SumsFileName), sidecar(t, c, runinfo.SumsFileName)) {
				t.Error("another seed produced the same output")
			}
		})
	}
}

// usesRandom reports whether a scenario draws any random value, and so must
// change with the seed.
func usesRandom(t *testing.T, args []string) bool {
	for _, line := range strings.Split(dryRun(t, append([]string{"--seed", "1"}, args...)...), "\n") {
		if strings.Contains(line, `"random_bytes"`) {
			return true
		}
	}
	a, b := dryRun(t, append([]string{"--seed", "1"}, args...)...), dryRun(t, append([]string{"--seed", "2"}, args...)...)
	return a != b
}

// TestSidecarRecords: SHA256SUMS lists every file with its digest, the run
// manifest carries the digest of SHA256SUMS and no absolute path, and the
// run info holds what is not reproducible.
func TestSidecarRecords(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := genRun(t, dir, "out", "--seed", "9", "--manifest", m)

	sums := string(sidecar(t, out, runinfo.SumsFileName))
	for _, name := range []string{"docs/a.txt", "docs/b.txt"} {
		data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(sums, fmt.Sprintf("%s  %s\n", sha(data), name)) {
			t.Errorf("SHA256SUMS lacks %s:\n%s", name, sums)
		}
	}
	rm := readManifest(t, out+".fsagen")
	if rm.Outputs == nil || rm.Outputs.SHA256SUMS != sha([]byte(sums)) || rm.Outputs.Files != 2 {
		t.Errorf("outputs = %+v", rm.Outputs)
	}
	raw := sidecar(t, out, runinfo.FileName)
	if bytes.Contains(raw, []byte(filepath.ToSlash(dir))) || bytes.Contains(raw, []byte(strings.ReplaceAll(dir, `\`, `\\`))) {
		t.Errorf("the run manifest records an absolute path:\n%s", raw)
	}
	var info runinfo.Info
	if err := json.Unmarshal(sidecar(t, out, runinfo.InfoFileName), &info); err != nil {
		t.Fatal(err)
	}
	if info.Output != out || info.Started == "" || info.Finished == "" || info.OS != runtime.GOOS {
		t.Errorf("run info = %+v", info)
	}
}

// TestInsertingUnrelatedActionLeavesOtherFilesUnchanged: a file's random
// bytes depend on the action that makes it, never on its position among
// the others.
func TestInsertingUnrelatedActionLeavesOtherFilesUnchanged(t *testing.T) {
	const head = "start: 2026-03-11T09:00:00Z\nactors: [ { name: u, base: home } ]\nsteps:\n"
	const keep = "  - actor: u\n    offset: 1h\n    actions:\n      - action: create\n        path: a-${RND:6}.txt\n      - action: create\n        path: b.txt\n        content: \"${UUID} ${HASH:16}\"\n"
	const extra = "  - actor: u\n    actions:\n      - action: create\n        path: early-${RND:6}.txt\n        content_len: 50\n"
	const extraAction = "      - action: create\n        path: middle.txt\n        content_len: 70\n"

	dir := t.TempDir()
	base := writeYAML(t, dir, "base.yaml", head+keep)
	edited := writeYAML(t, dir, "edited.yaml", head+extra+strings.Replace(keep, "      - action: create\n        path: b.txt", extraAction+"      - action: create\n        path: b.txt", 1))

	x := genRun(t, dir, "x", "--seed", "5", "--playbook", base)
	y := genRun(t, dir, "y", "--seed", "5", "--playbook", edited)
	sumsX := strings.Split(strings.TrimSpace(string(sidecar(t, x, runinfo.SumsFileName))), "\n")
	sumsY := string(sidecar(t, y, runinfo.SumsFileName))
	if len(sumsX) != 2 {
		t.Fatalf("base run: %v", sumsX)
	}
	for _, line := range sumsX {
		if !strings.Contains(sumsY, line+"\n") {
			t.Errorf("%q changed when unrelated actions were added:\n%s", line, sumsY)
		}
	}
}

// TestPlaybookRunsInTimeOrder: operations run in scheduled order even when
// steps are declared out of order; ${SEQ} keeps declaration order.
func TestPlaybookRunsInTimeOrder(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", "start: 2026-03-11T09:00:00Z\nactors: [ { name: u, base: home } ]\nsteps:\n"+
		"  - actor: u\n    offset: 2h\n    actions:\n      - action: delete\n        path: note.txt\n      - action: create\n        path: late-${SEQ}.txt\n        content: x\n"+
		"  - actor: u\n    offset: 1h\n    actions:\n      - action: create\n        path: note.txt\n        content: x\n")
	prog, err := compile.Load(compile.ModePlaybook, p, compile.Options{})
	if err != nil {
		t.Fatalf("a delete scheduled after its create was refused: %v", err)
	}
	defer prog.Close()
	var got []string
	for _, op := range prog.Ops {
		got = append(got, op.Action+" "+op.Path)
	}
	if want := "create home/note.txt,delete home/note.txt,create home/late-2.txt"; strings.Join(got, ",") != want {
		t.Errorf("order = %s, want %s", strings.Join(got, ","), want)
	}
}

// TestNoWallClockInContent: output made on either side of a clock tick is
// identical, for every generator that used to read the wall clock (bulk
// JSON, PDF and SQLite dates; unpinned pdf dates; manifest ${DATE}; email
// dates).
func TestNoWallClockInContent(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "start: 2026-01-02T03:04:05Z\noperations:\n"+
		"  - action: create\n    path: r.pdf\n    format: pdf\n    content: \"# ${DATE:2006-01-02}\"\n"+
		"  - action: email\n    path: m.eml\n    email: { from: a@x.test, to: [ b@x.test ], subject: s, body_text: hi }\n")
	p := writeYAML(t, dir, "p.yaml", "start: 2026-01-02T03:04:05Z\nactors: [ { name: u, base: home } ]\nsteps:\n"+
		"  - actor: u\n    actions:\n      - action: create\n        path: r.pdf\n        format: pdf\n        content: x\n"+
		"      - action: email\n        path: m.mbox\n        email: { from: a@x.test, to: [ b@x.test ], subject: s, body_text: hi }\n")

	run := func(tag string) [3][]byte {
		var got [3][]byte
		for i, args := range [][]string{{"--manifest", m}, {"--playbook", p}, {"--bulk", "1", "--depth", "1"}} {
			out := genRun(t, dir, fmt.Sprintf("%s%d", tag, i), args...)
			got[i] = sidecar(t, out, runinfo.SumsFileName)
		}
		return got
	}
	first := run("a")
	next := time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)
	time.Sleep(time.Until(next))
	second := run("b")
	for i := range first {
		if !bytes.Equal(first[i], second[i]) {
			t.Errorf("scenario %d changed with the wall clock:\n%s\n%s", i, first[i], second[i])
		}
	}
}

// TestManifestDateNeedsTime: with no mtime and no start there is no
// reference time, and ${DATE}, an unpinned pdf and an undated email are
// errors rather than the wall clock.
func TestManifestDateNeedsTime(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{
		"operations:\n  - action: create\n    path: a.txt\n    content: \"${DATE:2006}\"\n",
		"operations:\n  - action: create\n    path: a.pdf\n    format: pdf\n    content: x\n",
		"operations:\n  - action: email\n    path: a.eml\n    email: { from: a@x.test }\n",
	} {
		m := writeYAML(t, dir, "m.yaml", body)
		if code, _, errOut := runCLI(t, "--manifest", m, "--validate"); code != exitRuntime || !strings.Contains(errOut, "start") {
			t.Errorf("%q: exit %d: %s", body, code, errOut)
		}
		m = writeYAML(t, dir, "m.yaml", "start: 2026-01-01T00:00:00Z\n"+body)
		if code, _, errOut := runCLI(t, "--manifest", m, "--validate"); code != exitOK {
			t.Errorf("with a start: exit %d: %s", code, errOut)
		}
	}
}

// TestStartNowFlagged: start: now reads the (injected) clock and marks the
// run as not reproducible.
func TestStartNowFlagged(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", "start: now\nactors: [ { name: u, base: home } ]\nsteps:\n  - actor: u\n    offset: 1h\n    actions:\n      - action: create\n        path: a.txt\n        content: x\n")
	when := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	prog, err := compile.Load(compile.ModePlaybook, p, compile.Options{Now: func() time.Time { return when }})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	if !prog.StartNow || !prog.Ops[0].At.Equal(when.Add(time.Hour)) {
		t.Errorf("StartNow=%v At=%v", prog.StartNow, prog.Ops[0].At)
	}
	out := genRun(t, dir, "out", "--playbook", p)
	if readManifest(t, out+".fsagen").Reproducible {
		t.Error("a start: now run is marked reproducible")
	}
}

// TestCrossCapabilityContentEquality: without named streams (and with the
// stream operations skipped) every file has the same bytes; only the stream
// lines of SHA256SUMS are missing.
func TestCrossCapabilityContentEquality(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("needs a volume with named streams for the reference run")
	}
	example := filepath.Join("examples", "playbook-windows-ads-motw.yaml")
	dir := t.TempDir()
	full := genRun(t, dir, "full", "--seed", "42", "--playbook", example)

	capsOverride = &compile.Caps{NamedStreams: false}
	defer func() { capsOverride = nil }()
	bare := genRun(t, dir, "bare", "--seed", "42", "--playbook", example, "--on-unsupported=skip")

	var fileLines []string
	streams := 0
	for _, line := range strings.SplitAfter(string(sidecar(t, full, runinfo.SumsFileName)), "\n") {
		if _, name, _ := strings.Cut(line, "  "); strings.Contains(name, ":") {
			streams++
			continue
		}
		fileLines = append(fileLines, line)
	}
	if streams == 0 {
		t.Fatal("the reference run wrote no streams")
	}
	if got := string(sidecar(t, bare, runinfo.SumsFileName)); got != strings.Join(fileLines, "") {
		t.Errorf("file bytes differ without streams:\n%s\nwant\n%s", got, strings.Join(fileLines, ""))
	}
}

// TestRepeatedEmailRendersPerIteration: each occurrence of a repeated email
// action renders its own tokens and takes its own scheduled date. (Version 1
// rendered the first occurrence and reused it.)
func TestRepeatedEmailRendersPerIteration(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", "start: 2026-03-11T09:00:00Z\nactors: [ { name: u, base: home } ]\nsteps:\n"+
		"  - actor: u\n    repeat: 3\n    every: 1h\n    actions:\n      - action: email\n        path: box.mbox\n        email: { from: a@x.test, to: [ b@x.test ], subject: \"note ${ITER} ${RND:4}\", body_text: hi }\n")
	out := genRun(t, dir, "out", "--playbook", p)
	mbox, err := os.ReadFile(filepath.Join(out, "home", "box.mbox"))
	if err != nil {
		t.Fatal(err)
	}
	for i, hour := range []string{"09:00:00", "10:00:00", "11:00:00"} {
		if !bytes.Contains(mbox, []byte(fmt.Sprintf("Subject: note %d ", i))) || !bytes.Contains(mbox, []byte(hour+" +0000")) {
			t.Errorf("occurrence %d (Subject note %d, Date %s) missing:\n%s", i, i, hour, mbox)
		}
	}
}

// TestEmptyContentWritesEmptyFile: content: ” is an empty file.
func TestEmptyContentWritesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "operations:\n  - action: create\n    path: empty.log\n    content: ''\n")
	out := genRun(t, dir, "out", "--manifest", m)
	data, err := os.ReadFile(filepath.Join(out, "empty.log"))
	if err != nil || len(data) != 0 {
		t.Errorf("empty.log = %q, %v", data, err)
	}
}

// TestRefsTargetsDrawOwnContent: one action over several files (refs) gives
// each file its own random content.
func TestRefsTargetsDrawOwnContent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("refs with random content is only possible on ads, which needs named streams")
	}
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", "start: 2026-03-11T09:00:00Z\nactors: [ { name: u, base: home } ]\nsteps:\n"+
		"  - actor: u\n    batch_count: 2\n    actions:\n      - action: create\n        id: logs\n        path: l${BATCH}.log\n        content: x\n"+
		"  - actor: u\n    offset: 1h\n    actions:\n      - action: ads\n        refs: logs\n        stream: s\n        content_len: 16\n")
	out := genRun(t, dir, "out", "--playbook", p)
	fsys, err := sandbox.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	a, errA := fsys.ReadStream("home/l0.log", "s")
	b, errB := fsys.ReadStream("home/l1.log", "s")
	if errA != nil || errB != nil || len(a) != 16 || bytes.Equal(a, b) {
		t.Errorf("l0.log:s = %q (%v), l1.log:s = %q (%v)", a, errA, b, errB)
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
