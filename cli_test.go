package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	manifestpkg "github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
)

// testCaps replaces the detected capability set for the tests that exercise a
// platform they are not running on. nil uses the real detection. It lives here,
// in the test harness, rather than in the command: the command takes its
// capability source as an argument.
var testCaps *compile.Caps

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	capsFor := manifestpkg.Caps
	if testCaps != nil {
		fixed := *testCaps
		capsFor = func(*sandbox.FS) compile.Caps { return fixed }
	}
	code := runWithCaps(args, &out, &errOut, capsFor)
	return code, out.String(), errOut.String()
}

func writeYAML(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readManifest(t *testing.T, dir string) runinfo.Manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, runinfo.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var m runinfo.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

const simpleManifest = "operations:\n  - action: create\n    path: docs/a.txt\n    content: \"hello ${RND:8}\"\n    mtime: 2021-06-01T00:00:00Z\n  - action: create\n    path: docs/b.txt\n    content_len: 32\n"

func TestNoArgsExit2Stderr(t *testing.T) {
	code, out, errOut := runCLI(t)
	if code != 2 || out != "" || !strings.Contains(errOut, "nothing to do") {
		t.Errorf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestHelpExit0(t *testing.T) {
	code, out, _ := runCLI(t, "-h")
	if code != exitOK || !strings.Contains(out, "Usage: fsagen") || !strings.Contains(out, "Exit status") {
		t.Errorf("code=%d stdout=%q", code, out)
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	for _, args := range [][]string{
		{"--manifest", m, "--playbook", m, filepath.Join(dir, "o")},
		{"--manifest", m, "--clean", "--into-existing", filepath.Join(dir, "o")},
		{"--manifest", m, "--on-unsupported", "maybe", filepath.Join(dir, "o")},
		{"--bulk", "1", "--depth", "0", filepath.Join(dir, "o")},
		{"--manifest", m, filepath.Join(dir, "o"), "--seed", "3"},
		{"--nosuchflag"},
	} {
		if code, _, errOut := runCLI(t, args...); code != 2 || errOut == "" {
			t.Errorf("%v: code=%d stderr=%q", args, code, errOut)
		}
	}
}

func TestRuntimeErrorExit1Stderr(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "operations:\n  - action: delete\n    path: nope.txt\n")
	code, out, errOut := runCLI(t, "--manifest", m, filepath.Join(dir, "out"))
	if code != 1 || !strings.Contains(errOut, "nope.txt does not exist") || strings.Contains(out, "does not exist") {
		t.Errorf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Error("a refused run created the output directory")
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "--version")
	want := fmt.Sprintf("generator version %d", constant.GeneratorVersion)
	if code != exitOK || !strings.Contains(out, want) || !strings.Contains(out, runtime.GOOS) {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestOutputIsFileRefused(t *testing.T) {
	dir := t.TempDir()
	file := writeYAML(t, dir, "iamafile.txt", "x")
	code, _, errOut := runCLI(t, "--bulk", "1", "--depth", "1", file)
	if code != exitRuntime || !strings.Contains(errOut, "is a file") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("something was generated beside the file: %v", got)
	}
}

func TestNestedRootIsCreated(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "a", "b", "c")
	if code, _, errOut := runCLI(t, "--manifest", m, out); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(out, "docs", "a.txt")); err != nil {
		t.Error(err)
	}
}

func TestNonEmptyRootNeedsCleanOrIntoExisting(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")
	fresh := filepath.Join(dir, "fresh")

	for _, o := range []string{out, fresh} {
		if code, _, errOut := runCLI(t, "--seed", "5", "--manifest", m, o); code != exitOK {
			t.Fatalf("code=%d %s", code, errOut)
		}
	}
	os.WriteFile(filepath.Join(out, "leftover.txt"), []byte("old run"), 0o644)

	code, _, errOut := runCLI(t, "--seed", "5", "--manifest", m, out)
	if code != exitRuntime || !strings.Contains(errOut, "not empty") {
		t.Fatalf("second run without a flag: code=%d %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "--seed", "5", "--manifest", m, "--clean", out); code != exitOK {
		t.Fatalf("--clean: code=%d %s", code, errOut)
	}
	a, _ := testutil.Fingerprint(out)
	b, _ := testutil.Fingerprint(fresh)
	if a != b {
		t.Errorf("--clean output differs from a fresh run:\n%s\nvs\n%s", a, b)
	}

	os.WriteFile(filepath.Join(out, "leftover.txt"), []byte("old run"), 0o644)
	if code, _, errOut := runCLI(t, "--seed", "5", "--manifest", m, "--into-existing", out); code != exitOK {
		t.Fatalf("--into-existing: code=%d %s", code, errOut)
	}
	rm := readManifest(t, out+".fsagen")
	if !rm.Options.IntoExisting || rm.Reproducible {
		t.Errorf("merge not recorded: %+v", rm.Options)
	}
	if _, err := os.Stat(filepath.Join(out, "leftover.txt")); err != nil {
		t.Error("--into-existing should keep what was there")
	}
}

func TestTimelineFormats(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)

	body := filepath.Join(dir, "case.body")
	if code, _, errOut := runCLI(t, "--manifest", m, "--timeline", body, filepath.Join(dir, "o1")); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	data, _ := os.ReadFile(body)
	first := strings.SplitN(string(data), "\n", 2)[0]
	if strings.HasPrefix(first, "Path,") || strings.Count(first, "|") != 10 {
		t.Errorf(".body did not produce a bodyfile: %q", first)
	}

	txt := filepath.Join(dir, "forced.txt")
	if code, _, errOut := runCLI(t, "--manifest", m, "--timeline", txt, "--timeline-format", "bodyfile", filepath.Join(dir, "o2")); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	if data, _ := os.ReadFile(txt); strings.Count(strings.SplitN(string(data), "\n", 2)[0], "|") != 10 {
		t.Error("--timeline-format did not override the extension")
	}

	jl := filepath.Join(dir, "case.jsonl")
	if code, _, errOut := runCLI(t, "--manifest", m, "--timeline", jl, filepath.Join(dir, "o4")); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	if data, _ := os.ReadFile(jl); !strings.HasPrefix(string(data), `{"path":`) {
		t.Errorf(".jsonl did not produce JSON lines: %q", data)
	}

	foo := filepath.Join(dir, "case.foo")
	code, _, errOut := runCLI(t, "--manifest", m, "--timeline", foo, filepath.Join(dir, "o3"))
	if code != exitUsage || !strings.Contains(errOut, "cannot tell the timeline format") {
		t.Errorf("unknown extension: code=%d %s", code, errOut)
	}
	if _, err := os.Stat(foo); !os.IsNotExist(err) {
		t.Error("an unknown extension still wrote a timeline")
	}
	if _, err := os.Stat(filepath.Join(dir, "o3")); !os.IsNotExist(err) {
		t.Error("an unknown extension still generated output")
	}
}

func TestTimelineFailures(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")

	code, _, errOut := runCLI(t, "--manifest", m, "--timeline", filepath.Join(out, "tl.csv"), out)
	if code != exitUsage || !strings.Contains(errOut, "outside the output directory") {
		t.Errorf("timeline inside root: code=%d %s", code, errOut)
	}

	missing := filepath.Join(dir, "missing")
	code, _, errOut = runCLI(t, "--timeline", filepath.Join(dir, "tl.csv"), missing)
	if code != exitRuntime || !strings.Contains(errOut, "existing directory") {
		t.Errorf("timeline-only on a missing dir: code=%d %s", code, errOut)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("timeline-only mode created the directory it was asked to scan")
	}

	code, _, errOut = runCLI(t, "--manifest", m, "--timeline", filepath.Join(dir, "no", "such", "dir", "tl.csv"), out)
	if code != exitRuntime || !strings.Contains(errOut, "write timeline") {
		t.Errorf("unwritable timeline: code=%d %s", code, errOut)
	}
}

const streamPlaybook = `start: 2026-03-11T09:00:00Z
actors: [ { name: u, base: home } ]
steps:
  - actor: u
    actions:
      - { action: create, path: dl.exe, content: MZ, id: dl }
      - { action: ads, ref: dl, stream: quill }
      - { action: motw, ref: dl, zone_id: 3, host_url: 'http://evil.test/dl.exe' }
      - { action: create, path: after.txt, content_len: 64 }
`

func TestUnsupportedOpsFailBeforeAnyWrite(t *testing.T) {
	testCaps = &compile.Caps{NamedStreams: false}
	defer func() { testCaps = nil }()

	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", streamPlaybook)
	out := filepath.Join(dir, "out")
	code, _, errOut := runCLI(t, "--playbook", p, out)
	if code != exitRuntime || !strings.Contains(errOut, "[ads]") || !strings.Contains(errOut, "[motw]") || !strings.Contains(errOut, "--on-unsupported=skip") {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("the output directory was created by a refused run")
	}
	if _, err := os.Stat(out + ".fsagen"); !os.IsNotExist(err) {
		t.Error("a run manifest was written by a refused run")
	}
}

// With --on-unsupported=skip the rest is generated, each skip is recorded,
// and every other file has the same bytes as on a platform that performed
// the skipped operations: each operation draws from its own random stream.
func TestOnUnsupportedSkipRecordsAndKeepsOtherBytes(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", streamPlaybook)

	full := filepath.Join(dir, "full")
	if runtime.GOOS == "windows" {
		if code, _, errOut := runCLI(t, "--playbook", p, full); code != exitOK {
			t.Fatalf("full run: %d %s", code, errOut)
		}
	}

	testCaps = &compile.Caps{NamedStreams: false}
	defer func() { testCaps = nil }()
	skipped := filepath.Join(dir, "skipped")
	code, out, errOut := runCLI(t, "--playbook", p, "--on-unsupported=skip", skipped)
	if code != exitOK || !strings.Contains(out, "Skipped 2 unsupported") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out, errOut)
	}
	rm := readManifest(t, skipped+".fsagen")
	if rm.Status != runinfo.StatusComplete || len(rm.Skipped) != 2 || rm.Skipped[0].Action != "ads" || rm.Skipped[1].Action != "motw" {
		t.Errorf("run manifest: %+v", rm)
	}

	if runtime.GOOS == "windows" {
		a, _ := os.ReadFile(filepath.Join(full, "home", "after.txt"))
		b, _ := os.ReadFile(filepath.Join(skipped, "home", "after.txt"))
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Errorf("after.txt differs between a full and a skipping run: %q vs %q", a, b)
		}
	}
}

func TestFailedRunMarksSidecarFailed(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	os.MkdirAll(out, 0o755)
	locked := filepath.Join(out, "locked.txt")
	os.WriteFile(locked, []byte("x"), 0o644)
	os.Chmod(locked, 0o444)
	defer os.Chmod(locked, 0o644)
	if f, err := os.OpenFile(locked, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Skip("running with privileges that ignore read-only files")
	}

	m := writeYAML(t, dir, "m.yaml", "operations:\n  - action: create\n    path: first.txt\n    content: ok\n  - action: update\n    path: locked.txt\n    content: y\n")
	code, _, errOut := runCLI(t, "--manifest", m, "--into-existing", out)
	if code != exitRuntime || !strings.Contains(errOut, "incomplete") {
		t.Fatalf("code=%d %s", code, errOut)
	}
	rm := readManifest(t, out+".fsagen")
	if rm.Status != runinfo.StatusFailed || !strings.Contains(rm.Failure, "locked.txt") {
		t.Errorf("status=%q failure=%q", rm.Status, rm.Failure)
	}
	// The ledger says how far the run got; there is no answer key for a
	// scenario that did not finish.
	led, err := os.ReadFile(filepath.Join(out+".fsagen", ledger.FileName))
	if err != nil || strings.Count(string(led), "\n") != 1 || !strings.Contains(string(led), `"path":"first.txt"`) {
		t.Errorf("ledger of the failed run = %q, %v", led, err)
	}
	if _, err := os.Stat(filepath.Join(out+".fsagen", ledger.AnswerKeyFileName)); !os.IsNotExist(err) {
		t.Errorf("a failed run wrote an answer key (%v)", err)
	}
}

// F-TIME-6: the run manifest says which times the run could set, and that
// NTFS $FILE_NAME times and the root's own times are never controlled. The
// ledger's digest is recorded with the other outputs.
func TestRunManifestTimeCapabilities(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")
	if code, _, errOut := runCLI(t, "--manifest", m, out); code != exitOK {
		t.Fatalf("%d %s", code, errOut)
	}
	raw, err := os.ReadFile(filepath.Join(out+".fsagen", runinfo.FileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"filename_times_controlled": false`, `"root_times_controlled": false`, `"birth_time": `, `"change_time": `} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("run manifest lacks %s:\n%s", want, raw)
		}
	}
	rm := readManifest(t, out+".fsagen")
	if runtime.GOOS == "windows" && (!rm.Capabilities.BirthTime || !rm.Capabilities.ChangeTime) {
		t.Errorf("capabilities on Windows: %+v", rm.Capabilities)
	}
	led, err := os.ReadFile(filepath.Join(out+".fsagen", ledger.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if rm.Outputs == nil || rm.Outputs.Ledger != sha(led) {
		t.Errorf("run manifest ledger digest %+v, ledger sha %s", rm.Outputs, sha(led))
	}
	key, err := os.ReadFile(filepath.Join(out+".fsagen", ledger.AnswerKeyFileName))
	if err != nil || rm.Outputs.AnswerKey != sha(key) || !strings.Contains(string(key), `"event":"created"`) {
		t.Errorf("answer key %q (%v), recorded digest %s", key, err, rm.Outputs.AnswerKey)
	}
}

// D-2: the timeline source and format are recorded in the run manifest; a
// modelled timeline, being deterministic, with its digest.
func TestTimelineRecorded(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	for _, source := range []string{"observed", "modelled"} {
		out := filepath.Join(dir, source)
		tl := filepath.Join(dir, source+".jsonl")
		if code, _, errOut := runCLI(t, "--manifest", m, "--timeline", tl, "--timeline-source", source, out); code != exitOK {
			t.Fatalf("%s: %d %s", source, code, errOut)
		}
		data, err := os.ReadFile(tl)
		if err != nil || !strings.Contains(string(data), `"path":"docs/a.txt"`) {
			t.Fatalf("%s timeline %q, %v", source, data, err)
		}
		rec := readManifest(t, out+".fsagen").Timeline
		want := &runinfo.Timeline{Source: source, Format: "jsonl", File: source + ".jsonl"}
		if source == "modelled" {
			want.SHA256 = sha(data)
		}
		if rec == nil || *rec != *want {
			t.Errorf("%s: recorded %+v, want %+v", source, rec, want)
		}
	}
}

// The timeline flags are checked before anything is written.
func TestTimelineFlagErrors(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")
	tl := filepath.Join(dir, "tl.csv")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--manifest", m, "--timeline-source", "modelled", out}, "needs --timeline"},
		{[]string{"--manifest", m, "--timeline", tl, "--timeline-source", "guessed", out}, "observed or modelled"},
		{[]string{"--bulk", "1", "--timeline", tl, "--timeline-source", "modelled", out}, "needs --manifest or --playbook"},
		{[]string{"--timeline", tl, "--timeline-source", "modelled", dir}, "needs --manifest or --playbook"},
		{[]string{"--manifest", m, "--timeline", tl, "--hash-limit", "-1", out}, "must not be negative"},
		{[]string{"--manifest", m, "--hash-limit", "10", out}, "needs --timeline"},
		{[]string{"--manifest", m, "--timeline", tl, "--timeline-source", "modelled", "--hash-limit", "10", out}, "applies to observed"},
		{[]string{"--manifest", m, "--timeline", tl, "--timeline-format", "xml", out}, "csv, txt, bodyfile, macb or jsonl"},
	} {
		code, _, errOut := runCLI(t, c.args...)
		if code != exitUsage || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: code=%d %s", c.args, code, errOut)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a refused command still generated output")
	}
}

// F-PLAT-2 for times: an explicit creation time where none can be set fails
// before anything is written; with --on-unsupported=skip the file is made,
// and the dropped field is recorded.
func TestDroppedTimeFieldRecorded(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "operations:\n  - { action: create, path: a.txt, content: x, mtime: 2020-01-02T00:00:00Z, crtime: 2020-01-01T00:00:00Z }\n")
	testCaps = &compile.Caps{NamedStreams: true}
	defer func() { testCaps = nil }()

	out := filepath.Join(dir, "refused")
	code, _, errOut := runCLI(t, "--manifest", m, out)
	if code != exitRuntime || !strings.Contains(errOut, "creation time cannot be set") {
		t.Fatalf("code=%d %s", code, errOut)
	}
	if got := entries(t, out); len(got) != 0 {
		t.Errorf("files written before refusing: %v", got)
	}

	out = filepath.Join(dir, "skipped")
	if code, _, errOut := runCLI(t, "--manifest", m, "--on-unsupported=skip", out); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	rm := readManifest(t, out+".fsagen")
	if len(rm.Skipped) != 1 || rm.Skipped[0].Field != "crtime" || rm.Skipped[0].Action != "create" {
		t.Errorf("skipped = %+v", rm.Skipped)
	}
	if _, err := os.Stat(filepath.Join(out, "a.txt")); err != nil {
		t.Errorf("the operation itself was skipped: %v", err)
	}
	// The ledger does not claim the dropped time was stated and applied.
	if led := string(sidecar(t, out, ledger.FileName)); !strings.Contains(led, `"explicit":["mtime"]`) {
		t.Errorf("ledger explicit fields: %s", led)
	}
}

func TestRunManifestDeterministic(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	var got [2][]byte
	for i := range got {
		out := filepath.Join(dir, "run"+string(rune('a'+i)))
		if code, _, errOut := runCLI(t, "--seed", "9", "--manifest", m, out); code != exitOK {
			t.Fatalf("code=%d %s", code, errOut)
		}
		got[i], _ = os.ReadFile(filepath.Join(out+".fsagen", runinfo.FileName))
	}
	if !bytes.Equal(got[0], got[1]) {
		t.Errorf("run manifests differ:\n%s\n%s", got[0], got[1])
	}
	if bytes.Contains(got[0], []byte(dir)) || bytes.Contains(got[0], []byte(filepath.ToSlash(dir))) {
		t.Error("the run manifest records an absolute path")
	}
}

func TestMetaDirOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")
	code, _, errOut := runCLI(t, "--manifest", m, "--meta", filepath.Join(out, "meta"), out)
	if code != exitUsage || !strings.Contains(errOut, "outside the output directory") {
		t.Errorf("code=%d %s", code, errOut)
	}
}

func TestValidateAndDryRunWriteNothing(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	out := filepath.Join(dir, "out")

	code, stdout, errOut := runCLI(t, "--manifest", m, "--validate", out)
	if code != exitOK || !strings.Contains(stdout, "2 operations, valid") {
		t.Errorf("--validate: code=%d %s %s", code, stdout, errOut)
	}
	code, stdout, _ = runCLI(t, "--manifest", m, "--dry-run")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != exitOK || len(lines) != 2 || !json.Valid([]byte(lines[0])) || !strings.Contains(lines[1], `"random_bytes":32`) {
		t.Errorf("--dry-run: code=%d %q", code, stdout)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("--validate/--dry-run wrote %v", got)
	}
}

func TestEscapeRefusedNothingOutside(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "operations:\n  - action: create\n    path: ../ESCAPED.txt\n    content: escaped\n")
	code, _, errOut := runCLI(t, "--manifest", m, filepath.Join(dir, "out"))
	if code != exitRuntime || !strings.Contains(errOut, "escapes the output root") {
		t.Errorf("code=%d %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "ESCAPED.txt")); !os.IsNotExist(err) {
		t.Error("ESCAPED.txt was written outside the root")
	}
}

// 24 staging files are created under one id and all of them are gone from
// disk after a later "delete refs:" step.
func TestRefsDeleteAllStagingOnDisk(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "p.yaml", `start: 2026-03-11T09:00:00Z
actors: [ { name: u, base: home } ]
steps:
  - { actor: u, batch_count: 24, actions: [ { action: create, path: 'stage/stg_${SEQ}_${RND:6}.tmp', id: staging, content_len: 16 } ] }
  - { actor: u, offset: 1h, actions: [ { action: delete, refs: staging } ] }
`)
	out := filepath.Join(dir, "out")
	if code, _, errOut := runCLI(t, "--playbook", p, out); code != exitOK {
		t.Fatalf("code=%d %s", code, errOut)
	}
	if left := entries(t, filepath.Join(out, "home", "stage")); len(left) != 0 {
		t.Errorf("%d staging files survived: %v", len(left), left)
	}
}
