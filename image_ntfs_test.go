package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume/container"
	imagepkg "github.com/aoiflux/fsagen/volume/image"
	"github.com/aoiflux/libntfs"
)

// ntfsFixture is the scenario TestNTFSImageGolden pins.
var ntfsFixture = filepath.Join("testdata", "image", "ntfs.yaml")

// ntfsImage writes the NTFS fixture into a raw image with an MBR, and
// returns the image.
func ntfsImage(t *testing.T, extra ...string) string {
	t.Helper()
	img := filepath.Join(t.TempDir(), "evidence.img")
	args := append([]string{"--seed", "1", "--manifest", ntfsFixture, "--image", img, "--image-fs", "ntfs", "--image-size", "64M"}, extra...)
	if code, _, stderr := runCLI(t, args...); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	return img
}

// The NTFS fixture makes one image, byte for byte, on every platform: its
// digest, the residue its writes left, and its SHA256SUMS are pinned. The
// image reads back as the scenario intends (the run verifies every time
// through fsagen's NTFS reader), and a second run makes the same bytes.
func TestNTFSImageGolden(t *testing.T) {
	var first string
	for i := range 2 {
		img := ntfsImage(t, "--image-label", "evidence", "--image-time", "2023-03-01T00:00:00Z")
		meta := img + metaDirSuffix
		rm := readManifest(t, meta)
		if rm.Image == nil || rm.Image.FS != "ntfs" || rm.Image.ClusterSize != 4096 || rm.Image.Label != "evidence" || len(rm.Image.Serial) != 16 || rm.Image.UUID != "" || rm.Image.TimeZone != "" {
			t.Fatalf("run manifest image %+v", rm.Image)
		}
		c := rm.Capabilities
		if !c.BirthTime || !c.ChangeTime || !c.Hardlinks || !c.Symlinks || !c.Junctions || !c.NamedStreams || !c.FilenameTimesControlled || c.Slack != "exact" || c.ClusterSize != 4096 {
			t.Errorf("capabilities %+v", c)
		}
		key, err := os.ReadFile(filepath.Join(meta, ledger.AnswerKeyFileName))
		if err != nil {
			t.Fatal(err)
		}
		sums, err := os.ReadFile(filepath.Join(meta, runinfo.SumsFileName))
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		b.WriteString("image_sha256 " + rm.Outputs.Image + "\n")
		for line := range strings.SplitSeq(string(key), "\n") {
			if strings.Contains(line, `"event":"residue"`) {
				b.WriteString(line + "\n")
			}
		}
		b.WriteString(strings.ReplaceAll(string(sums), "\r", ""))
		got := b.String()
		if i == 0 {
			first = got
			testutil.CheckGolden(t, filepath.Join("testdata", "golden", "image", "ntfs.txt"), testutil.InputHash(t, ntfsFixture), got, *update)
		} else if got != first {
			t.Error("a second run made a different image")
		}
		for _, want := range []string{`"type":"ntfs_mft_record"`, `"seq":2`, `"overwritten":true`, `"cause":"overwrite"`, `"kind":"dir"`, `"type":"ntfs_index_entry"`, `"kind":"symlink"`} {
			if !strings.Contains(got, want) {
				t.Errorf("the golden lacks %s:\n%s", want, got)
			}
		}
	}
}

// diff-oracle scores fsagen's own observed timeline of an NTFS image at
// 1.0 with no tolerance at all: every name, stream, digest and link, and
// every time, to 100 ns, is on disk as the scenario intends, the times of
// every name's $FILE_NAME included, which the modelled timeline gives.
func TestNTFSObservedTimelineTo100ns(t *testing.T) {
	dir := t.TempDir()
	tl, model := filepath.Join(dir, "observed.jsonl"), filepath.Join(dir, "modelled.jsonl")
	ntfsImage(t, "--timeline", model, "--timeline-source", "modelled")
	img := ntfsImage(t, "--timeline", tl)
	sc := filepath.Join(dir, "scorecard.json")
	if code, stdout, stderr := runOracle(t, "--meta", img+metaDirSuffix, "--model", model, "--scorecard", sc, "--categories", "files,streams,times,hashes,links,filenames", "--time-tolerance", "0", "--fail-under", "1", tl); code != exitOK {
		t.Fatalf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
	var card struct {
		Categories []struct {
			Name     string
			Expected int
		}
	}
	data, err := os.ReadFile(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatal(err)
	}
	for _, c := range card.Categories {
		if c.Expected == 0 {
			t.Errorf("nothing was expected of %s", c.Name)
		}
	}
	if r := readManifest(t, img+metaDirSuffix).Capabilities.TimeResolution; r == nil || *r != (runinfo.Resolution{Atime: "100ns", Mtime: "100ns", Ctime: "100ns", Crtime: "100ns"}) {
		t.Errorf("time resolution %+v", r)
	}
}

// What an NTFS image cannot hold is refused before anything is written:
// slack on a file small enough to stay in its MFT record, a time before
// 1601, NTFS's own names at the root in any case, and names Windows
// forbids.
func TestNTFSRefusesWhatItCannotHold(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "x.img")
	for _, c := range []struct{ ops, want string }{
		{"  - action: create\n    path: a.txt\n    content_len: 1000\n    slack: {kind: canary, cluster_size: 4096}\n", "inside its NTFS MFT record"},
		{"  - action: create\n    path: a.txt\n    mtime: 1600-12-31T23:59:59Z\n", "outside what this volume can store"},
		{"  - action: create\n    path: $mft/x.txt\n", "file system's own"},
		{"  - action: create\n    path: \"what?.txt\"\n", "Windows name"},
	} {
		m := writeYAML(t, dir, "m.yaml", "operations:\n"+c.ops)
		if code, _, stderr := runCLI(t, "--validate", "--allow-nonportable", "--manifest", m, "--image", img, "--image-fs", "ntfs", "--image-size", "64M"); code != exitRuntime || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d: %s", c.want, code, stderr)
		}
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("--validate wrote %q", names)
	}
}

// A Mark-of-the-Web written into an NTFS image reads back, through libntfs
// rather than fsagen's own reader, as the Zone.Identifier stream Windows
// writes on a download: the same bytes a live run on NTFS would leave. The
// other named stream on the file is still there beside it.
func TestNTFSImageCarriesMarkOfTheWeb(t *testing.T) {
	img := filepath.Join(t.TempDir(), "motw.img")
	if code, _, stderr := runCLI(t, "--seed", "1", "--playbook", filepath.Join("examples", "playbook-windows-ads-motw.yaml"),
		"--image", img, "--image-fs", "ntfs", "--image-size", "64M"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	start := int64(container.MBRStart) * 512
	vol, err := libntfs.OpenWithOptions(io.NewSectionReader(f, start, info.Size()-start), libntfs.Options{ReadOnly: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	file, err := vol.OpenPath("/users/winuser/downloads/installer.exe")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		t.Helper()
		s, err := file.OpenStream(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := s.ReadAll()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(b)
	}
	const want = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\nHostUrl=https://example.com/downloads/installer.exe\r\n"
	if got := read("Zone.Identifier"); got != want {
		t.Errorf("Zone.Identifier = %q\nwant %q", got, want)
	}
	if got := read("Note"); got != "Downloaded by winuser" {
		t.Errorf("Note = %q", got)
	}
}

// The Sleuth Kit, where it is installed, lists every file fsagen wrote,
// and every deleted record the answer key names, under its name; and
// diff-oracle scores its bodyfile at 1.0.
func TestNTFSListedByTSK(t *testing.T) {
	fls, err := exec.LookPath("fls")
	if err != nil {
		t.Skip("fls (The Sleuth Kit) is not installed")
	}
	img := ntfsImage(t)
	off := fmt.Sprint(container.MBRStart)
	out, err := exec.Command(fls, "-r", "-p", "-o", off, img).CombinedOutput()
	if err != nil {
		t.Fatalf("fls: %v\n%s", err, out)
	}
	listing := string(out)
	sums, err := os.ReadFile(filepath.Join(img+metaDirSuffix, runinfo.SumsFileName))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(sums)), "\n") {
		_, name, _ := strings.Cut(line, "  ")
		if !strings.Contains(listing, ":\t"+name+"\n") {
			t.Errorf("fls does not list %s", name)
		}
	}
	key, err := os.ReadFile(filepath.Join(img+metaDirSuffix, ledger.AnswerKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	// The Sleuth Kit gets everything right but one thing: it reads every
	// index block $INDEX_ALLOCATION maps, without $BITMAP, so the entry
	// left in Cache's freed block is to it a file that is there, not one
	// that was deleted.
	phantom := "Cache/cached-thumbnail-0007-0123456789abcdef.tmp"
	n := 0
	for _, f := range readFacts(t, key) {
		if f.Residue == nil || f.Residue.Entry == nil || f.Residue.Entry.Overwritten || f.Residue.Entry.Type != "ntfs_mft_record" || f.Path == phantom {
			continue
		}
		e := f.Residue.Entry
		if !strings.Contains(listing, fmt.Sprintf(" * %d-", e.Number)) || !strings.Contains(listing, ":\t"+f.Path+"\n") {
			t.Errorf("fls lists no deleted record %d (%s)", e.Number, f.Path)
		}
		n++
	}
	if n == 0 {
		t.Error("no deleted record was checked")
	}
	body := filepath.Join(filepath.Dir(img), "tsk.body")
	out, err = exec.Command(fls, "-r", "-m", "/", "-o", off, img).Output()
	if err != nil {
		t.Fatalf("fls -m: %v", err)
	}
	if err := os.WriteFile(body, out, 0o644); err != nil {
		t.Fatal(err)
	}
	tskScore(t, img, body, phantom)
	// With the modelled timeline as the model, every name's $FILE_NAME
	// times are expected, and The Sleuth Kit's ($FILE_NAME) lines give them.
	model := filepath.Join(filepath.Dir(body), "modelled.jsonl")
	ntfsImage(t, "--timeline", model, "--timeline-source", "modelled")
	if c := tskScore(t, img, body, phantom, "--model", model); c["filenames"].Checked < 100 {
		t.Errorf("only %d $FILE_NAME times were checked", c["filenames"].Checked)
	}
}

// scoreCategory is a category of a diff-oracle scorecard.
type scoreCategory struct {
	Name                string
	Checked, TP, FP, FN int
	Missing             []string
	Extra               []struct{ Path string }
}

// tskScore scores The Sleuth Kit's bodyfile of img and checks every
// category is perfect but for phantom: listed as a file there, and its
// deletion missed.
func tskScore(t *testing.T, img, body, phantom string, args ...string) map[string]scoreCategory {
	t.Helper()
	sc := filepath.Join(t.TempDir(), "scorecard.json")
	if code, stdout, stderr := runOracle(t, append([]string{"--meta", img + metaDirSuffix, "--scorecard", sc}, append(args, body)...)...); code != exitOK {
		t.Fatalf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
	var card struct{ Categories []scoreCategory }
	data, err := os.ReadFile(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatal(err)
	}
	out := map[string]scoreCategory{}
	for _, c := range card.Categories {
		out[c.Name] = c
		switch {
		case c.Name == "files" && c.FP == 1 && c.FN == 0 && len(c.Extra) == 1 && c.Extra[0].Path == phantom:
		case c.Name == "deleted" && c.FP == 0 && c.FN == 1 && len(c.Missing) == 1 && strings.HasPrefix(c.Missing[0], phantom+" "):
		case c.Name != "files" && c.Name != "deleted" && c.FP == 0 && c.FN == 0:
		default:
			t.Errorf("%s: %+v", c.Name, c)
		}
	}
	return out
}

// fileNamesAsSet is an NTFS image whose settle pass does not set the
// $FILE_NAME times: once the operations are done, each name keeps the
// times the driver gave it, as NTFS does, and those a timestomp set.
type fileNamesAsSet struct {
	*imagepkg.Image
	settling bool
}

func (f *fileNamesAsSet) BeginOp(n int, when time.Time) {
	f.settling = n == 0
	f.Image.BeginOp(n, when)
}

func (f *fileNamesAsSet) SetFileNameTimes(name string, t target.Times) error {
	if f.settling {
		return nil
	}
	return f.Image.SetFileNameTimes(name, t)
}

// The NTFS driver sets each name's $FILE_NAME times where the model says
// NTFS does, in every example: with the settle pass leaving them as the
// driver set them, every one verifies. The settle pass sets them only so
// that a target that keeps no times of its own (the in-memory one) can
// hold them.
func TestNTFSSetsFileNameTimesAsTheModel(t *testing.T) {
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			c := &config{seed: 42, onUnsupported: onUnsupportedSkip}
			if exampleMode(path) == compile.ModeManifest {
				c.manifest = path
			} else {
				c.playbook = path
			}
			plan, err := imagepkg.NewPlan(imagepkg.Options{Path: filepath.Join(t.TempDir(), "x.img"), FS: "ntfs", Size: 64 << 20, Partition: container.PartitionNone, Time: libgen.DefaultStart, Seed: 42})
			if err != nil {
				t.Fatal(err)
			}
			caps := plan.Caps()
			prog, err := compile.Load(inputMode(c), path, compile.Options{Seed: 42, FoldCase: caps.FoldsCase})
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()
			if err := compile.Preflight(prog, caps, true); err != nil {
				t.Fatal(err)
			}
			img, err := imagepkg.Create(plan)
			if err != nil {
				t.Fatal(err)
			}
			defer img.Abort()
			if g := runGeneration(c, &fileNamesAsSet{Image: img}, prog, caps, runinfo.New(string(inputMode(c)), c.seed), t.TempDir()); g.err != nil {
				t.Fatal(g.err)
			}
		})
	}
}
