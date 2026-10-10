package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/internal/memtarget"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/fsagen/volume/fat"
)

// imageFixture is the scenario TestImageGolden pins.
var imageFixture = filepath.Join("testdata", "image", "fat32.yaml")

// Image flags that contradict each other, or come without --image, are
// usage errors, and nothing is written.
func TestImageFlagErrors(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	img := filepath.Join(dir, "x.img")
	for _, args := range [][]string{
		{"--manifest", m, "--image-fs", "fat32", filepath.Join(dir, "out")},
		{"--manifest", m, "--alloc", "first-fit", filepath.Join(dir, "out")},
		{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M", filepath.Join(dir, "out")},
		{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M", "--into-existing"},
		{"--manifest", m, "--image", img, "--image-size", "64M"},
		{"--manifest", m, "--image", img, "--image-fs", "fat32"},
		{"--manifest", m, "--image", img, "--image-fs", "ntfs", "--image-size", "64M"},
		{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "lots"},
		{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "16M"},
		{"--manifest", m, "--image", filepath.Join(dir, "x.vhdx"), "--image-fs", "fat32", "--image-size", "64M"},
		{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M", "--image-time", "yesterday"},
		{"--image", img, "--image-fs", "fat32", "--image-size", "64M"},
	} {
		if code, _, stderr := runCLI(t, args...); code != exitUsage {
			t.Errorf("%q: exit %d, want %d (%s)", args, code, exitUsage, stderr)
		}
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("left behind: %q", names)
	}
}

// The fixture scenario makes one image, byte for byte, on every platform:
// its digest, the residue its writes left, and its SHA256SUMS are pinned.
// The image reads back as the scenario intends (the run verifies every time
// through fsagen's FAT reader), and a second run makes the same bytes.
func TestImageGolden(t *testing.T) {
	var first string
	for i := range 2 {
		dir := t.TempDir()
		img := filepath.Join(dir, "evidence.vhd")
		if code, _, stderr := runCLI(t, "--seed", "1", "--manifest", imageFixture, "--image", img, "--image-fs", "fat32",
			"--image-size", "40M", "--image-label", "Evidence", "--image-time", "2023-03-01T00:00:00Z"); code != exitOK {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		meta := img + metaDirSuffix
		rm := readManifest(t, meta)
		if rm.Target != runinfo.TargetImage || rm.Image == nil || rm.Image.Partition != "mbr" || rm.Image.ClusterSize != 512 || rm.Image.Label != "EVIDENCE" {
			t.Fatalf("run manifest image %+v", rm.Image)
		}
		if !rm.Capabilities.BirthTime || rm.Capabilities.ChangeTime || rm.Capabilities.Slack != "exact" || rm.Capabilities.ClusterSize != 512 {
			t.Errorf("capabilities %+v", rm.Capabilities)
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
			if strings.Contains(line, `"event":"residue"`) || strings.Contains(line, `"event":"slack"`) {
				b.WriteString(line + "\n")
			}
		}
		b.WriteString(strings.ReplaceAll(string(sums), "\r", ""))
		got := b.String()
		if i == 0 {
			first = got
			testutil.CheckGolden(t, filepath.Join("testdata", "golden", "image", "fat32.txt"), testutil.InputHash(t, imageFixture), got, *update)
		} else if got != first {
			t.Error("a second run made a different image")
		}
		if !strings.Contains(got, `"verified":true`) || !strings.Contains(got, `"cause":"delete"`) || !strings.Contains(got, `"overwritten":true`) {
			t.Errorf("the golden lacks exact slack, a delete or an overwritten entry:\n%s", got)
		}
	}
}

// Every example a FAT32 volume can hold makes an image whose files are,
// byte for byte, the files the same scenario writes into a target in
// memory claiming FAT32's capabilities, and whose ledger is that run's: the
// image holds the whole scenario, and its reader reads it all back. The one
// example with a hard link is refused before anything is written.
func TestImagesTakeEveryExample(t *testing.T) {
	caps := fat.Caps(512)
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			mode := "--playbook"
			if exampleMode(path) == compile.ModeManifest {
				mode = "--manifest"
			}
			dir := t.TempDir()
			img := filepath.Join(dir, name+".img")
			code, _, stderr := runCLI(t, "--seed", "42", "--on-unsupported", "skip", mode, path, "--image", img, "--image-fs", "fat32", "--image-size", "64M", "--partition", "none")
			if name == "playbook-macro-phish" {
				if code != exitRuntime || !strings.Contains(stderr, "hard links") {
					t.Fatalf("exit %d: %s", code, stderr)
				}
				if names := entries(t, dir); len(names) != 0 {
					t.Errorf("a refused run left %q", names)
				}
				return
			}
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, stderr)
			}

			c := &config{seed: 42, onUnsupported: onUnsupportedSkip}
			if mode == "--manifest" {
				c.manifest = path
			} else {
				c.playbook = path
			}
			prog, err := compile.Load(inputMode(c), path, compile.Options{Seed: 42, FoldCase: true})
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()
			if err := compile.Preflight(prog, caps, true); err != nil {
				t.Fatal(err)
			}
			metaDir := t.TempDir()
			if g := runGeneration(c, memtarget.New(caps), prog, caps, runinfo.New(string(inputMode(c)), c.seed), metaDir); g.err != nil {
				t.Fatal(g.err)
			}
			for _, f := range []string{runinfo.SumsFileName, ledger.FileName} {
				want, err := os.ReadFile(filepath.Join(metaDir, f))
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(img+metaDirSuffix, f))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s differs from the in-memory run's (%d bytes, want %d)", f, len(got), len(want))
				}
			}
		})
	}
}

// --validate and --dry-run with --image check the scenario against the
// image's file system, not the host's, and write nothing.
func TestImageValidate(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", "operations:\n  - action: create\n    path: a.txt\n  - action: ads\n    path: a.txt\n    stream: s\n    content: x\n")
	img := filepath.Join(dir, "x.img")
	args := []string{"--validate", "--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M"}
	if code, _, stderr := runCLI(t, args...); code != exitRuntime || !strings.Contains(stderr, "alternate data stream") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	old := writeYAML(t, dir, "old.yaml", "operations:\n  - action: create\n    path: a.txt\n    mtime: 1979-12-31T23:59:59Z\n")
	if code, _, stderr := runCLI(t, "--validate", "--manifest", old, "--image", img, "--image-fs", "fat32", "--image-size", "64M"); code != exitRuntime || !strings.Contains(stderr, "outside what this volume can store") {
		t.Errorf("a 1979 time: exit %d: %s", code, stderr)
	}
	bad := writeYAML(t, dir, "bad.yaml", "operations:\n  - action: create\n    path: \"what?.txt\"\n")
	if code, _, stderr := runCLI(t, "--validate", "--allow-nonportable", "--manifest", bad, "--image", img, "--image-fs", "fat32", "--image-size", "64M"); code != exitRuntime || !strings.Contains(stderr, "FAT name") {
		t.Errorf("a '?' in a name: exit %d: %s", code, stderr)
	}
	if names := entries(t, dir); len(names) != 3 {
		t.Errorf("--validate wrote %q", names)
	}
}

// An image that exists is replaced only with --clean, and only once the new
// one is complete; a failed run leaves the old one as it was.
func TestImageExistingNeedsClean(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	img := filepath.Join(dir, "x.img")
	if err := os.WriteFile(img, []byte("an earlier image"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M"}
	if code, _, _ := runCLI(t, args...); code != exitRuntime {
		t.Errorf("an existing image was replaced without --clean (exit %d)", code)
	}
	if code, _, stderr := runCLI(t, append(args, "--clean")...); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if info, _ := os.Stat(img); info.Size() != 64<<20 {
		t.Errorf("the image is %d bytes", info.Size())
	}
	for _, n := range entries(t, dir) {
		if strings.HasSuffix(n, ".tmp") {
			t.Errorf("left a temporary file %s", n)
		}
	}
}

// An observed timeline of an image is read from the image itself.
func TestImageObservedTimeline(t *testing.T) {
	dir := t.TempDir()
	m := writeYAML(t, dir, "m.yaml", simpleManifest)
	img, tl := filepath.Join(dir, "x.img"), filepath.Join(dir, "x.body")
	if code, _, stderr := runCLI(t, "--manifest", m, "--image", img, "--image-fs", "fat32", "--image-size", "64M", "--timeline", tl); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	body, err := os.ReadFile(tl)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "|/docs/a.txt|") || !strings.Contains(string(body), "1622505600") {
		t.Errorf("timeline:\n%s", body)
	}
}

// 7-Zip, where it is installed, opens a VHD fsagen wrote, finds the MBR
// and the FAT32 volume in it, and extracts every file with the digest
// SHA256SUMS gives.
func TestImageReadBy7Zip(t *testing.T) {
	sevenZip, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z is not installed")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "evidence.vhd")
	if code, _, stderr := runCLI(t, "--seed", "1", "--manifest", imageFixture, "--image", img, "--image-fs", "fat32", "--image-size", "40M"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	out := filepath.Join(dir, "x")
	if b, err := exec.Command(sevenZip, "x", "-y", "-o"+out, img).CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, b)
	}
	sums, err := os.ReadFile(filepath.Join(img+metaDirSuffix, runinfo.SumsFileName))
	if err != nil {
		t.Fatal(err)
	}
	// 7-Zip extracts the partition's tree under a folder it names itself.
	root := out
	if es, _ := os.ReadDir(out); len(es) == 1 && es[0].IsDir() && !strings.Contains(string(sums), "  "+es[0].Name()+"/") {
		root = filepath.Join(out, es[0].Name())
	}
	n := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(sums)), "\n") {
		sum, name, _ := strings.Cut(line, "  ")
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("7-Zip did not extract %s: %v", name, err)
			continue
		}
		if runinfo.Digest(data) != sum {
			t.Errorf("%s: 7-Zip's bytes differ", name)
		}
		n++
	}
	if n < 40 {
		t.Errorf("only %d files checked", n)
	}
}

// A bulk corpus written into an image holds the files the bulk golden
// describes, byte for byte.
func TestImageTakesBulk(t *testing.T) {
	img := filepath.Join(t.TempDir(), "bulk.img")
	if code, _, stderr := runCLI(t, "--seed", "7", "--bulk", "1", "--depth", "1", "--bulk-start", bulkGoldenStart, "--image", img, "--image-fs", "fat32", "--image-size", "64M"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	sums, err := os.ReadFile(filepath.Join(img+metaDirSuffix, runinfo.SumsFileName))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden", fmt.Sprintf("v%d", constant.GeneratorVersion), "bulk", "one-of-each.txt")
	if want := sumsOf(t, golden); string(sums) != want {
		t.Errorf("%s:\n%s\nwant (from %s):\n%s", runinfo.SumsFileName, sums, golden, want)
	}
}

// fixtureImage writes the fixture scenario into a raw image with an MBR,
// and returns the image and its answer key.
func fixtureImage(t *testing.T) (string, []ledger.Fact) {
	t.Helper()
	img := filepath.Join(t.TempDir(), "evidence.img")
	if code, _, stderr := runCLI(t, "--seed", "1", "--manifest", imageFixture, "--image", img, "--image-fs", "fat32", "--image-size", "40M"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	data, err := os.ReadFile(filepath.Join(img+metaDirSuffix, ledger.AnswerKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	var facts []ledger.Fact
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var f ledger.Fact
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	return img, facts
}

// fsck.vfat, where dosfstools is installed, finds nothing wrong with an
// image fsagen wrote: not its boot sectors, FSInfo, FATs, chains, or
// directories, deleted entries included.
func TestImageCheckedByFsckVfat(t *testing.T) {
	fsck, err := exec.LookPath("fsck.vfat")
	if err != nil {
		t.Skip("fsck.vfat (dosfstools) is not installed")
	}
	img, _ := fixtureImage(t)
	part := filepath.Join(filepath.Dir(img), "part.img")
	data, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(part, data[container.MBRStart*512:], 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(fsck, "-n", "-v", part).CombinedOutput()
	if err != nil {
		t.Fatalf("fsck.vfat: %v\n%s", err, out)
	}
}

// The Sleuth Kit, where it is installed, lists every file fsagen wrote,
// and lists every deleted entry the answer key names at the address the
// answer key gives it.
func TestImageListedByTSK(t *testing.T) {
	fls, err := exec.LookPath("fls")
	if err != nil {
		t.Skip("fls (The Sleuth Kit) is not installed")
	}
	img, facts := fixtureImage(t)
	out, err := exec.Command(fls, "-r", "-p", "-o", fmt.Sprint(container.MBRStart), img).CombinedOutput()
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
	n := 0
	for _, f := range facts {
		if f.Residue == nil || f.Residue.Entry == nil || f.Residue.Entry.Overwritten {
			continue
		}
		if !strings.Contains(listing, fmt.Sprintf(" * %d:\t", f.Residue.Entry.Number)) {
			t.Errorf("fls lists no deleted entry %d (%s %s)", f.Residue.Entry.Number, f.Residue.Cause, f.Path)
		}
		n++
	}
	if n == 0 {
		t.Error("no deleted entry was checked")
	}

	// And diff-oracle scores what TSK reports at 1.0: every file, every
	// deleted entry that was not reused, and every time the run controls.
	body := filepath.Join(filepath.Dir(img), "tsk.body")
	out, err = exec.Command(fls, "-r", "-m", "/", "-o", fmt.Sprint(container.MBRStart), img).Output()
	if err != nil {
		t.Fatalf("fls -m: %v", err)
	}
	if err := os.WriteFile(body, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runOracle(t, "--meta", img+metaDirSuffix, "--fail-under", "1", body); code != exitOK {
		t.Errorf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
}

// diff-oracle scores an image run with what its file system can keep in
// mind: an access time FAT keeps only to the day matches, and a deleted
// entry whose name a tool shows damaged (FAT puts 0xE5 over the first
// character) is found by the address the answer key gives it. Here the
// tool is fsagen's own observed timeline, with a line added for each
// deleted entry as The Sleuth Kit shows it; TestImageListedByTSK runs the
// real thing where it is installed.
func TestImageScoredByOracle(t *testing.T) {
	img, facts := fixtureImage(t)
	meta := img + metaDirSuffix
	dir := filepath.Dir(img)
	observed := filepath.Join(dir, "observed.body")
	again := filepath.Join(dir, "again.img")
	if code, _, stderr := runCLI(t, "--seed", "1", "--manifest", imageFixture, "--image", again, "--image-fs", "fat32", "--image-size", "40M", "--timeline", observed); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	score := func(body string, categories string) oracleScore {
		t.Helper()
		card := filepath.Join(dir, "card.json")
		if code, stdout, stderr := runOracle(t, "--meta", meta, "--categories", categories, "--strip-prefix", "/", "--scorecard", card, body); code != exitOK {
			t.Fatalf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
		}
		data, err := os.ReadFile(card)
		if err != nil {
			t.Fatal(err)
		}
		var sc oracleScore
		if err := json.Unmarshal(data, &sc); err != nil {
			t.Fatal(err)
		}
		return sc
	}
	sc := score(observed, "files,times")
	if sc.Overall.F1 != 1 || sc.Resolution != "atime 24h, mtime 2s" {
		t.Errorf("files and times: F1 %v, resolution %q", sc.Overall.F1, sc.Resolution)
	}

	var b strings.Builder
	reused := 0
	for _, f := range facts {
		r := f.Residue
		if r == nil || r.Entry == nil {
			continue
		}
		if r.Entry.Overwritten {
			reused++
			continue
		}
		d, name := filepath.Dir(filepath.FromSlash(f.Path)), filepath.Base(f.Path)
		fmt.Fprintf(&b, "0|/%s/_%s (deleted)|%d|r/rrwxrwxrwx|0|0|0|0|0|0|0\n", filepath.ToSlash(d), name[1:], r.Entry.Number)
	}
	deleted := filepath.Join(dir, "deleted.body")
	if err := os.WriteFile(deleted, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	sc = score(deleted, "deleted")
	if sc.Overall.F1 != 1 || sc.Paths.Reused != reused || reused == 0 {
		t.Errorf("deleted: F1 %v, %d reused entries (want %d)", sc.Overall.F1, sc.Paths.Reused, reused)
	}
}

// oracleScore is the part of a scorecard the image tests read.
type oracleScore struct {
	Resolution string `json:"time_resolution"`
	Paths      struct {
		Reused int `json:"reused_entries"`
	} `json:"paths"`
	Overall struct {
		F1 float64 `json:"f1"`
	} `json:"overall"`
}
