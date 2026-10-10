package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/volume/container"
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
		if !c.BirthTime || !c.ChangeTime || c.Hardlinks || c.Symlinks || c.Junctions || c.NamedStreams || c.Slack != "none" || c.ClusterSize != 4096 {
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
		for _, want := range []string{`"type":"ntfs_mft_record"`, `"seq":2`, `"overwritten":true`, `"cause":"overwrite"`, `"kind":"dir"`} {
			if !strings.Contains(got, want) {
				t.Errorf("the golden lacks %s:\n%s", want, got)
			}
		}
	}
}

// diff-oracle scores fsagen's own observed timeline of an NTFS image at
// 1.0 with no tolerance at all: every name and every time, to 100 ns, is
// on disk as the scenario intends.
func TestNTFSObservedTimelineTo100ns(t *testing.T) {
	dir := t.TempDir()
	tl := filepath.Join(dir, "observed.jsonl")
	img := ntfsImage(t, "--timeline", tl)
	if code, stdout, stderr := runOracle(t, "--meta", img+metaDirSuffix, "--categories", "files,times", "--time-tolerance", "0", "--fail-under", "1", tl); code != exitOK {
		t.Fatalf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
	if r := readManifest(t, img+metaDirSuffix).Capabilities.TimeResolution; r == nil || *r != (runinfo.Resolution{Atime: "100ns", Mtime: "100ns", Ctime: "100ns", Crtime: "100ns"}) {
		t.Errorf("time resolution %+v", r)
	}
}

// What NTFS images cannot hold yet is refused before anything is written:
// links, streams and slack, a timestomp's $FILE_NAME times, NTFS's own
// names at the root in any case, and names Windows forbids.
func TestNTFSRefusesWhatItCannotHold(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "x.img")
	for _, c := range []struct{ ops, want string }{
		{"  - action: create\n    path: a.txt\n  - action: hardlink\n    path: a.txt\n    new_path: b.txt\n", "hard link"},
		{"  - action: symlink\n    path: l\n    target: a.txt\n    target_type: file\n", "symlink"},
		{"  - action: create\n    path: a.txt\n  - action: ads\n    path: a.txt\n    stream: s\n    content: x\n", "alternate data stream"},
		{"  - action: create\n    path: a.txt\n    content_len: 5000\n    slack: {kind: canary, cluster_size: 4096}\n", "FAT32 or ext4"},
		{"  - action: create\n    path: a.txt\n  - action: timestomp\n    path: a.txt\n    fn_mtime: 2020-01-01T00:00:00Z\n", "$FILE_NAME"},
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
	n := 0
	for _, f := range readFacts(t, key) {
		if f.Residue == nil || f.Residue.Entry == nil || f.Residue.Entry.Overwritten {
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
	if code, stdout, stderr := runOracle(t, "--meta", img+metaDirSuffix, "--fail-under", "1", body); code != exitOK {
		t.Errorf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
}
