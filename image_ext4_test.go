package main

import (
	"encoding/json"
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

// ext4Fixture is the scenario TestExt4ImageGolden pins.
var ext4Fixture = filepath.Join("testdata", "image", "ext4.yaml")

// ext4Image writes the ext4 fixture into a raw image with an MBR, and
// returns the image.
func ext4Image(t *testing.T, extra ...string) string {
	t.Helper()
	img := filepath.Join(t.TempDir(), "evidence.img")
	args := append([]string{"--seed", "1", "--manifest", ext4Fixture, "--image", img, "--image-fs", "ext4", "--image-size", "64M"}, extra...)
	if code, _, stderr := runCLI(t, args...); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	return img
}

// The ext4 fixture makes one image, byte for byte, on every platform: its
// digest, the residue its writes left, and its SHA256SUMS are pinned. The
// image reads back as the scenario intends (the run verifies every time
// through fsagen's ext4 reader), and a second run makes the same bytes.
func TestExt4ImageGolden(t *testing.T) {
	var first string
	for i := range 2 {
		img := ext4Image(t, "--image-label", "evidence", "--image-time", "2023-03-01T00:00:00Z")
		meta := img + metaDirSuffix
		rm := readManifest(t, meta)
		if rm.Image == nil || rm.Image.FS != "ext4" || rm.Image.ClusterSize != 4096 || rm.Image.Label != "evidence" || rm.Image.UUID == "" || rm.Image.Serial != "" || rm.Image.TimeZone != "" {
			t.Fatalf("run manifest image %+v", rm.Image)
		}
		c := rm.Capabilities
		if !c.BirthTime || !c.ChangeTime || !c.Hardlinks || !c.Symlinks || c.Junctions || c.NamedStreams || c.Slack != "exact" || c.ClusterSize != 4096 {
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
			if strings.Contains(line, `"event":"residue"`) || strings.Contains(line, `"event":"slack"`) {
				b.WriteString(line + "\n")
			}
		}
		b.WriteString(strings.ReplaceAll(string(sums), "\r", ""))
		got := b.String()
		if i == 0 {
			first = got
			testutil.CheckGolden(t, filepath.Join("testdata", "golden", "image", "ext4.txt"), testutil.InputHash(t, ext4Fixture), got, *update)
		} else if got != first {
			t.Error("a second run made a different image")
		}
		for _, want := range []string{`"verified":true`, `"type":"ext4_inode"`, `"deleted":"2023-03-02T09:01:10Z"`, `"overwritten":true`, `"cause":"overwrite"`} {
			if !strings.Contains(got, want) {
				t.Errorf("the golden lacks %s:\n%s", want, got)
			}
		}
	}
}

// diff-oracle scores fsagen's own observed timeline of an ext4 image at
// 1.0 with no tolerance at all: every name and every time, to the
// nanosecond, past 2038 too, is on disk as the scenario intends.
func TestExt4ObservedTimelineToTheNanosecond(t *testing.T) {
	dir := t.TempDir()
	tl := filepath.Join(dir, "observed.jsonl")
	img := ext4Image(t, "--timeline", tl)
	if code, stdout, stderr := runOracle(t, "--meta", img+metaDirSuffix, "--categories", "files,times,links", "--time-tolerance", "0", "--fail-under", "1", tl); code != exitOK {
		t.Fatalf("diff-oracle exit %d:\n%s%s", code, stdout, stderr)
	}
	if r := readManifest(t, img+metaDirSuffix).Capabilities.TimeResolution; r == nil || *r != (runinfo.Resolution{Atime: "1ns", Mtime: "1ns", Ctime: "1ns", Crtime: "1ns"}) {
		t.Errorf("time resolution %+v", r)
	}
}

// partition copies the file system out of an image with an MBR, for tools
// that take no offset.
func partition(t *testing.T, img string) string {
	t.Helper()
	data, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(filepath.Dir(img), "part.img")
	if err := os.WriteFile(part, data[container.MBRStart*512:], 0o644); err != nil {
		t.Fatal(err)
	}
	return part
}

// e2fsck, where e2fsprogs is installed, finds nothing wrong with an image
// fsagen wrote: not its superblocks, descriptors or bitmaps, its inodes and
// extent trees, its directories with their wiped entries, or its counts.
func TestExt4CheckedByE2fsck(t *testing.T) {
	e2fsck, err := exec.LookPath("e2fsck")
	if err != nil {
		t.Skip("e2fsck (e2fsprogs) is not installed")
	}
	part := partition(t, ext4Image(t))
	if out, err := exec.Command(e2fsck, "-f", "-n", part).CombinedOutput(); err != nil {
		t.Fatalf("e2fsck: %v\n%s", err, out)
	}
}

// The Sleuth Kit, where it is installed, lists every file fsagen wrote,
// and every deleted inode the answer key names as an orphan, by number;
// and diff-oracle scores its bodyfile at 1.0.
func TestExt4ListedByTSK(t *testing.T) {
	fls, err := exec.LookPath("fls")
	if err != nil {
		t.Skip("fls (The Sleuth Kit) is not installed")
	}
	img := ext4Image(t)
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
		ino := f.Residue.Entry.Number
		if !strings.Contains(listing, fmt.Sprintf(" * %d:\t$OrphanFiles/OrphanFile-%d\n", ino, ino)) {
			t.Errorf("fls lists no orphan inode %d (%s)", ino, f.Path)
		}
		n++
	}
	if n == 0 {
		t.Error("no deleted inode was checked")
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

// readFacts reads answer-key lines.
func readFacts(t *testing.T, data []byte) []ledger.Fact {
	t.Helper()
	var facts []ledger.Fact
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var f ledger.Fact
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	return facts
}
