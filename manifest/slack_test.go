package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// TestSlackBytes: each kind fills exactly the rest of the cluster. A canary
// names its object at the start and again at every sector boundary, so it
// survives Windows zeroing the rest of the sector the file ends in; a
// pattern is the marker repeated; a fragment is another file's first bytes,
// then zeros. The same operation always gives the same canary.
func TestSlackBytes(t *testing.T) {
	op := func(kind string) compile.Op {
		return compile.Op{
			Operation: spec.Operation{Slack: &spec.SlackSpec{Kind: kind}},
			Object:    7,
			Random:    5000,
			Rand:      prng.Root(1).Derive("op"),
		}
	}
	marker := []byte("FSAGEN-SLACK:7:")

	canary, err := slackBytes(ExecContext{}, op(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(canary) != 2*4096-5000 {
		t.Fatalf("canary is %d bytes, want the rest of the cluster, %d", len(canary), 2*4096-5000)
	}
	var starts []int
	for i := 0; i < len(canary); i++ {
		if bytes.HasPrefix(canary[i:], marker) {
			starts = append(starts, 5000+i)
		}
	}
	want := []int{5000, 5120, 5632, 6144, 6656, 7168, 7680}
	if fmt.Sprint(starts) != fmt.Sprint(want) {
		t.Errorf("canary markers at file offsets %v, want %v (the slack's start, then every sector boundary)", starts, want)
	}
	again, _ := slackBytes(ExecContext{}, op(""))
	if !bytes.Equal(canary, again) {
		t.Error("the same operation gave two different canaries")
	}

	pattern, _ := slackBytes(ExecContext{}, op(compile.SlackPattern))
	if !bytes.Equal(pattern, bytes.Repeat(marker, len(pattern)/len(marker)+1)[:len(pattern)]) {
		t.Errorf("pattern is not the marker repeated: %q", pattern[:40])
	}

	dir := t.TempDir()
	fsys, err := sandbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	if err := fsys.WriteFile("src.txt", []byte("an earlier file"), 0o644); err != nil {
		t.Fatal(err)
	}
	frag := op(compile.SlackFragment)
	frag.FragmentPath = "src.txt"
	got, err := slackBytes(ExecContext{FS: fsys}, frag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("an earlier file")) || len(bytes.Trim(got[15:], "\x00")) != 0 || len(got) != 2*4096-5000 {
		t.Errorf("fragment slack is %q... (%d bytes), want the source then zeros", got[:20], len(got))
	}
}

// TestSlackOnLiveNTFS: on a live NTFS volume a file with slack keeps exactly
// its content as a file — the size and digest a reader sees are unchanged —
// and the ledger and answer key say where the slack is, what it hashes to,
// and that nothing confirmed it stayed. Reading the bytes back needs the raw
// volume, which TestSlackSurvivesOnRawNTFS in the conformance suite does as
// an administrator. Elsewhere the scenario is refused before anything is
// written.
func TestSlackOnLiveNTFS(t *testing.T) {
	root := t.TempDir()
	probe, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ntfs, cluster := probe.SlackBestEffort(), probe.ClusterSize()
	probe.Close()

	baseDir := t.TempDir()
	body := fmt.Sprintf("start: 2024-03-15T09:00:00Z\noperations:\n  - action: create\n    path: docs/notes.txt\n    content_len: 5000\n    slack: { cluster_size: %d }\n", max(cluster, 4096))
	writeFile(t, baseDir, "manifest.yaml", body)
	res, err := ExecuteFile(compile.ModeManifest, root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if !ntfs {
		if err == nil {
			t.Fatal("a volume that cannot keep slack accepted a slack block")
		}
		t.Skipf("not NTFS here, and the slack block was refused as it should be: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(root, "docs", "notes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 5000 {
		t.Fatalf("the file is %d bytes, want its 5000 bytes of content and nothing more", len(data))
	}
	e := res.Ledger[0]
	if e.Slack == nil {
		t.Fatal("the ledger does not record the slack")
	}
	sum := sha256.Sum256(data)
	if e.SHA256After != hex.EncodeToString(sum[:]) {
		t.Error("the recorded content digest is not the file's")
	}
	c := max(cluster, 4096)
	wantLen := c - 5000%c
	if e.Slack.Offset != 5000 || e.Slack.Length != wantLen || e.Slack.Verified || e.Slack.Kind != "canary" {
		t.Errorf("ledger slack %+v, want offset 5000, length %d, kind canary, not verified", e.Slack, wantLen)
	}
	var fact *ledger.Fact
	for _, f := range res.AnswerKey() {
		if f.Event == ledger.SlackWritten {
			fact = &f
		}
	}
	if fact == nil || fact.Path != "docs/notes.txt" || fact.Slack == nil || fact.Slack.SHA256 != e.Slack.SHA256 {
		t.Errorf("answer key slack fact %+v", fact)
	}
}
