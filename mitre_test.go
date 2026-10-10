package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/attack"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
)

// taggedManifest is simpleManifest with ATT&CK tags on both operations; the
// second has no id, so its random content would move if the tags were part
// of its identity.
const taggedManifest = "operations:\n  - action: create\n    path: docs/a.txt\n    content: \"hello ${RND:8}\"\n    mtime: 2021-06-01T00:00:00Z\n    mitre: [T1564.004]\n  - action: create\n    path: docs/b.txt\n    content_len: 32\n    mitre: [T1070.006, T1564.004]\n"

// TestMitreLayerWritten: a tagged run writes mitre-layer.json beside the
// answer key, records its digest, tags the answer key and ledger rows, and
// writes exactly the corpus an untagged run writes. An untagged rerun into
// the same records directory removes the layer rather than leaving a stale
// one, and records no digest.
func TestMitreLayerWritten(t *testing.T) {
	dir := t.TempDir()
	tagged := writeYAML(t, dir, "m.yaml", taggedManifest)
	plain := writeYAML(t, dir, "plain.yaml", simpleManifest)
	out, plainOut := filepath.Join(dir, "out"), filepath.Join(dir, "plain")
	meta := out + ".fsagen"

	if code, _, errOut := runCLI(t, "--manifest", tagged, out); code != exitOK {
		t.Fatalf("tagged run: %d %s", code, errOut)
	}
	layer, err := os.ReadFile(filepath.Join(meta, attack.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Name       string `json:"name"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       *int   `json:"score"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(layer, &l); err != nil {
		t.Fatal(err)
	}
	scores := map[string]int{}
	for _, tc := range l.Techniques {
		if tc.Score != nil {
			scores[tc.TechniqueID] = *tc.Score
		}
	}
	if l.Name != "fsagen: m.yaml" || scores["T1564.004"] != 2 || scores["T1070.006"] != 1 {
		t.Errorf("layer %q scores %v", l.Name, scores)
	}
	rm := readManifest(t, meta)
	if rm.Outputs == nil || rm.Outputs.MitreLayer != sha(layer) {
		t.Errorf("run manifest records layer digest %+v, want %s", rm.Outputs, sha(layer))
	}

	key, err := os.ReadFile(filepath.Join(meta, ledger.AnswerKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(key), `"path":"docs/b.txt"`) || !strings.Contains(string(key), `"mitre":["T1070.006","T1564.004"]`) {
		t.Errorf("answer key does not carry the techniques:\n%s", key)
	}

	if code, _, errOut := runCLI(t, "--manifest", plain, plainOut); code != exitOK {
		t.Fatalf("untagged run: %d %s", code, errOut)
	}
	sums := func(meta string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(meta, runinfo.SumsFileName))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if sums(meta) != sums(plainOut+".fsagen") {
		t.Errorf("tagging changed the corpus:\n%s\nvs\n%s", sums(meta), sums(plainOut+".fsagen"))
	}

	// The untagged scenario rerun into the tagged run's records directory.
	if code, _, errOut := runCLI(t, "--manifest", plain, "--clean", "--meta", meta, out); code != exitOK {
		t.Fatalf("rerun: %d %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(meta, attack.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a stale layer survived an untagged rerun: %v", err)
	}
	if rm := readManifest(t, meta); rm.Outputs.MitreLayer != "" {
		t.Errorf("untagged run records a layer digest %q", rm.Outputs.MitreLayer)
	}
}
