package attack

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/fsagen/ledger"
)

var update = flag.Bool("update", false, "rewrite testdata/layer.json")

func sampleEntries() []ledger.Entry {
	return []ledger.Entry{
		{N: 1, Path: "home/a.txt", Outcome: ledger.Done, Mitre: []string{"T1070.006", "T1564.004"}},
		{N: 2, Path: "home/a.txt", NewPath: "home/b.txt", Outcome: ledger.Done, Mitre: []string{"T1036"}},
		{N: 3, Path: "home/c.txt", Outcome: ledger.Done},
		{N: 4, Path: "home/b.txt", Outcome: ledger.Done, Mitre: []string{"T1070.006", "T1070"}},
		// Skipped and no-op operations left no evidence, so they score nothing.
		{N: 5, Path: "home/d.txt", Outcome: ledger.Skipped, Mitre: []string{"T1027"}},
		{N: 6, Path: "home/e.txt", Outcome: ledger.NoOp, Mitre: []string{"T1070.006"}},
	}
}

// TestLayerGolden pins the layer's bytes for a fixed ledger: technique order,
// scores, comments, the unscored parent that unfolds a sub-technique, and
// field order.
func TestLayerGolden(t *testing.T) {
	got, err := Layer("fsagen: sample.yaml", sampleEntries(), [][2]string{{"generator_version", "6"}, {"seed", "42"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "layer.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to record it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("layer differs from %s:\n%s", path, got)
	}
}

// TestLayerContent checks the layer's meaning rather than its bytes: what is
// scored, by how much, and what Navigator needs to load it.
func TestLayerContent(t *testing.T) {
	data, err := Layer("x", sampleEntries(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Versions   map[string]string `json:"versions"`
		Domain     string            `json:"domain"`
		Techniques []struct {
			TechniqueID       string `json:"techniqueID"`
			Score             *int   `json:"score"`
			ShowSubtechniques bool   `json:"showSubtechniques"`
		} `json:"techniques"`
		Gradient struct {
			MaxValue int `json:"maxValue"`
		} `json:"gradient"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	if l.Versions["layer"] != LayerVersion || l.Domain != "enterprise-attack" {
		t.Errorf("versions %v, domain %q", l.Versions, l.Domain)
	}
	type row struct {
		score  int
		scored bool
		unfold bool
	}
	got := map[string]row{}
	var order []string
	for _, tc := range l.Techniques {
		r := row{unfold: tc.ShowSubtechniques}
		if tc.Score != nil {
			r.score, r.scored = *tc.Score, true
		}
		got[tc.TechniqueID] = r
		order = append(order, tc.TechniqueID)
	}
	want := map[string]row{
		"T1036":     {1, true, false},
		"T1070":     {1, true, true}, // tagged itself, and has a tagged sub-technique
		"T1070.006": {2, true, false},
		"T1564":     {0, false, true}, // only there to unfold T1564.004
		"T1564.004": {1, true, false},
	}
	if len(got) != len(want) {
		t.Errorf("techniques %v, want %d", order, len(want))
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %+v, want %+v", id, got[id], w)
		}
	}
	if _, ok := got["T1027"]; ok {
		t.Error("a skipped operation's technique is in the layer")
	}
	if l.Gradient.MaxValue != 2 {
		t.Errorf("gradient max = %d, want 2", l.Gradient.MaxValue)
	}
}

// TestTagged: only an operation that ran makes a run tagged.
func TestTagged(t *testing.T) {
	if !Tagged(sampleEntries()) {
		t.Error("sample not tagged")
	}
	if Tagged([]ledger.Entry{{Outcome: ledger.Skipped, Mitre: []string{"T1070"}}, {Outcome: ledger.Done}}) {
		t.Error("a skipped tagged operation made the run tagged")
	}
}
