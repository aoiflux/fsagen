package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
)

// featuresGolden is every feature name a release has listed. A name may be
// added, by running the tests with -update; one may not go, as consumers
// test for it instead of for a version.
var featuresGolden = filepath.Join("testdata", "golden", "features.txt")

// fsagen features names what a consumer tests for, by the same names in
// text and JSON, sorted, with the generator version.
func TestFeatures(t *testing.T) {
	code, stdout, stderr := runCLI(t, "features")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	list := strings.Fields(stdout)
	for _, want := range []string{
		"action:timestomp", "field:fn_crtime", "field:history.visits.redirect", "field:history.downloads.url_chain",
		"format:chrome_cookies", "field:cookies.entries.samesite", "playbook:subsecond_jitter",
		"image.fs:ntfs", "image.partition:gpt", "image.ntfs.usn_journal", "model.stomp_changes_ctime",
		"timeline.format:bodyfile", "timeline.source:modelled", "command:diff-oracle",
	} {
		if !slices.Contains(list, want) {
			t.Errorf("no %s", want)
		}
	}
	if !slices.IsSorted(list) {
		t.Error("the list is not sorted")
	}

	code, stdout, stderr = runCLI(t, "features", "--json")
	if code != exitOK {
		t.Fatalf("--json: exit %d: %s", code, stderr)
	}
	var got struct {
		Version          string   `json:"version"`
		GeneratorVersion int      `json:"generator_version"`
		Features         []string `json:"features"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version == "" || got.GeneratorVersion != constant.GeneratorVersion || !slices.Equal(got.Features, list) {
		t.Errorf("--json gives version %q, generator %d and %d features; want the text's %d", got.Version, got.GeneratorVersion, len(got.Features), len(list))
	}
	if code, _, _ := runCLI(t, "features", "extra"); code != exitUsage {
		t.Errorf("an argument: exit %d, want %d", code, exitUsage)
	}
}

// Every field the list names is a key validation accepts on some action:
// the list cannot claim what a run would refuse.
func TestFeatureFieldsAreAccepted(t *testing.T) {
	keys := map[string]bool{"action": true, "mitre": true}
	for _, ks := range compile.Fields {
		for _, k := range ks {
			keys[k] = true
		}
	}
	for _, f := range features() {
		if p, ok := strings.CutPrefix(f, "field:"); ok {
			if top, _, _ := strings.Cut(p, "."); !keys[top] {
				t.Errorf("%s: no action takes %q", f, top)
			}
		}
	}
}

// A feature a release listed stays listed; a new one is recorded.
func TestFeaturesKeepEveryName(t *testing.T) {
	list := features()
	want := strings.Join(list, "\n") + "\n"
	old, err := os.ReadFile(featuresGolden)
	if err != nil && !*update {
		t.Fatalf("%v (run with -update to record the list)", err)
	}
	var gone []string
	for _, f := range strings.Fields(string(old)) {
		if !slices.Contains(list, f) {
			gone = append(gone, f)
		}
	}
	if len(gone) > 0 {
		t.Fatalf("features removed, which breaks every consumer that tests for them: %s", strings.Join(gone, ", "))
	}
	if string(old) == want {
		return
	}
	if !*update {
		t.Fatalf("features were added; run with -update to record them in %s", featuresGolden)
	}
	if err := os.WriteFile(featuresGolden, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
}
