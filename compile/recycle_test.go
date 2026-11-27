package compile

import (
	"slices"
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestRecycleBlockRules: a $I file needs its block, takes no filler, is
// named as Windows names one with the deleted file's extension, and every
// value of the block is checked.
func TestRecycleBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	const dir = "    path: '$Recycle.Bin/S-1-5-21-1-2-3-1001/"
	const orig = "original_path: 'C:\\Users\\user1\\report.docx'"
	p := mustLoad(t, ModeManifest, head+dir+"$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { "+orig+", size: 24576 }\n")
	if got := p.Ops[0].Format; got != spec.FormatRecycleBin {
		t.Errorf("format %q, want recycle_bin", got)
	}

	for _, tc := range []struct{ name, body, want string }{
		{"no block", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n", "needs a recycle block"},
		{"filler", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    content_len: 16\n    recycle: { " + orig + " }\n", "no region for filler"},
		{"wrong format", dir + "$IA1B2C3.docx'\n    format: text\n    recycle: { " + orig + " }\n", "only applies with format: recycle_bin"},
		{"no original", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { size: 1 }\n", "original_path is required"},
		{"relative original", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { original_path: 'report.docx' }\n", "not an absolute Windows path"},
		{"negative size", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { " + orig + ", size: -1 }\n", "negative"},
		{"version", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { " + orig + ", version: xp }\n", "version"},
		{"bad time", dir + "$IA1B2C3.docx'\n    format: recycle_bin\n    recycle: { " + orig + ", deleted: soon }\n", "deleted"},
		{"not a $I name", dir + "index.docx'\n    format: recycle_bin\n    recycle: { " + orig + " }\n", "not named as Windows names"},
		{"other extension", dir + "$IA1B2C3.pdf'\n    format: recycle_bin\n    recycle: { " + orig + " }\n", "Windows keeps the original's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}

// TestWipeRules: only a delete wipes, and only a file with one name; the
// pattern and the number of renames are checked.
func TestWipeRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: docs/secret.txt\n    content: hidden\n"
	mustLoad(t, ModeManifest, head+"  - action: delete\n    path: docs/secret.txt\n    wipe: { pattern: random, renames: 3 }\n")
	for _, tc := range []struct{ name, body, want string }{
		{"pattern", "  - action: delete\n    path: docs/secret.txt\n    wipe: { pattern: dod }\n", "pattern"},
		{"too many renames", "  - action: delete\n    path: docs/secret.txt\n    wipe: { renames: 27 }\n", "renames 27"},
		{"not a delete", "  - action: update\n    path: docs/secret.txt\n    wipe: {}\n", "wipe"},
		{"directory", "  - action: delete\n    path: docs/secret.txt\n  - action: delete\n    path: docs\n    wipe: {}\n", "not a file"},
		{"hard link", "  - action: hardlink\n    path: docs/secret.txt\n    new_path: docs/other.txt\n  - action: delete\n    path: docs/secret.txt\n    wipe: {}\n", "has 2 names"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}

func TestWipeNames(t *testing.T) {
	three := 3
	if got, want := WipeNames("secret.txt", &spec.WipeSpec{Renames: &three}), []string{"AAAAAA.AAA", "BBBBBB.BBB", "CCCCCC.CCC"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// A name already of As skips the rename that would change nothing.
	if got := WipeNames("aa", &spec.WipeSpec{Renames: &three}); !slices.Equal(got, []string{"BB", "CC"}) {
		t.Errorf("got %q", got)
	}
	if got := WipeNames("x.bin", &spec.WipeSpec{}); len(got) != MaxWipeRenames || got[25] != "Z.ZZZ" {
		t.Errorf("default: %d names, last %q", len(got), got[len(got)-1])
	}
}
