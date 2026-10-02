package testutil

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestFingerprintSortsByPath pins the sort key against the flaw it used to
// have. The key was recovered from the finished line as its last
// space-delimited token, so a path containing a space sorted under its last
// segment alone, and two such paths whose last segments matched compared equal
// under an unstable sort.
//
// The tree catches both halves. "a b/c" sorted under "b/c", which put it after
// "a/b" instead of before it; "p q/same" and "r q/same" both sorted under
// "q/same", so which came first was left to the sort. Six of fsagen's own
// recorded goldens were wrong in the first way: every
// ".../Chrome/User Data/..." line sorted under "Data/...", which placed it
// above the "Users/" directory containing it.
func TestFingerprintSortsByPath(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"a b/c", "a/b", "p q/same", "r q/same"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}

	var paths []string
	for line := range strings.SplitSeq(strings.TrimSuffix(got, "\n"), "\n") {
		paths = append(paths, pathFrom(t, line))
	}

	// A directory keeps its trailing slash in the key, which is why "a b/"
	// precedes "a b/c" and both precede "a/".
	want := []string{"a b/", "a b/c", "a/", "a/b", "p q/", "p q/same", "r q/", "r q/same"}
	if !slices.Equal(paths, want) {
		t.Errorf("fingerprint order:\n got %q\nwant %q", paths, want)
	}
	if !slices.IsSorted(paths) {
		t.Errorf("fingerprint is not in path order: %q", paths)
	}
}

// pathFrom reads the path back out of a fingerprint line. It is written out
// here rather than shared with Fingerprint so the test does not depend on the
// thing it is checking: a path may contain spaces, so it is the remainder of
// the line and not a field within it.
func pathFrom(t *testing.T, line string) string {
	t.Helper()
	switch {
	case strings.HasPrefix(line, "d "):
		return strings.TrimPrefix(line, "d ")
	case strings.HasPrefix(line, "f "), strings.HasPrefix(line, "s "):
		kindShaSizePath := strings.SplitN(line, " ", 4)
		if len(kindShaSizePath) != 4 {
			t.Fatalf("malformed fingerprint line %q", line)
		}
		return kindShaSizePath[3]
	}
	t.Fatalf("unrecognised fingerprint line %q", line)
	return ""
}
