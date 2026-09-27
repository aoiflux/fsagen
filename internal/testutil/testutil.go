// Package testutil holds the helpers shared by fsagen's determinism and golden
// tests.
package testutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/sandbox"
)

// Fingerprint describes every directory, file and named stream under dir, one
// line each, sorted by path:
//
//	d <path>/
//	f <sha256> <size> <path>
//	s <sha256> <size> <path>:<stream>
//
// Two trees with the same fingerprint have the same names, contents and
// streams. Timestamps are deliberately not part of it.
func Fingerprint(dir string) (string, error) {
	fsys, err := sandbox.Open(dir)
	if err != nil {
		return "", err
	}
	defer fsys.Close()

	var lines []string
	addStream := func(name, stream string) error {
		data, err := fsys.ReadStream(name, stream)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("s %s %d %s:%s", sum(data), len(data), name, stream))
		return nil
	}
	addStreams := func(name string) error {
		streams, err := fsys.Streams(name)
		if err != nil {
			return err
		}
		for _, s := range streams {
			if err := addStream(name, s.Name); err != nil {
				return err
			}
		}
		return nil
	}

	err = fsys.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if d.IsDir() {
			lines = append(lines, "d "+name+"/")
			return addStreams(name)
		}
		data, err := fsys.ReadFile(name)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("f %s %d %s", sum(data), len(data), name))
		return addStreams(name)
	})
	if err != nil {
		return "", err
	}
	sort.Slice(lines, func(i, j int) bool { return pathOf(lines[i]) < pathOf(lines[j]) })
	return strings.Join(lines, "\n") + "\n", nil
}

// pathOf is the sort key of a fingerprint line.
//
// KNOWN FLAW: it returns the last space-delimited token rather than the path, so
// a path containing a space sorts under its last segment only, and two such
// paths whose last segments match compare equal under an unstable sort. Fixing
// it means carrying the path beside the line, as runinfo.Sums already does, and
// re-recording the examples goldens on every platform, so it is left for the
// owner to decide rather than changed here.
func pathOf(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// InputHash is the SHA-256 of a YAML input with CR bytes removed, so a CRLF
// checkout hashes the same as an LF one.
func InputHash(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum(bytes.ReplaceAll(data, []byte("\r"), nil))
}

const inputHeader = "# input-sha256 "

// CheckGolden compares got with the golden file at path. The golden records
// the hash of the input that produced it.
//
// With update set it is rewritten, but only if the input changed or the golden
// did not exist yet. Output that changes for an unchanged input means the
// generator's bytes changed, which requires a new GeneratorVersion (and so a
// new golden directory), never an edit of the old one.
func CheckGolden(t testing.TB, path, inputHash, got string, update bool) {
	t.Helper()
	want, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	content := inputHeader + inputHash + "\n" + got

	if exists {
		wantStr := strings.ReplaceAll(string(want), "\r", "")
		if wantStr == content {
			return
		}
		sameInput := strings.HasPrefix(wantStr, inputHeader+inputHash+"\n")
		if !update || sameInput {
			t.Fatalf(goldenMismatch(sameInput)+"\n%s", path, diff(wantStr, content))
		}
	} else if !update {
		t.Skipf("no golden %s yet; run with -update on this platform to record it", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote golden %s", path)
}

// diff lists lines present in only one of a and b; enough to see what moved.
func diff(a, b string) string {
	inA := map[string]bool{}
	for l := range strings.SplitSeq(a, "\n") {
		inA[l] = true
	}
	inB := map[string]bool{}
	for l := range strings.SplitSeq(b, "\n") {
		inB[l] = true
	}
	var out []string
	for l := range inA {
		if !inB[l] {
			out = append(out, "- "+l)
		}
	}
	for l := range inB {
		if !inA[l] {
			out = append(out, "+ "+l)
		}
	}
	sort.Strings(out)
	if len(out) > 40 {
		out = append(out[:40], fmt.Sprintf("... and %d more", len(out)-40))
	}
	return strings.Join(out, "\n")
}

// goldenMismatch says what a difference from the golden means. Output that
// changed for an input that did not means the generator's bytes changed, which
// calls for a new GeneratorVersion rather than an edit of the recorded goldens.
func goldenMismatch(sameInput bool) string {
	if sameInput {
		return "output differs from golden %s for an unchanged input: bump constant.GeneratorVersion rather than editing these goldens"
	}
	return "output differs from golden %s (input changed; rerun with -update)"
}
