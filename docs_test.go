package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docFiles are the documents that name tests as evidence for a claim.
// CHANGELOG.md is deliberately not among them: it is a record of what was
// true when each phase landed, so it keeps the names those tests had then.
// The release notes under docs/releases/ are excluded for the same reason —
// each one describes a version that has shipped and does not change with the
// tree.
var docFiles = []string{"README.md", "TIMELINE_FEATURE.md", filepath.Join("docs", "testing.md")}

var (
	citedTest = regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")
	declTest  = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
)

// TestDocumentedTestsExist: the documentation answers "how do you know?" by
// naming a test, which is worth nothing once the test is renamed or deleted.
// Every name the documents cite has to be a test that still exists.
func TestDocumentedTestsExist(t *testing.T) {
	have := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".codegraph", "testdata", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range declTest.FindAllSubmatch(src, -1) {
			have[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(have) < 100 {
		t.Fatalf("only found %d tests in the tree; the walk is wrong", len(have))
	}

	for _, doc := range docFiles {
		text, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		var missing []string
		seen := map[string]bool{}
		for _, m := range citedTest.FindAllStringSubmatch(string(text), -1) {
			name := m[1]
			if have[name] || seen[name] {
				continue
			}
			seen[name] = true
			missing = append(missing, name)
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s names tests that do not exist: %s", doc, strings.Join(missing, ", "))
		}
	}
}

// TestEveryFindingHasARow: docs/testing.md is the index of what closes each
// finding in the audit brief, so a finding missing from it is a claim nobody
// has to answer for.
func TestEveryFindingHasARow(t *testing.T) {
	brief, err := os.ReadFile("plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("docs", "testing.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := regexp.MustCompile(`"id":\s*"((?:F-[A-Z]+|CR)-\d+)"`)
	seen := map[string]bool{}
	var missing []string
	for _, m := range ids.FindAllSubmatch(brief, -1) {
		id := string(m[1])
		if seen[id] {
			continue
		}
		seen[id] = true
		if !strings.Contains(string(doc), "| "+id+" |") {
			missing = append(missing, id)
		}
	}
	if len(seen) < 60 {
		t.Fatalf("only found %d ids in plan.json", len(seen))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("docs/testing.md has no row for %s", strings.Join(missing, ", "))
	}
}
