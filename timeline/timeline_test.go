package timeline

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/sandbox"
)

func csvOf(t *testing.T, root string) string {
	t.Helper()
	tl, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tl.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestTimelineZoneIndependent: the machine's time zone does not reach the
// timeline; every time is written in UTC.
func TestTimelineZoneIndependent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2021, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone("UTC+5", 5*3600)
	east := csvOf(t, root)
	time.Local = time.FixedZone("UTC-7", -7*3600)
	west := csvOf(t, root)

	// Reading a file for its digest no longer moves its access time, so the
	// two timelines are identical, and in UTC.
	if east != west {
		t.Errorf("the time zone changed the timeline:\n%s\n%s", east, west)
	}
	for _, out := range []string{east, west} {
		if strings.Contains(out, "+05:00") || strings.Contains(out, "-07:00") {
			t.Errorf("local time in the timeline:\n%s", out)
		}
		if !strings.Contains(out, "a.txt,1,-rw-rw-rw-,") || !strings.Contains(out, ",2021-06-01T12:00:00Z,") {
			t.Errorf("mtime not written in UTC:\n%s", out)
		}
	}
}

// TestTimelineTieOrder: entries with the same time are ordered by path.
func TestTimelineTieOrder(t *testing.T) {
	when := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	var entries []Entry
	for i := 99; i >= 0; i-- {
		entries = append(entries, Entry{Path: fmt.Sprintf("f%02d", i), Mtime: when})
	}
	entries = append(entries, Entry{Path: "zz-earlier", Mtime: when.Add(-time.Second)})
	sortEntries(entries)
	if entries[0].Path != "zz-earlier" {
		t.Fatalf("first entry %s, want the earliest", entries[0].Path)
	}
	for i := 1; i < len(entries); i++ {
		if want := fmt.Sprintf("f%02d", i-1); entries[i].Path != want {
			t.Fatalf("entry %d is %s, want %s", i, entries[i].Path, want)
		}
	}
}

// TestNoWallClockInTimeline: the text formats carry no generation time.
func TestNoWallClockInTimeline(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tl, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	var txt, macb bytes.Buffer
	if err := tl.WriteTXT(&txt); err != nil {
		t.Fatal(err)
	}
	if err := tl.WriteMACB(&macb); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{txt.String(), macb.String()} {
		if strings.Contains(out, "Generated:") {
			t.Errorf("wall-clock header in:\n%s", out)
		}
	}
}

// TestTimelinePassKeepsAtime: building a timeline reads every file (for its
// digest) and lists every directory, and neither moves an access time. The
// test first shows that an ordinary read does move one on this volume, and
// skips where it does not (last-access updates off, noatime mounts).
func TestTimelinePassKeepsAtime(t *testing.T) {
	root := t.TempDir()
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	names := []string{"d/sub/a.txt", "d/b.txt"}
	for _, n := range names {
		if err := fsys.WriteFile(n, []byte("content of "+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Date(2019, 5, 6, 7, 8, 9, 0, time.UTC)
	all := append(names, "d/sub", "d")
	stamp := func() {
		for _, n := range all {
			if err := fsys.SetTimes(n, sandbox.Times{Atime: old, Mtime: old}); err != nil {
				t.Fatal(err)
			}
		}
	}
	stamp()
	if _, err := os.ReadFile(filepath.Join(root, "d", "b.txt")); err != nil {
		t.Fatal(err)
	}
	if got, _ := fsys.Times("d/b.txt"); got.Atime.Equal(old) {
		t.Skip("this volume does not update access times on read")
	}
	stamp()
	if _, err := Generate(root); err != nil {
		t.Fatal(err)
	}
	for _, n := range all {
		if got, _ := fsys.Times(n); !got.Atime.Equal(old) {
			t.Errorf("%s: the timeline pass moved the access time to %v", n, got.Atime)
		}
	}
}

// TestTimelineListsEveryStream: every named stream is listed, not only a
// few well-known names.
func TestTimelineListsEveryStream(t *testing.T) {
	root := t.TempDir()
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	if !fsys.SupportsStreams() {
		t.Skip("no named streams on this volume")
	}
	if err := fsys.WriteFile("a.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"quill", "Zone.Identifier"} {
		if err := fsys.WriteStream("a.txt", s, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	tl, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tl.Entries {
		if e.Path == "a.txt" {
			if strings.Join(e.ADSNames, ",") != "Zone.Identifier,quill" {
				t.Errorf("streams = %v", e.ADSNames)
			}
			return
		}
	}
	t.Error("a.txt missing from the timeline")
}
