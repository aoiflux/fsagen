package timeline

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// Reading a file for its digest moves its access time (fixed in a later
	// phase), so compare the columns that stay put, and require UTC in all.
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
