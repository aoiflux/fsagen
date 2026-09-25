package libgen

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/sandbox"
)

func openFS(t *testing.T, dir string) *sandbox.FS {
	t.Helper()
	fsys, err := sandbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })
	return fsys
}

func bulk(t *testing.T, seed int64, limit, depth int, opts Options) string {
	t.Helper()
	dir := t.TempDir()
	opts.Seed = seed
	if err := Generate(openFS(t, dir), limit, depth, opts); err != nil {
		t.Fatal(err)
	}
	fp, err := testutil.Fingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// TestBulkDeterministic: the same seed gives the same names and bytes run
// after run, however the workers are scheduled; another seed does not.
func TestBulkDeterministic(t *testing.T) {
	want := bulk(t, 7, 2, 2, Options{})
	if again := bulk(t, 7, 2, 2, Options{Workers: 1}); again != want {
		t.Fatalf("one worker and many gave different corpora")
	}
	runs := 20
	if testing.Short() {
		runs = 3
	}
	small := bulk(t, 7, 1, 2, Options{})
	for i := 0; i < runs; i++ {
		if got := bulk(t, 7, 1, 2, Options{Workers: 1 + i%8}); got != small {
			t.Fatalf("run %d differs from run 0", i+1)
		}
	}
	if bulk(t, 8, 1, 2, Options{}) == small {
		t.Error("a different seed produced the same corpus")
	}
}

// TestBulkNoJournalExactCounts: every planned file is written, nothing else
// is (no SQLite journals), and the count is what the plan says.
func TestBulkNoJournalExactCounts(t *testing.T) {
	for run := 0; run < 5; run++ {
		dir := t.TempDir()
		if err := Generate(openFS(t, dir), 2, 2, Options{Seed: int64(run)}); err != nil {
			t.Fatal(err)
		}
		var files, dirs int
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case p == dir:
			case d.IsDir():
				dirs++
			default:
				files++
				if strings.Contains(d.Name(), "-journal") || strings.Contains(d.Name(), "-wal") {
					t.Errorf("stray SQLite file %s", p)
				}
			}
			return nil
		})
		// 2 directories at the top, 2 under each: 6, each holding 2 of
		// every kind.
		if dirs != 6 || files != 6*2*len(kinds) {
			t.Fatalf("run %d: %d dirs and %d files, want 6 and %d", run, dirs, files, 6*2*len(kinds))
		}
	}
}

// TestBulkStartMovesDates: the dates inside the files come from the bulk
// start, never the wall clock.
func TestBulkStartMovesDates(t *testing.T) {
	a := bulk(t, 1, 1, 1, Options{})
	b := bulk(t, 1, 1, 1, Options{Start: DefaultStart})
	c := bulk(t, 1, 1, 1, Options{Start: DefaultStart.Add(time.Hour)})
	if a != b {
		t.Error("the default start is not DefaultStart")
	}
	if a == c {
		t.Error("moving the start changed no file")
	}
}

// TestBulkErrorReturnedNoLeak: a failing file is reported once, naming the
// first failing file in plan order, and no goroutine outlives the call.
func TestBulkErrorReturnedNoLeak(t *testing.T) {
	saved := kinds
	t.Cleanup(func() { kinds = saved })
	kinds = append([]kind(nil), saved...)
	boom := errors.New("boom")
	for i := range kinds {
		if kinds[i].id == "png" {
			kinds[i].gen = func(*prng.Stream, time.Time) ([]byte, error) { return nil, boom }
		}
	}

	before := runtime.NumGoroutine()
	_, jobs := Plan(3, 3, 1)
	firstPng := ""
	for _, j := range jobs {
		if kinds[j.kind].id == "png" {
			firstPng = j.Path
			break
		}
	}
	err := Generate(openFS(t, t.TempDir()), 3, 1, Options{Seed: 3})
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), firstPng+":") {
		t.Fatalf("err = %v, want boom at %s", err, firstPng)
	}
	for i := 0; i < 50 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("%d goroutines after the call, %d before", n, before)
	}
}

// TestPngMp4UnwritableDirOneError: a file that cannot be written is one
// error, not a panic or a hang.
func TestPngMp4UnwritableDirOneError(t *testing.T) {
	dir := t.TempDir()
	_, jobs := Plan(5, 1, 1)
	var blocked []string
	for _, j := range jobs {
		if id := kinds[j.kind].id; id == "png" || id == "mp4" {
			// A directory where the file should go makes the write fail.
			blocked = append(blocked, j.Path)
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(j.Path), "x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	err := Generate(openFS(t, dir), 1, 1, Options{Seed: 5})
	if err == nil {
		t.Fatal("writing over a directory succeeded")
	}
	if !strings.Contains(err.Error(), path.Base(blocked[0])) && !strings.Contains(err.Error(), path.Base(blocked[1])) {
		t.Errorf("err = %v, want it to name %v", err, blocked)
	}
}

func TestPlanNamesAreUniquePerDirectory(t *testing.T) {
	_, jobs := Plan(1, 3, 2)
	seen := map[string]bool{}
	for _, j := range jobs {
		k := strings.ToLower(j.Path)
		if seen[k] {
			t.Fatalf("duplicate path %s", j.Path)
		}
		seen[k] = true
	}
}

func TestDocxOpensWithParts(t *testing.T) {
	data, err := genDocx(prng.Root(1).Stream(), DefaultStart)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.Method != zip.Store || !f.Modified.Equal(DefaultStart) {
			t.Errorf("%s: method %d, modified %v", f.Name, f.Method, f.Modified)
		}
	}
	if got := strings.Join(names, ","); got != "[Content_Types].xml,_rels/.rels,word/document.xml" {
		t.Errorf("parts = %s", got)
	}
}

func openDB(t *testing.T, data []byte) *sql.DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.db")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBrowserHistoryTables(t *testing.T) {
	for _, tc := range []struct {
		gen    func(*prng.Stream, time.Time) ([]byte, error)
		tables []string
	}{
		{genChromeHistory, []string{"urls", "visits"}},
		{genFirefoxPlaces, []string{"moz_places", "moz_historyvisits"}},
	} {
		data, err := tc.gen(prng.Root(1).Stream(), DefaultStart)
		if err != nil {
			t.Fatal(err)
		}
		db := openDB(t, data)
		var check string
		if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
			t.Errorf("integrity_check = %q, %v", check, err)
		}
		for _, table := range tc.tables {
			var n int
			if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 5 {
				t.Errorf("%s: %d rows, %v", table, n, err)
			}
		}
	}
}

// TestBrowserHistoryTimestamps: visit times are counted back from the bulk
// start, one minute apart. They are Unix seconds, not the browsers' own
// epochs; the real encodings are planned.
func TestBrowserHistoryTimestamps(t *testing.T) {
	start := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	for _, tc := range []struct {
		gen   func(*prng.Stream, time.Time) ([]byte, error)
		query string
	}{
		{genChromeHistory, "SELECT last_visit_time FROM urls ORDER BY id"},
		{genFirefoxPlaces, "SELECT last_visit_date FROM moz_places ORDER BY id"},
	} {
		data, err := tc.gen(prng.Root(1).Stream(), start)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := openDB(t, data).Query(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		i := 1
		for rows.Next() {
			var ts int64
			if err := rows.Scan(&ts); err != nil {
				t.Fatal(err)
			}
			if want := start.Add(-time.Duration(i) * time.Minute).Unix(); ts != want {
				t.Errorf("%s row %d = %d, want %d", tc.query, i, ts, want)
			}
			i++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
}

// TestSQLiteDeterministic: the database bytes depend only on the stream.
func TestSQLiteDeterministic(t *testing.T) {
	a, err := genChromeHistory(prng.Root(4).Stream(), DefaultStart)
	if err != nil {
		t.Fatal(err)
	}
	b, err := genChromeHistory(prng.Root(4).Stream(), DefaultStart)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two identical SQLite builds differ")
	}
}
