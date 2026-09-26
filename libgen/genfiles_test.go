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
		// Exactly the plan: 2 directories at the top and 2 under each, every
		// one holding 2 files of every kind, plus the profile directories a
		// browser history file brings with it.
		planned, jobs := Plan(int64(run), 2, 2)
		want := map[string]bool{}
		for _, d := range planned {
			want[d] = true
		}
		for _, j := range jobs {
			for q := path.Dir(j.Path); q != "."; q = path.Dir(q) {
				want[q] = true
			}
		}
		if dirs != len(want) || files != 6*2*len(kinds) {
			t.Fatalf("run %d: %d dirs and %d files, want %d and %d", run, dirs, files, len(want), 6*2*len(kinds))
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
	if got := strings.Join(names, ","); got != "[Content_Types].xml,_rels/.rels,word/document.xml,docProps/core.xml,docProps/app.xml" {
		t.Errorf("parts = %s", got)
	}
	// The dates inside the package are what a document-metadata tool reports.
	for _, f := range zr.File {
		if f.Name != "docProps/core.xml" {
			continue
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var core bytes.Buffer
		if _, err := core.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		r.Close()
		want := DefaultStart.Format("2006-01-02T15:04:05Z")
		if !strings.Contains(core.String(), ">"+want+"<") {
			t.Errorf("docProps/core.xml does not carry %s:\n%s", want, core.String())
		}
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

// TestChromeWebKitEpoch: Chrome counts microseconds from 1601-01-01, so a
// visit in 2024 is about 1.3e16, not 1.7e9. Writing Unix seconds here puts
// every visit in the corpus in the year 1601.
func TestChromeWebKitEpoch(t *testing.T) {
	start := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	data, err := genChromeHistory(prng.Root(1).Stream(), start)
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	for i, ts := range queryInts(t, db, "SELECT visit_time FROM visits ORDER BY id") {
		want := start.Add(-time.Duration(i+1)*time.Minute).Unix() + 11644473600
		if ts/1_000_000 != want {
			t.Errorf("visit %d at %d microseconds, want %d seconds since 1601", i+1, ts, want)
		}
	}
	// And the same reading, taken the way a tool takes it.
	for i, secs := range queryInts(t, db, "SELECT (visit_time/1000000)-11644473600 FROM visits ORDER BY id") {
		if want := start.Add(-time.Duration(i+1) * time.Minute); time.Unix(secs, 0).UTC() != want {
			t.Errorf("visit %d reads back as %v, want %v", i+1, time.Unix(secs, 0).UTC(), want)
		}
	}
}

// TestFirefoxPRTime: Firefox counts microseconds from the Unix epoch.
func TestFirefoxPRTime(t *testing.T) {
	start := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	data, err := genFirefoxPlaces(prng.Root(1).Stream(), start)
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	for i, ts := range queryInts(t, db, "SELECT visit_date FROM moz_historyvisits ORDER BY id") {
		if want := start.Add(-time.Duration(i+1) * time.Minute).UnixMicro(); ts != want {
			t.Errorf("visit %d at %d, want %d", i+1, ts, want)
		}
	}
}

// TestStandardHistorySQLReturnsVisits: the query a forensic tool writes
// returns the pages the scenario named, joined through the tables it expects.
func TestStandardHistorySQLReturnsVisits(t *testing.T) {
	start := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	spec := HistorySpec{Visits: []Visit{
		{URL: "https://intranet.example/hr/salaries", Title: "Salaries", Time: start, Transition: "typed"},
		{URL: "https://intranet.example/hr/salaries", Title: "Salaries", Time: start.Add(time.Hour), Transition: "reload"},
		{URL: "https://news.example/", Title: "News", Time: start.Add(2 * time.Hour)},
	}}

	chrome, err := ChromeHistory(spec, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, openDB(t, chrome),
		`SELECT urls.url || " " || urls.visit_count || " " || urls.typed_count FROM urls ORDER BY urls.id`)
	want := []string{"https://intranet.example/hr/salaries 2 1", "https://news.example/ 1 0"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("chrome urls = %v, want %v", got, want)
	}
	if n := queryInts(t, openDB(t, chrome), "SELECT COUNT(*) FROM visits")[0]; n != 3 {
		t.Errorf("%d chrome visits, want 3", n)
	}

	firefox, err := FirefoxPlaces(spec, prng.Root(2).Stream())
	if err != nil {
		t.Fatal(err)
	}
	fdb := openDB(t, firefox)
	got = queryStrings(t, fdb, `SELECT p.url || " " || p.rev_host || " " || p.visit_count FROM moz_places p ORDER BY p.id`)
	want = []string{
		"https://intranet.example/hr/salaries elpmaxe.tenartni. 2",
		"https://news.example/ elpmaxe.swen. 1",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("firefox places = %v, want %v", got, want)
	}
	// visit_type 2 is TYPED and 9 is RELOAD; Chrome numbers them 1 and 8.
	if types := queryInts(t, fdb, "SELECT visit_type FROM moz_historyvisits ORDER BY id"); len(types) != 3 || types[0] != 2 || types[1] != 9 || types[2] != 1 {
		t.Errorf("firefox visit types = %v, want [2 9 1]", types)
	}
	if hosts := queryStrings(t, fdb, "SELECT host FROM moz_origins ORDER BY id"); len(hosts) != 2 {
		t.Errorf("moz_origins = %v, want one row per host", hosts)
	}
}

// TestChromeDownloadsRecorded: a download reaches the tables a tool reads.
func TestChromeDownloadsRecorded(t *testing.T) {
	data, err := genChromeHistory(prng.Root(1).Stream(), DefaultStart)
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	rows := queryStrings(t, db, `SELECT target_path || " " || mime_type || " " || total_bytes FROM downloads`)
	if len(rows) != 1 || !strings.Contains(rows[0], "application/zip 4096") {
		t.Errorf("downloads = %v", rows)
	}
	if chains := queryStrings(t, db, "SELECT url FROM downloads_url_chains"); len(chains) != 1 {
		t.Errorf("downloads_url_chains = %v", chains)
	}
}

func queryInts(t *testing.T, db *sql.DB, query string) []int64 {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func queryStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
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
