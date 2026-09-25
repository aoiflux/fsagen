// Package libgen generates bulk corpora and typed file content.
//
// Bulk generation is planned first and written second. The plan (every
// directory, every file name, every file's random key) is built in one
// sequential pass from the seed; then a bounded pool of workers renders each
// file into memory and writes it through the confined output root. A file's
// bytes depend only on the seed, the bulk start time and its place in the
// plan, never on scheduling, and every worker is waited for, on success and
// on failure alike.
package libgen

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver
	"github.com/jung-kurt/gofpdf"

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/sandbox"
)

// DefaultStart is the default bulk start time: the reference time for the
// dates written inside generated files.
var DefaultStart = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

// Options tune bulk generation.
type Options struct {
	Seed int64
	// Start is the reference time for dates inside the files (log lines,
	// message dates, history visits, archive member times).
	Start time.Time
	// Workers bounds the number of files rendered at once; 0 means one per
	// CPU. It never affects the output.
	Workers int
}

// kind is one type of bulk file. gen renders a file's bytes from its own
// stream; name, when set, replaces the default random name.
type kind struct {
	id   string
	ext  string
	name func(s *prng.Stream) string
	gen  func(s *prng.Stream, start time.Time) ([]byte, error)
}

// kinds is every file type bulk mode writes, once per item in every
// directory, in this order.
var kinds = []kind{
	{id: "txt", ext: constant.TxtExtension, gen: genTxt},
	{id: "docx", ext: constant.DocxExtension, gen: genDocx},
	{id: "png", ext: constant.PngExtension, gen: genPng},
	{id: "pdf", ext: constant.PdfExtension, gen: genPdf},
	{id: "mp4", ext: constant.Mp4Extension, gen: genMp4},
	{id: "csv", ext: constant.CsvExtension, gen: genCsv},
	{id: "json", ext: constant.JsonExtension, gen: genJson},
	{id: "xml", ext: constant.XmlExtension, gen: genXml},
	{id: "html", ext: constant.HtmlExtension, gen: genHtml},
	{id: "log", ext: constant.LogExtension, gen: genLog},
	{id: "reg", ext: constant.RegExtension, gen: genReg},
	{id: "zip", ext: constant.ZipExtension, gen: genZip},
	{id: "exe", ext: constant.ExeExtension, gen: genExe},
	{id: "jsonl", ext: constant.JsonlExtension, gen: genJsonl},
	{id: "syslog", ext: constant.SyslogExtension, gen: genSyslog},
	{id: "md", ext: constant.MdExtension, gen: genMarkdown},
	{id: "eml", ext: constant.EmlExtension, gen: genEml},
	{id: "mbox", ext: constant.MboxExtension, gen: genMbox},
	{id: "chrome-history", ext: constant.DbExtension, gen: genChromeHistory},
	{id: "firefox-places", ext: constant.SqLiteExtension, gen: genFirefoxPlaces,
		name: func(s *prng.Stream) string { return "places_" + s.Text(6) + constant.SqLiteExtension }},
}

// Job is one planned file.
type Job struct {
	Path string // slash-separated, relative to the output root
	kind int
	key  prng.Key
}

// Plan lists the directories (parents first) and files a bulk run with
// limit items per level and the given depth produces. Each of the limit
// directories at a level holds limit files of every kind and, below the
// last level, limit directories of its own.
func Plan(seed int64, limit, depth int) (dirs []string, jobs []Job) {
	root := prng.Root(seed).Derive("bulk")
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		if depth == 0 {
			return
		}
		for index := 0; index < limit; index++ {
			name := root.Derive("dir", parent, strconv.Itoa(index)).Stream().Text(constant.FileNameLen)
			dir := path.Join(parent, fmt.Sprintf("%s_%d", name, index))
			dirs = append(dirs, dir)

			taken := map[string]bool{}
			for i := 0; i < limit; i++ {
				for ki, k := range kinds {
					key := root.Derive("file", dir, k.id, strconv.Itoa(i))
					file := ""
					// A repeated name would overwrite a file; draw again,
					// deterministically, until the name is new.
					for try := 0; file == "" || taken[strings.ToLower(file)]; try++ {
						s := key.Derive("name", strconv.Itoa(try)).Stream()
						if k.name != nil {
							file = k.name(s)
						} else {
							file = s.Text(constant.FileNameLen) + k.ext
						}
					}
					taken[strings.ToLower(file)] = true
					jobs = append(jobs, Job{Path: path.Join(dir, file), kind: ki, key: key})
				}
			}
			walk(dir, depth-1)
		}
	}
	walk("", depth)
	return dirs, jobs
}

// Generate writes a bulk corpus into fsys.
func Generate(fsys *sandbox.FS, limit, depth int, opts Options) error {
	if opts.Start.IsZero() {
		opts.Start = DefaultStart
	}
	dirs, jobs := Plan(opts.Seed, limit, depth)
	for _, d := range dirs {
		if err := fsys.MkdirAll(d, sandbox.DirMode); err != nil {
			return err
		}
	}
	return runJobs(len(jobs), opts.Workers, func(i int) error {
		j := jobs[i]
		data, err := kinds[j.kind].gen(j.key.Derive("content").Stream(), opts.Start.UTC())
		if err != nil {
			return fmt.Errorf("%s: %w", j.Path, err)
		}
		return fsys.WriteFile(j.Path, data, sandbox.FileMode)
	})
}

// runJobs runs do(0..n-1) on at most workers goroutines. After a failure no
// new job starts; every running one is waited for. The error returned is the
// one from the lowest-numbered failing job, so it does not depend on
// scheduling.
func runJobs(n, workers int, do func(int) error) error {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var (
		mu       sync.Mutex
		firstIdx = n
		firstErr error
		next     int
		wg       sync.WaitGroup
	)
	take := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr != nil || next >= n {
			return 0, false
		}
		next++
		return next - 1, true
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i, ok := take()
				if !ok {
					return
				}
				if err := do(i); err != nil {
					mu.Lock()
					if i < firstIdx {
						firstIdx, firstErr = i, err
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func genTxt(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte(s.Text(constant.ContentLen)), nil
}

func genDocx(s *prng.Stream, start time.Time) ([]byte, error) {
	return docx(s.Text(constant.ContentLen), start)
}

var (
	pngOnce sync.Once
	pngData []byte
	pngErr  error
)

// genPng draws the same 500x500 two-tone image every time.
func genPng(_ *prng.Stream, _ time.Time) ([]byte, error) {
	pngOnce.Do(func() {
		const width, height = 500, 500
		img := image.NewRGBA(image.Rect(0, 0, width, height))
		cyan := color.RGBA{100, 200, 200, 0xff}
		for x := 0; x < width; x++ {
			for y := 0; y < height; y++ {
				switch {
				case x < width/2 && y < height/2:
					img.Set(x, y, cyan)
				case x >= width/2 && y >= height/2:
					img.Set(x, y, color.White)
				}
			}
		}
		var buf bytes.Buffer
		pngErr = png.Encode(&buf, img)
		pngData = buf.Bytes()
	})
	return pngData, pngErr
}

func genPdf(s *prng.Stream, start time.Time) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetCatalogSort(true)
	pdf.SetCreationDate(start)
	pdf.SetModificationDate(start)
	pdf.AddPage()
	pdf.SetFont("Arial", "", 12)
	for i := 0; i < 25; i++ {
		pdf.Text(10, 10*float64(i), s.Text(20))
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// genMp4 writes random text under an .mp4 name: a placeholder, not a video
// (a real container is planned).
func genMp4(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte(s.Text(constant.ContentLen)), nil
}

func genCsv(s *prng.Stream, _ time.Time) ([]byte, error) {
	rows := []string{"id,name,value"}
	for i := 0; i < 10; i++ {
		rows = append(rows, fmt.Sprintf("%d,%s,%s", i+1, s.Text(8), s.Text(12)))
	}
	return []byte(strings.Join(rows, "\n") + "\n"), nil
}

func genJson(s *prng.Stream, start time.Time) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"id":%d,"name":"%s","timestamp":"%s"}`, 1, s.Text(8), start.Format(time.RFC3339))), nil
}

func genXml(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte(fmt.Sprintf(`<root><id>%d</id><name>%s</name></root>`, 1, s.Text(8))), nil
}

func genHtml(s *prng.Stream, _ time.Time) ([]byte, error) {
	body := s.Text(64)
	return []byte(fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head><body><p>%s</p></body></html>`, body[:8], body)), nil
}

func genLog(s *prng.Stream, start time.Time) ([]byte, error) {
	lines := make([]string, 0, 50)
	t := start
	for i := 0; i < 50; i++ {
		msg := s.Text(24)
		lines = append(lines, fmt.Sprintf("%s INFO user=%s event=%s", t.Format(time.RFC3339), s.Text(6), msg))
		t = t.Add(time.Minute)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func genReg(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte("Windows Registry Editor Version 5.00\r\n\r\n" +
		fmt.Sprintf("[HKEY_CURRENT_USER\\Software\\Fsagen\\%s]\r\n\"Value\"=\"%s\"\r\n", s.Text(6), s.Text(12))), nil
}

func genZip(s *prng.Stream, start time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 3; i++ {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     fmt.Sprintf("file%d.txt", i+1),
			Method:   zip.Store,
			Modified: start.Add(time.Duration(i) * time.Hour),
		})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(s.Text(32))); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// genExe writes a 256-byte DOS MZ stub: the signature and the DOS-mode
// message, not a loadable PE (a real PE writer is planned).
func genExe(_ *prng.Stream, _ time.Time) ([]byte, error) {
	buf := make([]byte, 256)
	buf[0], buf[1] = 'M', 'Z'
	copy(buf[0x40:], "This program cannot be run in DOS mode.\r\r\n$")
	return buf, nil
}

func genJsonl(s *prng.Stream, start time.Time) ([]byte, error) {
	var b strings.Builder
	t := start
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, `{"ts":"%s","level":"info","user":"%s","msg":"%s"}`+"\n", t.Format(time.RFC3339), s.Text(6), s.Text(18))
		t = t.Add(30 * time.Second)
	}
	return []byte(b.String()), nil
}

func genSyslog(s *prng.Stream, start time.Time) ([]byte, error) {
	lines := make([]string, 0, 50)
	t := start
	for i := 0; i < 50; i++ {
		lines = append(lines, fmt.Sprintf("%s host01 fsagen[%d]: %s", t.Format(time.RFC3339), 1000+i, s.Text(20)))
		t = t.Add(45 * time.Second)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func genMarkdown(s *prng.Stream, _ time.Time) ([]byte, error) {
	title := s.Text(12)
	return []byte(fmt.Sprintf("# %s\n\n%s\n", title, s.Text(80))), nil
}

func genEml(s *prng.Stream, start time.Time) ([]byte, error) {
	date := start.Add(12 * time.Hour).Format(time.RFC1123Z)
	subj := "Test message " + s.Text(6)
	return []byte(fmt.Sprintf("Date: %s\r\nFrom: alice@example.com\r\nTo: bob@example.com\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", date, subj, s.Text(120))), nil
}

func genMbox(s *prng.Stream, start time.Time) ([]byte, error) {
	var b strings.Builder
	base := start.Add(12 * time.Hour)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Hour).Format(time.RFC1123Z)
		subj := fmt.Sprintf("Message %d %s", i+1, s.Text(6))
		body := s.Text(100)
		fmt.Fprintf(&b, "From alice@example.com %s\n", ts)
		fmt.Fprintf(&b, "Date: %s\nFrom: alice@example.com\nTo: bob@example.com\nSubject: %s\n\n%s\n\n", ts, subj, body)
	}
	return []byte(b.String()), nil
}

// buildSQLite creates a database in a private temporary directory outside
// the output root, with no rollback journal, fills it and returns its bytes.
// Nothing but the finished file reaches the output.
func buildSQLite(fill func(db *sql.DB) error) ([]byte, error) {
	dir, err := os.MkdirTemp("", "fsagen-sqlite-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "db.sqlite")

	db, err := sql.Open("sqlite", p)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=OFF"); err != nil {
		db.Close()
		return nil, err
	}
	if err := fill(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func execAll(db *sql.DB, stmts ...string) error {
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// genChromeHistory writes Chrome-style urls and visits tables. The visit
// times are Unix seconds, not Chrome's WebKit epoch; the real schema and
// epoch are planned.
func genChromeHistory(s *prng.Stream, start time.Time) ([]byte, error) {
	return buildSQLite(func(db *sql.DB) error {
		if err := execAll(db,
			`CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)`,
			`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER)`,
		); err != nil {
			return err
		}
		for i := 1; i <= 5; i++ {
			url := fmt.Sprintf("https://example.com/%d/%s", i, s.Text(6))
			title := "Example " + s.Text(6)
			lastVisit := start.Add(-time.Duration(i) * time.Minute).Unix()
			if _, err := db.Exec(`INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time) VALUES(?,?,?,?,?)`, url, title, i*10, i*2, lastVisit); err != nil {
				return err
			}
			if _, err := db.Exec(`INSERT INTO visits(url, visit_time, from_visit, transition) VALUES(?,?,?,?)`, i, lastVisit, 0, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

// genFirefoxPlaces writes Firefox-style moz_places and moz_historyvisits
// tables, with the same epoch caveat as genChromeHistory.
func genFirefoxPlaces(s *prng.Stream, start time.Time) ([]byte, error) {
	return buildSQLite(func(db *sql.DB) error {
		if err := execAll(db,
			`CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER, last_visit_date INTEGER)`,
			`CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, from_visit INTEGER)`,
		); err != nil {
			return err
		}
		for i := 1; i <= 5; i++ {
			url := fmt.Sprintf("https://mozilla.example/%d/%s", i, s.Text(6))
			title := "Mozilla " + s.Text(4)
			lastVisit := start.Add(-time.Duration(i) * time.Minute).Unix()
			if _, err := db.Exec(`INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date) VALUES (?, ?, ?, ?, ?, ?)`, i, url, title, i*3, i%2, lastVisit); err != nil {
				return err
			}
			if _, err := db.Exec(`INSERT INTO moz_historyvisits (id, place_id, visit_date, from_visit) VALUES (?, ?, ?, ?)`, i, i, lastVisit, 0); err != nil {
				return err
			}
		}
		return nil
	})
}
