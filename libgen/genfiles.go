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
	"database/sql"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/email"
	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
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
	{id: "png", ext: constant.PngExtension, gen: genPNG},
	{id: "jpg", ext: constant.JpgExtension, gen: genJPEG},
	{id: "pdf", ext: constant.PdfExtension, gen: genPdf},
	{id: "mp4", ext: constant.MP4Extension, gen: genMP4},
	{id: "csv", ext: constant.CsvExtension, gen: genCsv},
	{id: "json", ext: constant.JSONExtension, gen: genJSON},
	{id: "xml", ext: constant.XMLExtension, gen: genXML},
	{id: "html", ext: constant.HTMLExtension, gen: genHTML},
	{id: "log", ext: constant.LogExtension, gen: genLog},
	{id: "reg", ext: constant.RegExtension, gen: genReg},
	{id: "zip", ext: constant.ZipExtension, gen: genZip},
	{id: "exe", ext: constant.ExeExtension, gen: genExe},
	{id: "jsonl", ext: constant.JSONLExtension, gen: genJSONL},
	{id: "syslog", ext: constant.SyslogExtension, gen: genSyslog},
	{id: "md", ext: constant.MdExtension, gen: genMarkdown},
	{id: "eml", ext: constant.EmlExtension, gen: genEml},
	{id: "mbox", ext: constant.MboxExtension, gen: genMbox},
	// The browser profiles keep the names a tool looks for; the profile
	// directory invented around each one keeps them apart.
	{id: "chrome-history", ext: constant.DBExtension, gen: genChromeHistory,
		name: func(s *prng.Stream) string { return "Chrome-" + s.Text(6) + "/Default/History" }},
	{id: "firefox-places", ext: constant.SQLiteExtension, gen: genFirefoxPlaces,
		name: func(s *prng.Stream) string {
			return "Firefox-" + s.Text(6) + "/Profiles/" + s.Text(8) + ".default-release/places" + constant.SQLiteExtension
		}},
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
	p := &planner{root: prng.Root(seed).Derive("bulk"), limit: limit}
	p.level("", depth)
	return p.dirs, p.jobs
}

// planner builds a bulk plan from the seed alone. Every name and key comes from
// the plan's own position in the tree, so the same seed and shape always give
// the same corpus.
type planner struct {
	root  prng.Key
	limit int
	dirs  []string
	jobs  []Job
}

// level plans the directories at one level and everything beneath them.
func (p *planner) level(parent string, depth int) {
	if depth == 0 {
		return
	}
	for index := 0; index < p.limit; index++ {
		dir := p.dirName(parent, index)
		p.dirs = append(p.dirs, dir)
		p.files(dir)
		p.level(dir, depth-1)
	}
}

// dirName is the name of one directory, drawn from its parent and its position
// so that what else the plan holds cannot change it.
func (p *planner) dirName(parent string, index int) string {
	name := p.root.Derive("dir", parent, strconv.Itoa(index)).Stream().Text(constant.FileNameLen)
	return path.Join(parent, fmt.Sprintf("%s_%d", name, index))
}

// files plans limit files of every kind in one directory.
func (p *planner) files(dir string) {
	taken := map[string]bool{}
	for i := 0; i < p.limit; i++ {
		for ki, k := range kinds {
			key := p.root.Derive("file", dir, k.id, strconv.Itoa(i))
			p.jobs = append(p.jobs, Job{Path: path.Join(dir, uniqueName(k, key, taken)), kind: ki, key: key})
		}
	}
}

// uniqueName draws a name for one file. A repeated name would overwrite a file
// already planned, so the draw repeats, deterministically, until it is new.
func uniqueName(k kind, key prng.Key, taken map[string]bool) string {
	for try := 0; ; try++ {
		file := k.fileName(key.Derive("name", strconv.Itoa(try)).Stream())
		if file == "" || taken[strings.ToLower(file)] {
			continue
		}
		taken[strings.ToLower(file)] = true
		return file
	}
}

// fileName draws a name for a file of this kind: the kind's own naming when it
// has one (a browser profile keeps the names a tool looks for), else a random
// name with the kind's extension.
func (k kind) fileName(s *prng.Stream) string {
	if k.name != nil {
		return k.name(s)
	}
	return s.Text(constant.FileNameLen) + k.ext
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

// runJobs runs do(0..n-1) on at most workers goroutines. Jobs are handed out in
// order, so once one has failed nothing still unstarted can be an earlier
// failure and the queue stops; every job already running is waited for. The
// error returned is therefore the one from the lowest-numbered failing job,
// whatever order the workers happened to run in.
func runJobs(n, workers int, do func(int) error) error {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	q := &jobQueue{do: do, n: n, firstIdx: n}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.work()
		}()
	}
	wg.Wait()
	return q.firstErr
}

// jobQueue hands out job numbers in order and remembers the first failure.
type jobQueue struct {
	do func(int) error
	n  int

	mu sync.Mutex
	// next is the next job to hand out.
	next int
	// firstIdx is the lowest-numbered job that has failed and firstErr its
	// error. firstIdx starts past every job, so nothing has failed yet.
	firstIdx int
	firstErr error
}

// work runs jobs until none are left worth starting.
func (q *jobQueue) work() {
	for {
		i, ok := q.take()
		if !ok {
			return
		}
		if err := q.do(i); err != nil {
			q.fail(i, err)
		}
	}
}

// take is the next job to run, if one is still worth running.
func (q *jobQueue) take() (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.next >= q.n || q.next >= q.firstIdx {
		return 0, false
	}
	q.next++
	return q.next - 1, true
}

// fail records a failure, keeping the lowest-numbered one.
func (q *jobQueue) fail(i int, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if i < q.firstIdx {
		q.firstIdx, q.firstErr = i, err
	}
}

func genTxt(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte(s.Text(constant.ContentLen)), nil
}

func genDocx(s *prng.Stream, start time.Time) ([]byte, error) {
	return Docx(s.Text(constant.ContentLen), DocxMeta{Author: "fsagen", Created: start, Modified: start})
}

func genPNG(s *prng.Stream, _ time.Time) ([]byte, error) {
	return PNG(DefaultImageSize, DefaultImageSize, s, nil)
}

func genJPEG(s *prng.Stream, _ time.Time) ([]byte, error) {
	return JPEG(DefaultImageSize, DefaultImageSize, s, nil)
}

// genPdf renders through RenderPDF, the same paginating renderer the pdf
// format uses, so a bulk .pdf gets margins, wrapped text, a sorted catalog and
// a checked pdf.Err(). What it replaced placed 25 runs at fixed coordinates,
// the first of them at y=0 -- above the top of the page, and so invisible.
func genPdf(s *prng.Stream, start time.Time) ([]byte, error) {
	var b strings.Builder
	for range bulkPdfParagraphs {
		b.WriteString(s.Text(bulkTextLen))
		b.WriteString("\n\n")
	}
	return RenderPDF(b.String(), PDFMeta{Author: "fsagen", Created: start, Modified: start})
}

func genMP4(s *prng.Stream, start time.Time) ([]byte, error) {
	return MP4(start, 3*time.Second, 320, 240, s.Bytes(4096)), nil
}

func genCsv(s *prng.Stream, _ time.Time) ([]byte, error) {
	rows := []string{"id,name,value"}
	for i := 0; i < 10; i++ {
		rows = append(rows, fmt.Sprintf("%d,%s,%s", i+1, s.Text(8), s.Text(12)))
	}
	return []byte(strings.Join(rows, "\n") + "\n"), nil
}

func genJSON(s *prng.Stream, start time.Time) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"id":%d,"name":"%s","timestamp":"%s"}`, 1, s.Text(8), start.Format(time.RFC3339))), nil
}

func genXML(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte(fmt.Sprintf(`<root><id>%d</id><name>%s</name></root>`, 1, s.Text(8))), nil
}

func genHTML(s *prng.Stream, _ time.Time) ([]byte, error) {
	body := s.Text(64)
	return []byte(fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head><body><p>%s</p></body></html>`, body[:8], body)), nil
}

// How much of each shape a bulk file carries. They are named together because
// they are arbitrary: nothing reads them back, they only have to be stable.
const (
	// bulkLogLines is how many lines each of the log-shaped kinds carries.
	bulkLogLines = 50
	// bulkPdfParagraphs is how many paragraphs of bulkTextLen a bulk pdf holds.
	bulkPdfParagraphs = 25
	// bulkTextLen is the length of one invented run of text.
	bulkTextLen = 20
	// bulkMboxMessages is how many messages a bulk mbox accumulates.
	bulkMboxMessages = 3
	// bulkEmailBodyLen is the body length of one generated message.
	bulkEmailBodyLen = 120
	// bulkEmailOffset puts a message partway into the day the corpus starts on,
	// so its date is not the same instant as the files around it.
	bulkEmailOffset = 12 * time.Hour
)

// timestampedLines is the body the three log-shaped kinds share: bulkLogLines
// lines, one per step from start, each newline-terminated. They differed only
// in the step, the line format, and whether they joined a slice or appended to
// a builder -- which came to the same bytes.
func timestampedLines(start time.Time, step time.Duration, line func(i int, t time.Time) string) []byte {
	var b strings.Builder
	t := start
	for i := range bulkLogLines {
		b.WriteString(line(i, t))
		b.WriteByte('\n')
		t = t.Add(step)
	}
	return []byte(b.String())
}

func genLog(s *prng.Stream, start time.Time) ([]byte, error) {
	return timestampedLines(start, time.Minute, func(_ int, t time.Time) string {
		// The event is drawn before the user, which is not the order the two
		// are printed in. The stream decides the bytes, so the draws stay in
		// the order they were already in.
		event := s.Text(24)
		return fmt.Sprintf("%s INFO user=%s event=%s", t.Format(time.RFC3339), s.Text(6), event)
	}), nil
}

func genReg(s *prng.Stream, _ time.Time) ([]byte, error) {
	return []byte("Windows Registry Editor Version 5.00\r\n\r\n" +
		fmt.Sprintf("[HKEY_CURRENT_USER\\Software\\Fsagen\\%s]\r\n\"Value\"=\"%s\"\r\n", s.Text(6), s.Text(12))), nil
}

func genZip(s *prng.Stream, start time.Time) ([]byte, error) {
	var entries []ZipEntry
	for i := 0; i < 3; i++ {
		entries = append(entries, ZipEntry{
			Name:     fmt.Sprintf("file%d.txt", i+1),
			Data:     []byte(s.Text(32)),
			Modified: start.Add(time.Duration(i) * time.Hour),
		})
	}
	return BuildZip(entries, "")
}

// genExe writes a real PE: headers, sections of filler, an import table and a
// version resource. It holds no code and does nothing if it is run.
func genExe(s *prng.Stream, start time.Time) ([]byte, error) {
	imports, err := ParseImports([]string{
		"kernel32.dll!CreateFileW", "kernel32.dll!ReadFile", "kernel32.dll!CloseHandle",
		"advapi32.dll!RegOpenKeyExW", "user32.dll!MessageBoxW",
	})
	if err != nil {
		return nil, err
	}
	name := s.Text(8)
	return BuildPE(PESpec{
		Timestamp: start,
		Sections: []PESection{
			{Name: ".text", Data: s.Bytes(2048)},
			{Name: ".rdata", Data: []byte(s.Text(512))},
			{Name: ".data", Data: s.Bytes(256)},
		},
		Imports: imports,
		Version: &PEVersion{
			FileVersion: "1.0.0.0", ProductVersion: "1.0.0.0",
			CompanyName: "Example Software", FileDescription: "Example utility",
			InternalName: name, OriginalFilename: name + constant.ExeExtension,
			ProductName: "Example Tools", LegalCopyright: "(c) Example Software",
		},
	})
}

func genJSONL(s *prng.Stream, start time.Time) ([]byte, error) {
	return timestampedLines(start, 30*time.Second, func(_ int, t time.Time) string {
		return fmt.Sprintf(`{"ts":"%s","level":"info","user":"%s","msg":"%s"}`, t.Format(time.RFC3339), s.Text(6), s.Text(18))
	}), nil
}

func genSyslog(s *prng.Stream, start time.Time) ([]byte, error) {
	return timestampedLines(start, 45*time.Second, func(i int, t time.Time) string {
		return fmt.Sprintf("%s host01 fsagen[%d]: %s", t.Format(time.RFC3339), 1000+i, s.Text(20))
	}), nil
}

func genMarkdown(s *prng.Stream, _ time.Time) ([]byte, error) {
	title := s.Text(12)
	return []byte(fmt.Sprintf("# %s\n\n%s\n", title, s.Text(80))), nil
}

// bulkEmail is the message the eml and mbox kinds build, described the way the
// email action describes one. Going through email.Build is what gives a bulk
// message its headers in canonical order, folded at 78 columns, with a
// Message-ID and CRLF throughout; going through email.ToMbox is what escapes a
// body line beginning "From ", which the hand-written mbox did not, and which
// is how one message gets read as two.
//
// The draws are named rather than written inline, so the order the stream is
// consumed in is the order they appear on the page.
func bulkEmail(s *prng.Stream, date time.Time, subject string) email.Options {
	id := "<" + s.Hex(16) + "@example.com>"
	body := s.Text(bulkEmailBodyLen)
	return email.Options{
		Spec: spec.EmailSpec{
			From:      "alice@example.com",
			To:        []string{"bob@example.com"},
			Subject:   subject,
			Date:      date.Format(time.RFC3339),
			MessageID: id,
			BodyText:  body,
		},
		// Never called for a text-only message, but a deterministic one has to
		// be here before a body is ever added beside the text.
		Boundary: func() string { return "----=_fsagen_" + s.Hex(24) },
	}
}

func genEml(s *prng.Stream, start time.Time) ([]byte, error) {
	subject := "Test message " + s.Text(6)
	msg, _, err := email.Build(bulkEmail(s, start.Add(bulkEmailOffset), subject))
	return msg, err
}

func genMbox(s *prng.Stream, start time.Time) ([]byte, error) {
	var out []byte
	base := start.Add(bulkEmailOffset)
	for i := range bulkMboxMessages {
		subject := fmt.Sprintf("Message %d %s", i+1, s.Text(6))
		opts := bulkEmail(s, base.Add(time.Duration(i)*time.Hour), subject)
		msg, date, err := email.Build(opts)
		if err != nil {
			return nil, err
		}
		out = append(out, email.ToMbox(msg, email.EnvelopeSender(opts.Spec), date)...)
	}
	return out, nil
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

// bulkHistory invents five visits to one host, counted back from the bulk
// start so no date inside the corpus comes from the wall clock.
func bulkHistory(host string, s *prng.Stream, start time.Time) HistorySpec {
	var spec HistorySpec
	for i := 1; i <= 5; i++ {
		spec.Visits = append(spec.Visits, Visit{
			URL:        fmt.Sprintf("https://%s/%d/%s", host, i, s.Text(6)),
			Title:      "Page " + s.Text(6),
			Time:       start.Add(-time.Duration(i) * time.Minute),
			Transition: Transitions[s.IntN(len(Transitions))],
		})
	}
	return spec
}

func genChromeHistory(s *prng.Stream, start time.Time) ([]byte, error) {
	spec := bulkHistory("example.com", s, start)
	name := s.Text(6) + constant.ZipExtension
	spec.Downloads = []Download{{
		URL:        "https://example.com/files/" + name,
		TargetPath: `C:\Users\user\Downloads\` + name,
		Start:      start.Add(-2 * time.Hour),
		End:        start.Add(-2*time.Hour + time.Minute),
		Received:   4096,
		Total:      4096,
		MimeType:   "application/zip",
	}}
	return ChromeHistory(spec, s)
}

func genFirefoxPlaces(s *prng.Stream, start time.Time) ([]byte, error) {
	return FirefoxPlaces(bulkHistory("mozilla.example", s, start), s)
}
