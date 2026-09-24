package libgen

import (
	"archive/zip"
	"database/sql"
	"fmt"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/util"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abema/go-mp4"
	"github.com/gingfrederik/docx"
	_ "github.com/glebarez/sqlite"
	"github.com/jung-kurt/gofpdf"
)

func GenerateFiles(rootpath string, limit, depth int64) error {
	if depth == 0 {
		return nil
	}

	// Use buffered channel to prevent blocking
	err := make(chan error, limit)

	for index := int64(0); index < limit; index++ {
		pathfmt := fmt.Sprintf("%s_%d", util.GetRandomString(constant.FileNameLen), index)
		path := filepath.Join(rootpath, pathfmt)

		go populateFolder(path, limit, err)

		// Recurse synchronously to maintain depth structure
		if recErr := GenerateFiles(path, limit, depth-1); recErr != nil {
			return recErr
		}
	}

	// Collect results from all populateFolder calls
	for index := int64(0); index < limit; index++ {
		if e := <-err; e != nil {
			return e
		}
	}

	return nil
}

func populateFolder(path string, limit int64, channeledErr chan error) {
	ioerr := os.MkdirAll(path, 0o755)
	if ioerr != nil {
		channeledErr <- ioerr
		return
	}

	// Calculate total goroutines per iteration: 18 file types
	totalPerIteration := int64(19)
	totalGoroutines := limit * totalPerIteration

	// Use buffered channel sized to hold all results to prevent blocking
	generr := make(chan error, totalGoroutines)

	for index := int64(0); index < limit; index++ {
		go generateTxt(path, generr)
		go generateDocx(path, generr)
		go generatePng(path, generr)
		go generatePdf(path, generr)
		go generateMp4(path, generr)
		go generateCsv(path, generr)
		go generateJson(path, generr)
		go generateXml(path, generr)
		go generateHtml(path, generr)
		go generateLog(path, generr)
		go generateReg(path, generr)
		go generateZip(path, generr)
		go generateExe(path, generr)
		go generateJsonl(path, generr)
		go generateSyslog(path, generr)
		go generateMarkdown(path, generr)
		go generateEml(path, generr)
		go generateMbox(path, generr)
		go generateChromeHistory(path, generr)
		go generateFirefoxPlaces(path, generr)
	}

	// Collect all results
	for i := int64(0); i < totalGoroutines; i++ {
		if err := <-generr; err != nil {
			channeledErr <- err
			return
		}
	}

	channeledErr <- nil
}

func generateTxt(basedir string, channeledErr chan error) {
	txtpath := util.GetFilePath(basedir, constant.TxtExtension)
	randomData := []byte(util.GetRandomString(constant.ContentLen))
	channeledErr <- os.WriteFile(txtpath, randomData, 0o644)
}

func generateDocx(basedir string, channeledErr chan error) {
	docfile := docx.NewFile()
	para := docfile.AddParagraph()
	randomData := util.GetRandomString(constant.ContentLen)
	para.AddText(randomData).Size(12)
	docxpath := util.GetFilePath(basedir, constant.DocxExtension)
	channeledErr <- docfile.Save(docxpath)
}

func generatePng(basedir string, channeledErr chan error) {
	width := 500
	height := 500
	upLeft := image.Point{0, 0}
	lowRight := image.Point{width, height}

	img := image.NewRGBA(image.Rectangle{upLeft, lowRight})
	cyan := color.RGBA{100, 200, 200, 0xff}

	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			switch {
			case x < width/2 && y < height/2:
				img.Set(x, y, cyan)
			case x >= width/2 && y >= height/2:
				img.Set(x, y, color.White)
			default:
			}
		}
	}

	pngpath := util.GetFilePath(basedir, constant.PngExtension)
	pngfile, pngerr := os.Create(pngpath)
	if pngerr != nil {
		channeledErr <- pngerr
	}
	encodeErr := png.Encode(pngfile, img)
	if encodeErr != nil {
		channeledErr <- encodeErr
	}
	channeledErr <- pngfile.Close()
}

func generatePdf(basedir string, channeledErr chan error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "", 12)
	for i := 0; i < 25; i++ {
		randomData := util.GetRandomString(20)
		pdf.Text(10, 10*float64(i), randomData)
	}
	pdfpath := util.GetFilePath(basedir, constant.PdfExtension)
	channeledErr <- pdf.OutputFileAndClose(pdfpath)
}

func generateMp4(basedir string, channeledErr chan error) {
	mp4path := util.GetFilePath(basedir, constant.Mp4Extension)
	mp4file, mp4err := os.Create(mp4path)
	if mp4err != nil {
		channeledErr <- mp4err
	}
	mp4writer := mp4.NewWriter(mp4file)
	randomData := []byte(util.GetRandomString(constant.ContentLen))
	_, writeErr := mp4writer.Write(randomData)
	if writeErr != nil {
		channeledErr <- writeErr
	}
	channeledErr <- mp4file.Close()
}

func generateCsv(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.CsvExtension)
	rows := []string{"id,name,value"}
	for i := 0; i < 10; i++ {
		rows = append(rows, fmt.Sprintf("%d,%s,%s", i+1, util.GetRandomString(8), util.GetRandomString(12)))
	}
	channeledErr <- os.WriteFile(p, []byte(strings.Join(rows, "\n")+"\n"), 0o644)
}

func generateJson(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.JsonExtension)
	content := fmt.Sprintf(`{"id":%d,"name":"%s","timestamp":"%s"}`,
		1, util.GetRandomString(8), time.Now().UTC().Format(time.RFC3339))
	channeledErr <- os.WriteFile(p, []byte(content), 0o644)
}

func generateXml(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.XmlExtension)
	content := fmt.Sprintf(`<root><id>%d</id><name>%s</name></root>`, 1, util.GetRandomString(8))
	channeledErr <- os.WriteFile(p, []byte(content), 0o644)
}

func generateHtml(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.HtmlExtension)
	body := util.GetRandomString(64)
	html := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head><body><p>%s</p></body></html>`, body[:8], body)
	channeledErr <- os.WriteFile(p, []byte(html), 0o644)
}

func generateLog(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.LogExtension)
	lines := make([]string, 0, 50)
	t := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		msg := util.GetRandomString(24)
		lines = append(lines, fmt.Sprintf("%s INFO user=%s event=%s", t.Format(time.RFC3339), util.GetRandomString(6), msg))
		t = t.Add(1 * time.Minute)
	}
	channeledErr <- os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func generateReg(basedir string, channeledErr chan error) {
	// Windows .reg format (REGEDIT4 or Windows Registry Editor Version 5.00)
	p := util.GetFilePath(basedir, constant.RegExtension)
	content := "Windows Registry Editor Version 5.00\r\n\r\n" +
		fmt.Sprintf("[HKEY_CURRENT_USER\\Software\\Fsagen\\%s]\r\n\"Value\"=\"%s\"\r\n", util.GetRandomString(6), util.GetRandomString(12))
	channeledErr <- os.WriteFile(p, []byte(content), 0o644)
}

func generateZip(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.ZipExtension)
	f, err := os.Create(p)
	if err != nil {
		channeledErr <- err
		return
	}
	zw := zip.NewWriter(f)
	// add a few deterministic files
	for i := 0; i < 3; i++ {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     fmt.Sprintf("file%d.txt", i+1),
			Method:   zip.Store,
			Modified: time.Date(2021, 1, 1, i, 0, 0, 0, time.UTC),
		})
		if err != nil {
			_ = zw.Close()
			_ = f.Close()
			channeledErr <- err
			return
		}
		_, _ = io.WriteString(w, util.GetRandomString(32))
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		channeledErr <- err
		return
	}
	channeledErr <- f.Close()
}

// generateExe writes a minimal DOS MZ stub .exe intended for filesystem artifact testing.
// It is not a functional Windows PE binary but includes the 'MZ' signature and DOS-mode message.
func generateExe(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.ExeExtension)
	// Minimal MZ header with DOS stub message; simplifies to a recognizable EXE artifact.
	buf := make([]byte, 256)
	buf[0] = 'M'
	buf[1] = 'Z'
	copy(buf[0x40:], []byte("This program cannot be run in DOS mode.\r\r\n$"))
	channeledErr <- os.WriteFile(p, buf, 0o644)
}

func generateJsonl(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.JsonlExtension)
	t := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 50; i++ {
		line := fmt.Sprintf(`{"ts":"%s","level":"info","user":"%s","msg":"%s"}`,
			t.Format(time.RFC3339), util.GetRandomString(6), util.GetRandomString(18))
		b.WriteString(line)
		b.WriteByte('\n')
		t = t.Add(30 * time.Second)
	}
	channeledErr <- os.WriteFile(p, []byte(b.String()), 0o644)
}

func generateSyslog(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.SyslogExtension)
	t := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	host := "host01"
	app := "fsagen"
	lines := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		msg := util.GetRandomString(20)
		lines = append(lines, fmt.Sprintf("%s %s %s[%d]: %s", t.Format(time.RFC3339), host, app, 1000+i, msg))
		t = t.Add(45 * time.Second)
	}
	channeledErr <- os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func generateMarkdown(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.MdExtension)
	title := util.GetRandomString(12)
	body := util.GetRandomString(80)
	md := fmt.Sprintf("# %s\n\n%s\n", title, body)
	channeledErr <- os.WriteFile(p, []byte(md), 0o644)
}

func generateEml(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.EmlExtension)
	date := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC1123Z)
	from := "alice@example.com"
	to := "bob@example.com"
	subj := "Test message " + util.GetRandomString(6)
	body := util.GetRandomString(120)
	eml := fmt.Sprintf("Date: %s\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", date, from, to, subj, body)
	channeledErr <- os.WriteFile(p, []byte(eml), 0o644)
}

func generateMbox(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.MboxExtension)
	var b strings.Builder
	base := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Hour).Format(time.RFC1123Z)
		subj := fmt.Sprintf("Message %d %s", i+1, util.GetRandomString(6))
		body := util.GetRandomString(100)
		b.WriteString(fmt.Sprintf("From alice@example.com %s\n", ts))
		b.WriteString(fmt.Sprintf("Date: %s\nFrom: alice@example.com\nTo: bob@example.com\nSubject: %s\n\n%s\n\n", ts, subj, body))
	}
	channeledErr <- os.WriteFile(p, []byte(b.String()), 0o644)
}

func generateChromeHistory(basedir string, channeledErr chan error) {
	p := util.GetFilePath(basedir, constant.DbExtension)
	db, err := sql.Open("sqlite", p)
	if err != nil {
		channeledErr <- err
		return
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS urls(
		id INTEGER PRIMARY KEY,
		url LONGVARCHAR,
		title LONGVARCHAR,
		visit_count INTEGER,
		typed_count INTEGER,
		last_visit_time INTEGER
	);`,
		`CREATE TABLE IF NOT EXISTS visits(
		id INTEGER PRIMARY KEY,
		url INTEGER,
		visit_time INTEGER,
		from_visit INTEGER,
		transition INTEGER
	);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			channeledErr <- err
			return
		}
	}
	now := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		url := fmt.Sprintf("https://example.com/%d/%s", i, util.GetRandomString(6))
		title := "Example " + util.GetRandomString(6)
		lastVisit := now.Add(-time.Duration(i) * time.Minute).Unix()

		if _, err := db.Exec(`INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time) VALUES(?,?,?,?,?)`, url, title, i*10, i*2, lastVisit); err != nil {
			channeledErr <- err
			return
		}

		if _, err := db.Exec(`INSERT INTO visits(url, visit_time, from_visit, transition) VALUES(?,?,?,?)`, i, lastVisit, 0, 0); err != nil {
			channeledErr <- err
			return
		}
	}

	channeledErr <- nil
}

func generateFirefoxPlaces(basedir string, channeledErr chan error) {
	p := filepath.Join(basedir, "places_"+util.GetRandomString(6)+constant.SqLiteExtension)
	db, err := sql.Open("sqlite", p)
	if err != nil {
		channeledErr <- err
		return
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            rev_host TEXT,
            visit_count INTEGER,
            hidden INTEGER,
            typed INTEGER,
            last_visit_date INTEGER
        );`,
		`CREATE TABLE IF NOT EXISTS moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER,
            visit_date INTEGER,
            from_visit INTEGER
        );`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			channeledErr <- err
			return
		}
	}

	now := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		url := fmt.Sprintf("https://mozilla.example/%d/%s", i, util.GetRandomString(6))
		title := "Mozilla " + util.GetRandomString(4)
		lastVisit := now.Add(-time.Duration(i) * time.Minute).Unix()
		if _, err := db.Exec(`INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date) VALUES (?, ?, ?, ?, ?, ?)`, i, url, title, i*3, i%2, lastVisit); err != nil {
			channeledErr <- err
			return
		}
		if _, err := db.Exec(`INSERT INTO moz_historyvisits (id, place_id, visit_date, from_visit) VALUES (?, ?, ?, ?)`, i, i, lastVisit, 0); err != nil {
			channeledErr <- err
			return
		}
	}

	channeledErr <- nil
}
