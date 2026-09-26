package manifest

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"debug/pe"
	"encoding/binary"
	"image/jpeg"
	"image/png"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"

	_ "github.com/glebarez/go-sqlite" // the driver the history databases are read back with
)

func readOut(t *testing.T, root, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTypedFormatsParse: every format fsagen claims to write is opened by the
// library that reads that format, and carries the filler the scenario asked
// for. A ".exe" of base32 text is exactly what this stops.
func TestTypedFormatsParse(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: bin/dropper.exe
    content_len: 4096
    pe:
      machine: amd64
      subsystem: gui
      imports:
        - kernel32.dll!CreateFileW
        - ws2_32.dll!connect
      version:
        file_version: 3.2.1.0
        company_name: Example Corp
        original_filename: dropper.exe
  - action: create
    path: bin/helper.dll
    pe:
      dll: true
      timestamp: "0"
  - action: create
    path: share/bundle.zip
    content_len: 2048
  - action: create
    path: media/photo.png
    content_len: 300
  - action: create
    path: media/scan.jpg
    content_len: 300
  - action: create
    path: media/clip.mp4
    content_len: 1024
  - action: create
    path: docs/report.docx
    content_len: 500
    docx:
      title: Quarterly Report
      author: A. Analyst
      created: 2024-01-02T03:04:05Z
      modified: 2024-02-03T04:05:06Z
`, nil)

	// A PE the standard library reads, with the imports and sections asked for.
	data := readOut(t, root, "bin/dropper.exe")
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("machine %#x", f.Machine)
	}
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); !ok || oh.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
		t.Errorf("optional header %+v, want a GUI subsystem", f.OptionalHeader)
	}
	syms, err := f.ImportedSymbols()
	if err != nil || !strings.Contains(strings.Join(syms, " "), "CreateFileW") {
		t.Errorf("imports %v (%v)", syms, err)
	}
	rsrc := f.Section(".rsrc")
	if rsrc == nil {
		t.Fatal("no version resource")
	}
	// A section called .rsrc is not enough: the resource data directory has
	// to point at it, or nothing that walks resources the way Explorer does
	// will find the version block.
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	if d := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]; d.VirtualAddress != rsrc.VirtualAddress || d.Size == 0 {
		t.Errorf("resource directory is %+v, want %d bytes at %#x", d, rsrc.Size, rsrc.VirtualAddress)
	}
	// The version strings are stored as UTF-16 inside .rsrc.
	if !bytes.Contains(data, utf16le("Example Corp")) {
		t.Error("the version resource does not carry the company name")
	}
	if got := f.TimeDateStamp; got == 0 {
		t.Error("TimeDateStamp left at zero; it should default to the operation time")
	}
	// content_len is the overlay: the bytes after the last section, where an
	// installer keeps its payload.
	if overlay := len(data) - peImageEnd(f); overlay != 4096 {
		t.Errorf("overlay is %d bytes, want the content_len of 4096", overlay)
	}

	dll := readOut(t, root, "bin/helper.dll")
	df, err := pe.NewFile(bytes.NewReader(dll))
	if err != nil {
		t.Fatalf("debug/pe on the dll: %v", err)
	}
	defer df.Close()
	if df.Characteristics&pe.IMAGE_FILE_DLL == 0 {
		t.Error("helper.dll is not marked as a DLL")
	}
	if df.TimeDateStamp != 0 {
		t.Errorf(`timestamp: "0" gave %d`, df.TimeDateStamp)
	}
	// With no content_len, a structured format writes the smallest valid
	// file: no filler is invented behind the scenario's back.
	if overlay := len(dll) - peImageEnd(df); overlay != 0 {
		t.Errorf("a dll with no content_len carries a %d byte overlay", overlay)
	}

	// A zip archive/zip reads, holding the filler.
	zdata := readOut(t, root, "share/bundle.zip")
	zr, err := zip.NewReader(bytes.NewReader(zdata), int64(len(zdata)))
	if err != nil {
		t.Fatalf("archive/zip: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].UncompressedSize64 != 2048 {
		t.Errorf("zip holds %d members", len(zr.File))
	}

	if _, err := png.Decode(bytes.NewReader(readOut(t, root, "media/photo.png"))); err != nil {
		t.Errorf("image/png: %v", err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(readOut(t, root, "media/scan.jpg"))); err != nil {
		t.Errorf("image/jpeg: %v", err)
	}

	mp4 := readOut(t, root, "media/clip.mp4")
	if string(mp4[4:8]) != "ftyp" {
		t.Errorf("mp4 starts %q", mp4[4:8])
	}
	if !bytes.Contains(mp4, []byte("moov")) || !bytes.Contains(mp4, []byte("mdat")) {
		t.Error("the mp4 has no movie or media box")
	}

	// A docx is a readable OOXML package whose properties carry the dates.
	ddata := readOut(t, root, "docs/report.docx")
	dr, err := zip.NewReader(bytes.NewReader(ddata), int64(len(ddata)))
	if err != nil {
		t.Fatalf("docx: %v", err)
	}
	var core string
	for _, p := range dr.File {
		if p.Name == "docProps/core.xml" {
			r, _ := p.Open()
			var b bytes.Buffer
			b.ReadFrom(r)
			r.Close()
			core = b.String()
		}
	}
	for _, want := range []string{
		"Quarterly Report", "A. Analyst",
		// The two dates are different, so neither can stand in for the other.
		`<dcterms:created xsi:type="dcterms:W3CDTF">2024-01-02T03:04:05Z</dcterms:created>`,
		`<dcterms:modified xsi:type="dcterms:W3CDTF">2024-02-03T04:05:06Z</dcterms:modified>`,
	} {
		if !strings.Contains(core, want) {
			t.Errorf("docProps/core.xml does not carry %q:\n%s", want, core)
		}
	}
}

// peImageEnd is where the last section's data stops, so what follows is the
// overlay.
func peImageEnd(f *pe.File) int {
	var end uint32
	for _, s := range f.Sections {
		if e := s.Offset + s.Size; e > end {
			end = e
		}
	}
	return int(end)
}

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// TestHistoryFromScenario: the visits a playbook names reach the database in
// the engine's own epoch, and a tool's query returns them.
func TestHistoryFromScenario(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: Chrome/Default/History
    format: chrome_history
    history:
      visits:
        - url: https://intranet.example/payroll
          title: Payroll
          time: 2024-03-15T09:15:00Z
          transition: typed
        - url: https://intranet.example/payroll/export.csv
          title: Export
          time: 2024-03-15T09:16:00Z
          from_visit: 1
      downloads:
        - url: https://intranet.example/payroll/export.csv
          target_path: C:\Users\u\Downloads\export.csv
          start: 2024-03-15T09:16:05Z
          end: 2024-03-15T09:16:07Z
          received_bytes: 51200
          total_bytes: 51200
          mime_type: text/csv
  - action: create
    path: Firefox/places.sqlite
    format: firefox_places
    history:
      visits:
        - url: https://intranet.example/payroll
          title: Payroll
          time: 2024-03-15T09:15:00Z
          transition: typed
`, nil)

	chrome := openDB(t, readOut(t, root, "Chrome/Default/History"))
	var url string
	var visitTime int64
	if err := chrome.QueryRow(`SELECT urls.url, visits.visit_time FROM visits JOIN urls ON urls.id = visits.url ORDER BY visits.id LIMIT 1`).Scan(&url, &visitTime); err != nil {
		t.Fatal(err)
	}
	if url != "https://intranet.example/payroll" {
		t.Errorf("first visit %s", url)
	}
	// 2024-03-15T09:15:00Z in microseconds since 1601.
	if want := int64(1710494100+11644473600) * 1_000_000; visitTime != want {
		t.Errorf("visit_time %d, want %d", visitTime, want)
	}
	var from int
	if err := chrome.QueryRow(`SELECT from_visit FROM visits WHERE id = 2`).Scan(&from); err != nil || from != 1 {
		t.Errorf("from_visit %d (%v)", from, err)
	}
	var target, mime string
	if err := chrome.QueryRow(`SELECT target_path, mime_type FROM downloads`).Scan(&target, &mime); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(target, `export.csv`) || mime != "text/csv" {
		t.Errorf("download %s %s", target, mime)
	}

	firefox := openDB(t, readOut(t, root, "Firefox/places.sqlite"))
	var date int64
	var rev string
	if err := firefox.QueryRow(`SELECT v.visit_date, p.rev_host FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id`).Scan(&date, &rev); err != nil {
		t.Fatal(err)
	}
	if want := int64(1710494100) * 1_000_000; date != want {
		t.Errorf("visit_date %d, want %d (PRTime, not the WebKit epoch)", date, want)
	}
	if rev != "elpmaxe.tenartni." {
		t.Errorf("rev_host %q", rev)
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
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check = %q, %v", check, err)
	}
	return db
}

// TestArchiveMembersMatchSources: the archive holds exactly the files named,
// byte for byte, with the modification times the scenario gave them.
func TestArchiveMembersMatchSources(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-06-01T10:00:00Z
operations:
  - action: create
    path: staging/a.txt
    content: alpha
    mtime: 2024-05-01T08:00:00Z
  - action: create
    path: staging/b.txt
    content: bravo
    mtime: 2024-05-02T08:00:00Z
  - action: create
    path: staging/notes/c.txt
    content: charlie
  - action: create
    path: staging/extra/d.txt
    content: delta
    id: extra
  - action: archive
    path: out/bundle.zip
    mtime: 2024-06-01T10:00:00Z
    archive:
      base: staging
      comment: staged for exfiltration
      members:
        - staging/*.txt
      member_refs:
        - extra
`, nil)

	data := readOut(t, root, "out/bundle.zip")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Comment != "staged for exfiltration" {
		t.Errorf("comment %q", zr.Comment)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if _, err := b.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		r.Close()
		got[f.Name] = b.String()
		if f.CRC32 == 0 && b.Len() > 0 {
			t.Errorf("%s: no CRC", f.Name)
		}
	}
	// member_refs come first, then the pattern's matches in path order. The
	// glob stops at a slash, so notes/c.txt is not in it.
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "extra/d.txt,a.txt,b.txt" {
		t.Errorf("members = %v", names)
	}
	if got["a.txt"] != "alpha" || got["b.txt"] != "bravo" || got["extra/d.txt"] != "delta" {
		t.Errorf("contents = %v", got)
	}
	for _, f := range zr.File {
		if f.Name == "a.txt" && !f.Modified.Equal(mustTime(t, "2024-05-01T08:00:00Z")) {
			t.Errorf("a.txt stored with mtime %v", f.Modified)
		}
	}
	// The source files are still there: an archive copies, it does not move.
	if string(readOut(t, root, "staging/a.txt")) != "alpha" {
		t.Error("archiving changed the source")
	}
}

// TestArchiveDeflateAndSelfExclusion: deflate is opt-in, and a pattern that
// would sweep the archive into itself does not.
func TestArchiveDeflateAndSelfExclusion(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-06-01T10:00:00Z
operations:
  - action: create
    path: logs/a.log
    content_len: 4096
    content_kind: zeros
  - action: archive
    path: logs/all.zip
    archive:
      method: deflate
      members:
        - logs/*
`, nil)
	data := readOut(t, root, "logs/all.zip")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "logs/a.log" {
		t.Fatalf("members = %d", len(zr.File))
	}
	if zr.File[0].Method != zip.Deflate {
		t.Errorf("method %d, want deflate", zr.File[0].Method)
	}
	if len(data) >= 4096 {
		t.Errorf("4096 zero bytes deflated to a %d byte archive", len(data))
	}
}

// TestEditDeleteLines40to60: a gap in a log is a real gap, and the line count
// and sequence numbers show it.
func TestEditDeleteLines40to60(t *testing.T) {
	var body strings.Builder
	body.WriteString("start: 2024-06-01T10:00:00Z\noperations:\n  - action: create\n    path: var/log/beacon.log\n    content: |\n")
	for i := 1; i <= 170; i++ {
		body.WriteString("      seq=" + strconv.Itoa(i) + " beacon\n")
	}
	body.WriteString(`  - action: edit
    path: var/log/beacon.log
    mtime: 2024-06-02T10:00:00Z
    edit:
      delete_lines: 40-60
`)
	root, _ := runManifest(t, body.String(), nil)

	lines := strings.Split(strings.TrimSuffix(string(readOut(t, root, "var/log/beacon.log")), "\n"), "\n")
	if len(lines) != 149 {
		t.Fatalf("%d lines, want 149", len(lines))
	}
	if lines[38] != "seq=39 beacon" || lines[39] != "seq=61 beacon" {
		t.Errorf("no gap at the join: %q then %q", lines[38], lines[39])
	}
}

// TestEditReplaceAndInsert: substitutions honour their count and keep the
// file's line endings, and insertions land after the line they name.
func TestEditReplaceAndInsert(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-06-01T10:00:00Z
operations:
  - action: create
    path: app.conf
    content: "debug = true\r\nhost = old.example\r\nhost = old.example\r\ntrace = off\r\n"
  - action: edit
    path: app.conf
    edit:
      insert_after:
        - pattern: '^debug'
          text: "audit = on\r"
      replace:
        - pattern: 'old\.example'
          with: new.example
          count: 1
      delete_matching: '^trace'
`, nil)
	// The steps run in their documented order whatever order they were
	// written in: whole lines go first, then substitutions, then insertions.
	got := string(readOut(t, root, "app.conf"))
	want := "debug = true\r\naudit = on\r\nhost = new.example\r\nhost = old.example\r\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestEditRefusesMissingLines(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	p := writeFile(t, dir, "m.yaml", `
operations:
  - action: create
    path: a.txt
    content: "one\ntwo\n"
  - action: edit
    path: a.txt
    edit:
      delete_lines: 5-9
`)
	_, err := ExecuteFile(compile.ModeManifest, root, p, compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "past the end") {
		t.Fatalf("err = %v, want it to say the range is past the end", err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestMP4DurationAndDimensions: the movie header carries what the container
// claims, which is all a metadata tool reads off it.
func TestMP4DurationAndDimensions(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: clip.mp4
    content_len: 64
`, nil)
	data := readOut(t, root, "clip.mp4")
	i := bytes.Index(data, []byte("tkhd"))
	if i < 0 {
		t.Fatal("no track header")
	}
	w := binary.BigEndian.Uint32(data[i+4+76:]) >> 16
	h := binary.BigEndian.Uint32(data[i+4+80:]) >> 16
	if w != 320 || h != 240 {
		t.Errorf("track is %dx%d", w, h)
	}

	// The movie header says how long the clip claims to be, and when it was
	// made: an MP4 counts seconds from 1904, which is neither epoch anything
	// else here uses.
	m := bytes.Index(data, []byte("mvhd"))
	if m < 0 {
		t.Fatal("no movie header")
	}
	created := binary.BigEndian.Uint32(data[m+8:])
	timescale := binary.BigEndian.Uint32(data[m+16:])
	ticks := binary.BigEndian.Uint32(data[m+20:])
	if timescale == 0 || time.Duration(ticks)*time.Second/time.Duration(timescale) != 3*time.Second {
		t.Errorf("duration is %d ticks at %d per second, want 3s", ticks, timescale)
	}
	epoch1904 := time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)
	want := uint32(time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC).Sub(epoch1904) / time.Second)
	if created != want {
		t.Errorf("creation time %d, want %d (the operation time, counted from 1904)", created, want)
	}
}

func TestMailTemplateIsRFC5322(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	p := writeFile(t, dir, "pb.yaml", `
start: 2024-03-15T09:00:00Z
actors:
  - name: alice
    base: users/alice
steps:
  - actor: alice
    offset: 0s
    actions:
      - action: create
        path: mail/note.eml
        template: email
`)
	if _, err := ExecuteFile(compile.ModePlaybook, root, p, compile.Options{}); err != nil {
		t.Fatal(err)
	}
	data := readOut(t, root, "users/alice/mail/note.eml")
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("net/mail cannot read the template: %v", err)
	}
	if msg.Header.Get("Message-Id") == "" {
		t.Error("no Message-ID")
	}
	if !bytes.Contains(data, []byte("\r\n")) || bytes.Contains(bytes.ReplaceAll(data, []byte("\r\n"), nil), []byte("\n")) {
		t.Error("the template is not CRLF throughout")
	}
	if got := msg.Header.Get("From"); got != "alice@example.com" {
		t.Errorf("From %q", got)
	}
}

// TestArchiveBaseMustCoverEveryMember: a member outside base has no name
// inside the archive, and saying so beats inventing one.
// TestArchiveRefusesEmptyPattern: a pattern that matches nothing is a
// scenario that did not do what it says, not an empty archive.
func TestArchiveRefusesEmptyPattern(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "m.yaml", `
start: 2024-01-01T00:00:00Z
operations:
  - action: create
    path: notes.txt
    content: hello
  - action: archive
    path: bundle.zip
    archive:
      members: ["*.csv"]
`)
	_, err := ExecuteFile(compile.ModeManifest, t.TempDir(), p, compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "matches no file") {
		t.Errorf("err = %v, want a complaint that the pattern matches nothing", err)
	}
}

func TestArchiveBaseMustCoverEveryMember(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	p := writeFile(t, dir, "m.yaml", `
operations:
  - action: create
    path: staging/a.txt
    content: a
  - action: create
    path: elsewhere/b.txt
    content: b
    id: extra
  - action: archive
    path: out.zip
    archive:
      base: staging
      member_refs: [extra]
`)
	_, err := ExecuteFile(compile.ModeManifest, root, p, compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "is not under staging") {
		t.Fatalf("err = %v, want it to name the member outside base", err)
	}
}

// TestAttachmentRefAttachesGeneratedFile: a message can attach an artefact an
// earlier action created without knowing the name it was given.
func TestAttachmentRefAttachesGeneratedFile(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-04-01T08:00:00Z
operations:
  - action: create
    path: reports/summary-${RND:6}.txt
    id: report
    content: quarterly numbers
  - action: email
    path: mail/out.eml
    email:
      from: a@example.com
      to: ["b@example.com"]
      subject: Numbers
      body_text: attached
      attachments:
        - ref: report
          name: summary.txt
`, nil)
	msg := string(readOut(t, root, "mail/out.eml"))
	if !strings.Contains(msg, "filename=summary.txt") {
		t.Errorf("the attachment is not named:\n%s", msg)
	}
	// "quarterly numbers" base64-encoded.
	if !strings.Contains(msg, "cXVhcnRlcmx5IG51bWJlcnM=") {
		t.Errorf("the attachment does not carry the file's bytes:\n%s", msg)
	}
}

func TestAttachmentRefErrors(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`
operations:
  - action: email
    path: m.eml
    email:
      from: a@example.com
      date: 2024-01-01T00:00:00Z
      attachments:
        - ref: nothing
`, `unknown id "nothing"`},
		{`
operations:
  - action: create
    path: a.txt
    id: two
    content: a
  - action: create
    path: b.txt
    id: two
    content: b
  - action: email
    path: m.eml
    email:
      from: a@example.com
      date: 2024-01-01T00:00:00Z
      attachments:
        - ref: two
`, "already declared"},
	} {
		dir := t.TempDir()
		p := writeFile(t, dir, "m.yaml", tc.body)
		_, err := ExecuteFile(compile.ModeManifest, t.TempDir(), p, compile.Options{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("err = %v, want %q", err, tc.want)
		}
	}
}

// TestAttachmentRefNamingSeveralFiles: a batch gives one id several live
// paths. A message attaches one file, so picking one of them silently would
// attach whichever happened to come first.
func TestAttachmentRefNamingSeveralFiles(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "p.yaml", `
start: "2024-01-01T00:00:00Z"
actors:
  - name: a
    base: u
steps:
  - actor: a
    offset: 0s
    batch_count: 2
    actions:
      - action: create
        path: report-${BATCH}.txt
        id: reports
        content: numbers
  - actor: a
    offset: 1m
    actions:
      - action: email
        path: m.eml
        email:
          from: a@example.com
          to: ["b@example.com"]
          subject: Reports
          body_text: attached
          attachments:
            - ref: reports
`)
	_, err := ExecuteFile(compile.ModePlaybook, t.TempDir(), p, compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "attaches one file at a time") {
		t.Errorf("err = %v, want a refusal to pick one of the two", err)
	}
}

// TestContentKindShapesTheBytes: each kind reaches the file, and the default
// is the base32 text every earlier release wrote.
func TestContentKindShapesTheBytes(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-04-01T08:00:00Z
operations:
  - action: create
    path: k/default.bin
    content_len: 512
  - action: create
    path: k/zeros.bin
    content_len: 512
    content_kind: zeros
  - action: create
    path: k/pattern.bin
    content_len: 512
    content_kind: pattern
  - action: create
    path: k/lorem.txt
    content_len: 512
    content_kind: lorem
  - action: create
    path: k/bytes.bin
    content_len: 512
    content_kind: bytes
`, nil)
	def := readOut(t, root, "k/default.bin")
	if len(def) != 512 || strings.Trim(string(def), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		t.Errorf("the default kind is not base32 text: %q", def[:32])
	}
	if got := readOut(t, root, "k/zeros.bin"); !bytes.Equal(got, make([]byte, 512)) {
		t.Error("zeros are not zero")
	}
	if got := readOut(t, root, "k/pattern.bin"); got[0] != 0 || got[255] != 255 || got[256] != 0 {
		t.Errorf("pattern does not ramp: % x", got[250:260])
	}
	if got := readOut(t, root, "k/lorem.txt"); !strings.Contains(string(got), " ") {
		t.Errorf("lorem has no words: %q", got[:40])
	}
	if got := readOut(t, root, "k/bytes.bin"); len(got) != 512 {
		t.Errorf("%d bytes", len(got))
	}
}
