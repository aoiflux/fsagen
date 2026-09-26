package main

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"debug/pe"
	"flag"
	"fmt"
	"image/jpeg"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	_ "github.com/glebarez/go-sqlite" // reads the generated browser profiles back

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	manifestpkg "github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
)

var update = flag.Bool("update", false, "rewrite golden files whose input changed")

const exampleSeed = 42

func exampleFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("examples", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	return files
}

func exampleMode(path string) compile.Mode {
	if strings.HasPrefix(filepath.Base(path), "manifest") {
		return compile.ModeManifest
	}
	return compile.ModePlaybook
}

// runExample generates one shipped example into root with the example seed
// and returns the run's ledger and model. Where the platform cannot do
// everything an example asks (named streams, creation times), the rest is
// generated and the skips are recorded, as --on-unsupported=skip does.
func runExample(t *testing.T, path, root string) manifestpkg.Result {
	t.Helper()
	res, err := manifestpkg.ExecuteFile(exampleMode(path), root, path, compile.Options{Seed: exampleSeed, SkipUnsupported: runtime.GOOS != "windows"})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return res
}

// TestExampleContentGoldens pins the names, bytes and streams every shipped
// example produces for the example seed; its ledger (digests, intended
// times, what the platform leaves uncontrolled); its answer key; and its
// modelled bodyfile. It is what proves a change did not alter output for an
// unchanged input: if it did, GeneratorVersion must be bumped and a new
// golden directory recorded.
func TestExampleContentGoldens(t *testing.T) {
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			res := runExample(t, path, root)
			got, err := testutil.Fingerprint(root)
			if err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			if err := res.Timeline().WriteBodyfile(&body); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join("testdata", "golden", fmt.Sprintf("v%d", constant.GeneratorVersion), runtime.GOOS)
			in := testutil.InputHash(t, path)
			testutil.CheckGolden(t, filepath.Join(dir, "examples", name+".txt"), in, got, *update)
			testutil.CheckGolden(t, filepath.Join(dir, "ledger", name+".jsonl"), in, string(ledger.Bytes(res.Ledger)), *update)
			testutil.CheckGolden(t, filepath.Join(dir, "answer-key", name+".jsonl"), in, string(ledger.FactBytes(res.AnswerKey())), *update)
			testutil.CheckGolden(t, filepath.Join(dir, "bodyfile", name+".body"), in, body.String(), *update)
		})
	}
}

// TestDryRunGoldens pins the compiled operation list of every example. It is
// platform-independent: compilation never touches the disk.
func TestDryRunGoldens(t *testing.T) {
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			prog, err := compile.Load(exampleMode(path), path, compile.Options{Seed: exampleSeed})
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()
			var buf bytes.Buffer
			if err := compile.WriteDryRun(&buf, prog); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", "golden", fmt.Sprintf("v%d", constant.GeneratorVersion), "dryrun", name+".jsonl")
			testutil.CheckGolden(t, golden, testutil.InputHash(t, path), buf.String(), *update)
		})
	}
}

// exampleChecks holds what each shipped example must actually produce, beyond
// exiting 0: deletions that take effect, logs with real line breaks, streams
// on the files the scenario names, parseable mail.
var exampleChecks = map[string]func(t *testing.T, root string, fsys *sandbox.FS){
	"manifest-basic": func(t *testing.T, root string, _ *sandbox.FS) {
		mustExist(t, root, "media/videos/sample-renamed.mp4")
		mustNotExist(t, root, "media/videos/sample.mp4", "docs/readme.txt")
	},
	"manifest-bulk-simple": func(t *testing.T, root string, _ *sandbox.FS) {
		// The same deployment on five computers and a network share: every
		// .exe is a PE a tool can read and every .eml a message it can
		// parse, which is the whole point of the example.
		exes := globAll(t, root, "*", "*", "*.exe")
		if len(exes) != 17 {
			t.Errorf("%d executables, want 17", len(exes))
		}
		for _, p := range exes {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			f, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Errorf("%s is not a PE: %v", filepath.Base(p), err)
				continue
			}
			f.Close()
		}
		emls := globAll(t, root, "*", "*", "*.eml")
		if len(emls) != 16 {
			t.Errorf("%d messages, want 16", len(emls))
		}
		for _, p := range emls {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mail.ReadMessage(bytes.NewReader(data)); err != nil {
				t.Errorf("%s is not a message: %v", filepath.Base(p), err)
			}
		}
		// ${SEQ} counts every action, so the five installers are five
		// different files rather than one name written five times.
		names := map[string]bool{}
		for _, p := range globAll(t, root, "*", "temp", "installer-*.exe") {
			names[filepath.Base(p)] = true
		}
		if len(names) != 5 {
			t.Errorf("the ${SEQ} installers are named %v, want five distinct names", names)
		}
	},
	"playbook-comprehensive-ransomware": func(t *testing.T, root string, _ *sandbox.FS) {
		victim := "C/Users/victim"
		// batch_count: 50 encrypts 50 files; the second action only runs on
		// odd batch indices, so it adds 25 more.
		important, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(victim), "Desktop", "IMPORTANT_*.txt.encrypted"))
		all, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(victim), "Desktop", "*.encrypted"))
		if len(important) != 50 || len(all) != 75 {
			t.Errorf("%d IMPORTANT_ files and %d encrypted files, want 50 and 75", len(important), len(all))
		}
		// repeat: 5 with condition: even runs on iterations 0, 2 and 4, and
		// batch_count: 3 makes three of each per iteration.
		docx, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(victim), "AppData/Local/staging", "*.docx"))
		xlsx, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(victim), "AppData/Local/staging", "*.xlsx"))
		if len(docx) != 9 || len(xlsx) != 9 {
			t.Errorf("%d staged .docx and %d .xlsx, want 9 and 9", len(docx), len(xlsx))
		}
		// The archive of them, and the upload log, are covered up; the first
		// recon file is emptied rather than removed.
		mustNotExist(t, root, victim+"/AppData/Local/staging/archive-RW2024-A.zip", victim+"/AppData/Local/Temp/upload.log")
		if b := read(t, root, victim+"/AppData/Local/Temp/recon-0.txt"); len(b) != 0 {
			t.Errorf("the truncated recon file holds %d bytes", len(b))
		}
		if b := read(t, root, victim+"/AppData/Local/Temp/recon-1.txt"); len(b) == 0 {
			t.Error("truncate emptied a file it was not aimed at")
		}
		note := string(read(t, root, victim+"/Desktop/README_RW2024-A.txt"))
		if !strings.HasPrefix(note, "YOUR FILES HAVE BEEN ENCRYPTED\n\n") || !strings.Contains(note, "Campaign: RW2024-A") {
			t.Errorf("the ransom note is not the written text with real line breaks: %q", note)
		}
	},
	"playbook-basic": func(t *testing.T, root string, _ *sandbox.FS) {
		for _, p := range []string{"users/alice/docs/report-0.txt", "users/alice/docs/report-1.txt"} {
			if b := read(t, root, p); len(b) != 64 {
				t.Errorf("%s: %d bytes, want the 64 written by its update", p, len(b))
			}
		}
		mustBeEmpty(t, root, "users/bob/media/photos")
	},
	"playbook-email-and-archive": func(t *testing.T, root string, _ *sandbox.FS) {
		mustExist(t, root, "users/bob/bundles/bundle.zip")
		mustBeEmpty(t, root, "users/bob/mail")
		mustBeEmpty(t, root, "users/bob/media")
		// The archive still holds the message and the image the scenario
		// deleted afterwards, which is the point of staging then cleaning up.
		data := read(t, root, "users/bob/bundles/bundle.zip")
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("bundle.zip: %v", err)
		}
		if zr.Comment != "staged for transfer" {
			t.Errorf("comment %q", zr.Comment)
		}
		if len(zr.File) != 2 {
			t.Fatalf("bundle.zip holds %d members", len(zr.File))
		}
		for _, f := range zr.File {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			b.ReadFrom(r)
			r.Close()
			switch {
			case strings.HasSuffix(f.Name, ".eml"):
				if _, err := mail.ReadMessage(bytes.NewReader(b.Bytes())); err != nil {
					t.Errorf("%s in the archive is not a message: %v", f.Name, err)
				}
			case strings.HasSuffix(f.Name, ".jpg"):
				if _, err := jpeg.Decode(bytes.NewReader(b.Bytes())); err != nil {
					t.Errorf("%s in the archive is not a JPEG: %v", f.Name, err)
				}
			default:
				t.Errorf("unexpected member %s", f.Name)
			}
		}
	},
	"playbook-adversary-data-theft": func(t *testing.T, root string, _ *sandbox.FS) {
		data := read(t, root, "users/alice/staging/data.zip")
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("data.zip: %v", err)
		}
		var names []string
		for _, f := range zr.File {
			names = append(names, f.Name)
			r, _ := f.Open()
			var b bytes.Buffer
			b.ReadFrom(r)
			r.Close()
			// The member is the file as it stood, byte for byte.
			if want := read(t, root, "users/alice/staging/"+f.Name); !bytes.Equal(b.Bytes(), want) {
				t.Errorf("%s in the archive differs from the file on disk", f.Name)
			}
		}
		if strings.Join(names, ",") != "customers.csv,quarterly.csv" {
			t.Errorf("members = %v", names)
		}
	},
	"manifest-history": func(t *testing.T, root string, _ *sandbox.FS) {
		// Chrome counts microseconds from 1601; 2023-10-30T09:12:00Z is
		// 1698657120 seconds after the Unix epoch.
		chrome := exampleDB(t, filepath.Join(root, "Chrome", "Default", "History"))
		var first int64
		if err := chrome.QueryRow("SELECT visit_time FROM visits ORDER BY id LIMIT 1").Scan(&first); err != nil {
			t.Fatal(err)
		}
		if want := (int64(1698657120) + 11644473600) * 1e6; first != want {
			t.Errorf("chrome visit_time %d, want %d", first, want)
		}
		var downloads int
		chrome.QueryRow("SELECT COUNT(*) FROM downloads").Scan(&downloads)
		if downloads != 1 {
			t.Errorf("%d downloads recorded", downloads)
		}
		firefox := exampleDB(t, filepath.Join(root, "Firefox", "Profiles", "default", "places.sqlite"))
		var visits int
		if err := firefox.QueryRow("SELECT COUNT(*) FROM moz_historyvisits").Scan(&visits); err != nil {
			t.Fatal(err)
		}
		if visits != 3 {
			t.Errorf("%d firefox visits, want 3", visits)
		}
	},
	"playbook-browsing": func(t *testing.T, root string, _ *sandbox.FS) {
		chrome := exampleDB(t, filepath.Join(root, "Users", "User1", "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"))
		var urls int
		if err := chrome.QueryRow("SELECT COUNT(*) FROM urls").Scan(&urls); err != nil {
			t.Fatal(err)
		}
		if urls != 3 {
			t.Errorf("%d pages in the chrome profile, want 3", urls)
		}
		firefox := exampleDB(t, filepath.Join(root, "Users", "User2", "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "default", "places.sqlite"))
		var rev string
		if err := firefox.QueryRow("SELECT rev_host FROM moz_places ORDER BY id LIMIT 1").Scan(&rev); err != nil {
			t.Fatal(err)
		}
		if rev != "elpmaxe.ikiw." {
			t.Errorf("rev_host %q", rev)
		}
	},
	"playbook-insider-threat-exfil": func(t *testing.T, root string, _ *sandbox.FS) {
		left, _ := filepath.Glob(filepath.Join(root, "users", "jsmith", "Downloads", "attachment-*.zip"))
		if len(left) != 0 {
			t.Errorf("the final cleanup left %d attachments behind", len(left))
		}
	},
	"playbook-malware-lifecycle": func(t *testing.T, root string, fsys *sandbox.FS) {
		mustExist(t, root, "users/alice/AppData/Local/Temp/wupdmgr32.exe")
		// The dropper is a PE a tool can read, with the imports an imphash is
		// built from and the version resource Explorer shows.
		dropper := read(t, root, "users/alice/AppData/Local/Temp/wupdmgr32.exe")
		pf, err := pe.NewFile(bytes.NewReader(dropper))
		if err != nil {
			t.Fatalf("the dropper is not a PE: %v", err)
		}
		defer pf.Close()
		syms, err := pf.ImportedSymbols()
		if err != nil || !strings.Contains(strings.Join(syms, " "), "RegSetValueExW") {
			t.Errorf("imports = %v (%v)", syms, err)
		}
		if !bytes.Contains(dropper, utf16of("Windows Update Manager")) {
			t.Error("no version resource in the dropper")
		}
		if zipped := read(t, root, "users/alice/AppData/Local/Temp/exfil-ready.zip"); !bytes.HasPrefix(zipped, []byte("PK\x03\x04")) {
			t.Error("exfil-ready.zip is not a zip archive")
		}
		if reg := string(read(t, root, "users/alice/AppData/Roaming/.persistence.reg")); !strings.Contains(reg, `Temp\\wupdmgr32.exe`) {
			t.Errorf("the Run key does not name the dropper:\n%s", reg)
		}
		mustHaveStream(t, fsys, "users/alice/AppData/Local/Temp/wupdmgr32.exe", "Zone.Identifier", "ZoneId=3")
	},
	"playbook-windows-ads-motw": func(t *testing.T, _ string, fsys *sandbox.FS) {
		mustHaveStream(t, fsys, "users/winuser/downloads/installer.exe", "Zone.Identifier", "HostUrl=")
		mustHaveStream(t, fsys, "users/winuser/downloads/installer.exe", "Note", "")
	},
	"playbook-log-tampering": func(t *testing.T, root string, _ *sandbox.FS) {
		mustNotExist(t, root, "systems/server01/var/log/app.jsonl")
	},
	"playbook-log-rotate-and-truncate": func(t *testing.T, root string, _ *sandbox.FS) {
		if got := string(read(t, root, "systems/web01/var/log/access.log.1")); got != "2021-10-10T00:00:00Z GET /index.html 200\n" {
			t.Errorf("rotated log = %q", got)
		}
		if got := string(read(t, root, "systems/web01/var/log/access.log")); got != "2021-10-10T00:30:05Z GET /login 302\n" {
			t.Errorf("live log after truncate = %q", got)
		}
	},
	"playbook-persistence-artifacts": func(t *testing.T, root string, _ *sandbox.FS) {
		bat := string(read(t, root, "systems/workstation01/Users/Public/Startup/helper.bat"))
		if !strings.HasSuffix(bat, "\r\n") || strings.Contains(bat, `\r\n`) {
			t.Errorf("helper.bat should end in a real CRLF: %q", bat)
		}
		md := string(read(t, root, "systems/workstation01/Users/Public/Startup/readme.md"))
		if strings.Count(md, "\n") != 1 || strings.Contains(md, `\n`) {
			t.Errorf("readme.md should hold two real lines: %q", md)
		}
	},
	"playbook-email-thread": func(t *testing.T, root string, _ *sandbox.FS) {
		base := "Users/priyan.nair/AppData/Local/Microsoft/Outlook"
		emls, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(base), "*", "*.eml"))
		if len(emls) != 4 {
			t.Fatalf("found %d .eml files, want 4", len(emls))
		}
		for _, p := range emls {
			data, _ := os.ReadFile(p)
			msg, err := mail.ReadMessage(bytes.NewReader(data))
			if err != nil || msg.Header.Get("Message-Id") == "" || !bytes.Contains(data, []byte("\r\n")) {
				t.Errorf("%s: not a parseable CRLF message with a Message-ID (%v)", p, err)
			}
		}
		mbox := string(read(t, root, base+"/thread.mbox"))
		if n := strings.Count("\n"+mbox, "\nFrom "); n != 4 {
			t.Errorf("thread.mbox holds %d messages, want 4", n)
		}
	},
}

// TestExamples runs every shipped example through the command line, as a
// user would, and checks what each one is meant to produce.
func TestExamples(t *testing.T) {
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "out")
			args := []string{"--seed", fmt.Sprint(exampleSeed), "--" + string(exampleMode(path)), path}
			if runtime.GOOS != "windows" {
				args = append(args, "--on-unsupported=skip")
			}
			code, _, errOut := runCLI(t, append(args, root)...)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if rm := readManifest(t, root+".fsagen"); rm.Status != runinfo.StatusComplete || rm.Operations == 0 {
				t.Errorf("run manifest: status %q, %d operations", rm.Status, rm.Operations)
			}
			var files int
			filepath.WalkDir(root, func(_ string, d os.DirEntry, _ error) error {
				if d != nil && !d.IsDir() {
					files++
				}
				return nil
			})
			if files == 0 && name != "playbook-log-tampering" {
				t.Error("the example produced no files")
			}
			if check := exampleChecks[name]; check != nil {
				fsys, err := sandbox.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				defer fsys.Close()
				check(t, root, fsys)
			}
		})
	}
}

// globAll collects every path matching a pattern built from parts, joined
// under root with the platform's separator.
func globAll(t *testing.T, root string, parts ...string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	return got
}

func read(t *testing.T, root, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
	if err != nil {
		t.Errorf("%s: %v", p, err)
	}
	return b
}

func mustExist(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			t.Errorf("%s should exist: %v", p, err)
		}
	}
}

func mustNotExist(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); !os.IsNotExist(err) {
			t.Errorf("%s should not exist", p)
		}
	}
}

func mustBeEmpty(t *testing.T, root, dir string) {
	t.Helper()
	if got := entries(t, filepath.Join(root, filepath.FromSlash(dir))); len(got) != 0 {
		t.Errorf("%s should be empty, holds %v", dir, got)
	}
}

// mustHaveStream checks a named stream where the platform has them.
func mustHaveStream(t *testing.T, fsys *sandbox.FS, name, stream, contains string) {
	t.Helper()
	if !fsys.SupportsStreams() {
		return
	}
	data, err := fsys.ReadStream(name, stream)
	if err != nil {
		t.Errorf("%s:%s: %v", name, stream, err)
		return
	}
	if !strings.Contains(string(data), contains) {
		t.Errorf("%s:%s = %q, want it to contain %q", name, stream, data, contains)
	}
}

// exampleDB opens a generated SQLite database read-only and checks it is not
// corrupt before a test reads it.
func exampleDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		t.Fatalf("%s: integrity_check = %q, %v", path, check, err)
	}
	return db
}

// utf16of is how the version resource stores a string.
func utf16of(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
