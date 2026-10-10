//go:build windows

package libgen

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// officeScript opens every .docm and .xlsm in a directory in Word and Excel
// with every macro forcibly disabled, prints what each application sees, and
// saves each document again under resaved. It refuses to touch an Office
// that is already running, and stops the ones it started.
const officeScript = `param([string]$Dir)
$ErrorActionPreference = 'Stop'
if (Get-Process WINWORD, EXCEL -ErrorAction SilentlyContinue) { 'RUNNING'; exit 0 }
$out = Join-Path $Dir 'resaved'
New-Item -ItemType Directory -Force $out | Out-Null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $word.AutomationSecurity = 3
    foreach ($f in Get-ChildItem $Dir -Filter *.docm) {
        $doc = $word.Documents.Open($f.FullName)
        'DOC|{0}|{1}|{2}' -f $f.Name, $doc.HasVBProject, $doc.Content.Text.Trim()
        $doc.SaveAs2((Join-Path $out $f.Name), 13)
        $doc.Close(0)
    }
    $word.Quit(0)
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.AutomationSecurity = 3
    foreach ($f in Get-ChildItem $Dir -Filter *.xlsm) {
        $wb = $excel.Workbooks.Open($f.FullName)
        'BOOK|{0}|{1}|{2}|{3}|{4}' -f $f.Name, $wb.HasVBProject, $wb.Worksheets.Item(1).Range('A1').Value2, $wb.CodeName, $wb.Worksheets.Item(1).CodeName
        $wb.Close($false)
    }
    $excel.Quit()
} finally {
    Start-Sleep -Seconds 3
    Get-Process WINWORD, EXCEL -ErrorAction SilentlyContinue | Stop-Process -Force
}
`

// TestMacroDocumentsOpenInOffice: Word and Excel open each macro-enabled
// document fsagen writes, with every macro forcibly disabled, and find its
// project. Word goes further: it compiles the project's source, and saves the
// document back with a project of its own making, whose source is fsagen's
// byte for byte. Opt-in with FSAGEN_OFFICE=1, as it starts Word and Excel;
// skipped where either is already running.
func TestMacroDocumentsOpenInOffice(t *testing.T) {
	if os.Getenv("FSAGEN_OFFICE") != "1" {
		t.Skip("set FSAGEN_OFFICE=1 to open the documents in Word and Excel")
	}
	dir := t.TempDir()
	specs := map[string]VBASpec{
		"autoopen.docm": {Host: VBAWord, EntryPoint: "AutoOpen", Module: "Updater", Marker: "FSAGEN-VBA:word"},
		"docopen.docm":  {Host: VBAWord, EntryPoint: "Document_Open", Marker: "FSAGEN-VBA:document"},
		"autoopen.xlsm": {Host: VBAExcel, EntryPoint: "Auto_Open", Marker: "FSAGEN-VBA:excel"},
		"bookopen.xlsm": {Host: VBAExcel, EntryPoint: "Workbook_Open", Marker: "FSAGEN-VBA:workbook"},
	}
	meta := DocxMeta{Author: "fsagen", Created: time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)}
	for name, spec := range specs {
		vba, err := BuildVBAProject(spec, prng.Root(1).Derive(name).Stream())
		if err != nil {
			t.Fatal(err)
		}
		var b []byte
		if spec.Host == VBAWord {
			b, err = Docm("Opened by Word.", meta, vba)
		} else {
			b, err = Xlsx("Opened by Excel.", meta, vba)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(t.TempDir(), "office.ps1")
	if err := os.WriteFile(script, []byte(officeScript), 0o644); err != nil {
		t.Fatal(err)
	}
	// Windows PowerShell 5.1 leaves Word waiting on the save; PowerShell 7
	// does not.
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell 7 (pwsh) drives Office here, and it is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Dir", dir).CombinedOutput()
	if strings.TrimSpace(string(out)) == "RUNNING" {
		t.Skip("Word or Excel is already running; not touching it")
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	seen := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		f := strings.Split(line, "|")
		switch {
		case f[0] == "DOC" && len(f) == 4:
			seen++
			if f[2] != "True" || f[3] != "Opened by Word." {
				t.Errorf("Word sees %s as: project %s, text %q", f[1], f[2], f[3])
			}
		case f[0] == "BOOK" && len(f) == 6:
			seen++
			if f[2] != "True" || f[3] != "Opened by Excel." || f[4] != "ThisWorkbook" || f[5] != "Sheet1" {
				t.Errorf("Excel sees %s as: project %s, A1 %q, code names %s and %s", f[1], f[2], f[3], f[4], f[5])
			}
		}
	}
	if seen != len(specs) {
		t.Fatalf("Office reported %d of %d documents:\n%s", seen, len(specs), out)
	}

	for name, spec := range specs {
		if spec.Host != VBAWord {
			continue
		}
		modules, compiled, err := wordSavedSource(filepath.Join(dir, "resaved", name))
		if err != nil {
			t.Errorf("%s as Word saved it: %v", name, err)
			continue
		}
		if !compiled {
			t.Errorf("%s: Word saved the project without compiling it", name)
		}
		for _, m := range VBAModules(spec) {
			if modules[m.Name] != m.Source {
				t.Errorf("%s: Word saved module %s as\n%s\nwant\n%s", name, m.Name, modules[m.Name], m.Source)
			}
		}
	}
}

// wordSavedSource reads each module's source from the VBA project of a
// document Word saved, and whether Word compiled it (its _VBA_PROJECT names
// a version and so carries a performance cache).
func wordSavedSource(path string) (map[string]string, bool, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, false, err
	}
	defer zr.Close()
	var bin []byte
	for _, f := range zr.File {
		if f.Name == "word/vbaProject.bin" {
			r, err := f.Open()
			if err != nil {
				return nil, false, err
			}
			bin, err = io.ReadAll(r)
			r.Close()
			if err != nil {
				return nil, false, err
			}
		}
	}
	if bin == nil {
		return nil, false, errors.New("no word/vbaProject.bin")
	}
	f, err := readCFB(bin)
	if err != nil {
		return nil, false, err
	}
	compiled := !bytes.Equal(f.streams["VBA/_VBA_PROJECT"][2:4], []byte{0xFF, 0xFF})
	dir, err := ovbaDecompress(f.streams["VBA/dir"])
	if err != nil {
		return nil, false, err
	}
	recs, err := dirRecords(dir)
	if err != nil {
		return nil, false, err
	}
	modules := map[string]string{}
	var name, stream string
	for _, r := range recs {
		id, data := r[0].(uint16), r[1].([]byte)
		switch id {
		case 0x0019:
			name = string(data)
		case 0x001A:
			stream = string(data)
		case 0x0031:
			raw := f.streams["VBA/"+stream]
			off := int(binary.LittleEndian.Uint32(data))
			if off > len(raw) {
				return nil, false, errors.New("module offset past its stream")
			}
			src, err := ovbaDecompress(raw[off:])
			if err != nil {
				return nil, false, err
			}
			modules[name] = string(src)
		}
	}
	return modules, compiled, nil
}
