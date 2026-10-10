package libgen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// TestVBAReadByOlevba: olevba, the oletools scanner analysts point at a
// suspect document first, extracts each generated macro with its marker and
// reports its entry point as the one thing it runs on its own (AutoExec), and
// nothing a malicious macro would show. The single other finding is on
// Excel's projects: the class GUIDs in the Attribute VB_Base lines of
// ThisWorkbook and Sheet1, which every Excel project carries and which olevba
// reads as hex strings in a workbook Excel itself wrote too. Skipped where
// olevba is not on the PATH.
func TestVBAReadByOlevba(t *testing.T) {
	olevba, err := exec.LookPath("olevba")
	if err != nil {
		t.Skip("olevba (oletools) is not installed")
	}
	dir := t.TempDir()
	specs := map[string]VBASpec{
		"a.docm": {Host: VBAWord, EntryPoint: "AutoOpen", Marker: "FSAGEN-VBA:hijklmnopqrstuvg"},
		"b.docm": {Host: VBAWord, EntryPoint: "Document_Open", Marker: "FSAGEN-VBA:b"},
		"c.xlsm": {Host: VBAExcel, EntryPoint: "Auto_Open", Module: "Loader", Marker: "FSAGEN-VBA:c"},
		"d.xlsm": {Host: VBAExcel, EntryPoint: "Workbook_Open", Marker: "FSAGEN-VBA:d"},
	}
	var files []string
	for name, spec := range specs {
		vba, err := BuildVBAProject(spec, prng.Root(1).Derive(name).Stream())
		if err != nil {
			t.Fatal(err)
		}
		meta := DocxMeta{Created: time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)}
		var b []byte
		if spec.Host == VBAWord {
			b, err = Docm("text", meta, vba)
		} else {
			b, err = Xlsx("text", meta, vba)
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	out, err := exec.Command(olevba, append([]string{"-j"}, files...)...).Output()
	if err != nil {
		t.Fatalf("olevba: %v\n%s", err, out)
	}
	var results []struct {
		File     string                           `json:"file"`
		Type     string                           `json:"type"`
		Macros   []struct{ Code string }          `json:"macros"`
		Analysis []struct{ Type, Keyword string } `json:"analysis"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("olevba -j: %v\n%s", err, out)
	}
	seen := 0
	for _, r := range results {
		spec, ok := specs[filepath.Base(r.File)]
		if !ok {
			continue
		}
		seen++
		var code string
		for _, m := range r.Macros {
			code += m.Code
		}
		if !strings.Contains(code, spec.EntryPoint+"()") || !strings.Contains(code, `"`+spec.Marker+`"`) {
			t.Errorf("%s: olevba extracted\n%s", r.File, code)
		}
		var autoexec []string
		for _, a := range r.Analysis {
			switch {
			case a.Type == "AutoExec":
				autoexec = append(autoexec, a.Keyword)
			case a.Type == "Suspicious" && a.Keyword == "Hex Strings" && spec.Host == VBAExcel:
			case a.Type == "Hex String" && spec.Host == VBAExcel:
			default:
				t.Errorf("%s: olevba reports %s %q", r.File, a.Type, a.Keyword)
			}
		}
		if !slices.Contains(autoexec, spec.EntryPoint) {
			t.Errorf("%s: AutoExec %v, want %s", r.File, autoexec, spec.EntryPoint)
		}
	}
	if seen != len(specs) {
		t.Errorf("olevba reported on %d of %d files", seen, len(specs))
	}
}
