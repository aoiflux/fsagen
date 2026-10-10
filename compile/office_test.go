package compile

import (
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestOfficeBlockRules: a .docm, .xlsx or .xlsm is that document without
// saying so, takes text as its content and the vba block only where a
// project goes; the macro's entry point belongs to its host, a module is
// named only where there is one to name, and the marker cannot break out of
// its string. A sheet takes only text its cells can hold.
func TestOfficeBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+"    path: Invoice.docm\n    format: docm\n    content: Please enable content.\n    vba: { entry_point: Document_Open }\n    docx: { author: victim }\n"+
		"  - action: create\n    path: budget.xlsm\n    vba: { module_name: Loader, marker: 'id 7' }\n    xlsx: { title: Budget }\n"+
		"  - action: create\n    path: plain.xlsx\n    format: xlsx\n    content: \"a\\nb\"\n")
	for i, want := range []spec.Format{spec.FormatDOCM, spec.FormatXLSM, spec.FormatXLSX} {
		if got := p.Ops[i].Format; got != want {
			t.Errorf("op %d format %q, want %q", i+1, got, want)
		}
	}
	if p.Ops[1].Random != 1024 {
		t.Errorf("an xlsm with no content gets %d characters of filler, want 1024", p.Ops[1].Random)
	}
	if s := VBAOf(p.Ops[0].Operation); s.Host != "word" || s.EntryPoint != "Document_Open" {
		t.Errorf("docm macro %+v", s)
	}
	if s := VBAOf(p.Ops[1].Operation); s.Host != "excel" || s.EntryPoint != "Auto_Open" || s.Module != "Loader" {
		t.Errorf("xlsm macro %+v", s)
	}

	long := strings.Repeat("x", 32768)
	for _, tc := range []struct{ name, body, want string }{
		{"vba on docx", "    path: a.docx\n    vba: {}\n", "only applies with format: docm or xlsm"},
		{"vba on xlsx", "    path: a.xlsx\n    vba: {}\n", "only applies with format: docm or xlsm"},
		{"xlsx block on docm", "    path: a.docm\n    xlsx: { title: t }\n", "only applies with format: xlsx or xlsm"},
		{"docx block on xlsm", "    path: a.xlsm\n    docx: { title: t }\n", "only applies with format: docx or docm"},
		{"excel entry in word", "    path: a.docm\n    vba: { entry_point: Workbook_Open }\n", "want one of: AutoOpen, Document_Open"},
		{"word entry in excel", "    path: a.xlsm\n    vba: { entry_point: AutoOpen }\n", "want one of: Auto_Open, Workbook_Open"},
		{"module for document event", "    path: a.docm\n    vba: { entry_point: Document_Open, module_name: M }\n", "no module to name"},
		{"module name", "    path: a.docm\n    vba: { module_name: 'my module' }\n", "not a VBA name"},
		{"document module", "    path: a.xlsm\n    vba: { module_name: Sheet1 }\n", "the document's own module"},
		{"marker quote", "    path: a.docm\n    vba: { marker: 'x\" : Shell \"calc' }\n", "no double quote"},
		{"marker long", "    path: a.docm\n    vba: { marker: '" + strings.Repeat("m", 201) + "' }\n", "1 to 200"},
		{"bad date", "    path: a.xlsx\n    xlsx: { created: soon }\n", "xlsx: created"},
		{"cell too long", "    path: a.xlsx\n    format: xlsx\n    content: " + long + "\n", "more than the 32767 a cell holds"},
		{"filler too long", "    path: a.xlsm\n    content_len: 32768\n", "one cell, which holds at most 32767"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
