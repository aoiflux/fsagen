package manifest

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// zipParts reads every part of an Office package.
func zipParts(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	parts := map[string][]byte{}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		parts[f.Name] = b
	}
	return parts
}

// TestOfficeDocumentsParse: a .docm and a .xlsm are packages whose content
// types say they carry macros and whose VBA project is where their main
// part's relationship points; a .xlsx has its text in its cells and no
// project at all. Every XML part is well formed. What is inside the projects
// is read back by the libgen tests, by the conformance module, and by Word.
func TestOfficeDocumentsParse(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
operations:
  - action: create
    path: mail/Invoice.docm
    format: docm
    content: Please enable content to view this invoice.
    docx: { author: victim }
    vba: { entry_point: Document_Open }
  - action: create
    path: mail/budget.xlsm
  - action: create
    path: mail/again.xlsm
  - action: create
    path: share/list.xlsx
    format: xlsx
    content: "alpha\nbeta"
`, nil)

	type want struct {
		path, main, project, rels string
	}
	for _, w := range []want{
		{"mail/Invoice.docm", "application/vnd.ms-word.document.macroEnabled.main+xml", "word/vbaProject.bin", "word/_rels/document.xml.rels"},
		{"mail/budget.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.main+xml", "xl/vbaProject.bin", "xl/_rels/workbook.xml.rels"},
		{"share/list.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", "", "xl/_rels/workbook.xml.rels"},
	} {
		parts := zipParts(t, readOut(t, root, w.path))
		for name, b := range parts {
			if strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".rels") {
				if err := xml.Unmarshal(b, new(struct{})); err != nil {
					t.Errorf("%s %s: %v", w.path, name, err)
				}
			}
		}
		types := string(parts["[Content_Types].xml"])
		if !strings.Contains(types, `ContentType="`+w.main+`"`) {
			t.Errorf("%s content types: %s", w.path, types)
		}
		rels := string(parts[w.rels])
		if w.project == "" {
			if strings.Contains(types, "vbaProject") || strings.Contains(rels, "vbaProject") {
				t.Errorf("%s is not macro-enabled but mentions a project", w.path)
			}
			continue
		}
		if !bytes.HasPrefix(parts[w.project], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
			t.Errorf("%s: %s is not a compound file", w.path, w.project)
		}
		if !strings.Contains(rels, `Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"`) {
			t.Errorf("%s relationships: %s", w.path, rels)
		}
	}

	docm := zipParts(t, readOut(t, root, "mail/Invoice.docm"))
	if !strings.Contains(string(docm["word/document.xml"]), "Please enable content") || !strings.Contains(string(docm["docProps/core.xml"]), "<dc:creator>victim</dc:creator>") {
		t.Error("the document's text or author is missing")
	}
	xlsm := zipParts(t, readOut(t, root, "mail/budget.xlsm"))
	if !strings.Contains(string(xlsm["xl/workbook.xml"]), `codeName="ThisWorkbook"`) || !strings.Contains(string(xlsm["xl/worksheets/sheet1.xml"]), `codeName="Sheet1"`) {
		t.Error("the workbook and sheet do not carry the project's code names")
	}
	// Two workbooks with no marker of their own draw different ones.
	again := zipParts(t, readOut(t, root, "mail/again.xlsm"))
	if bytes.Equal(xlsm["xl/vbaProject.bin"], again["xl/vbaProject.bin"]) {
		t.Error("two macro-enabled workbooks carry the same project")
	}
	sheet := string(zipParts(t, readOut(t, root, "share/list.xlsx"))["xl/worksheets/sheet1.xml"])
	if !strings.Contains(sheet, `<c r="A1" t="inlineStr"><is><t xml:space="preserve">alpha</t></is></c>`) || !strings.Contains(sheet, `r="A2"`) {
		t.Errorf("sheet: %s", sheet)
	}
}
