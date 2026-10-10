package libgen

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// A .docx is a zip of XML parts. fsagen writes the four a reader needs plus
// the two property parts, because the dates inside docProps/core.xml are what
// a document-metadata tool reports, and a corpus whose documents have no
// internal dates teaches such a tool nothing. Members are stored
// uncompressed and in a fixed order, so the bytes depend on the arguments
// alone and not on the Go release. A .docm is the same with a VBA project
// beside the document, and a .xlsx or .xlsm the spreadsheet equivalent.

// DocxMeta is the document metadata a scenario can set.
type DocxMeta struct {
	Title    string
	Author   string
	Created  time.Time
	Modified time.Time
}

const (
	nsContentTypes = "http://schemas.openxmlformats.org/package/2006/content-types"
	nsRelationship = "http://schemas.openxmlformats.org/package/2006/relationships"
	nsOfficeDoc    = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	nsSpreadsheet  = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
)

// The content type and relationship that make a package macro-enabled.
const (
	ctVBAProject  = "application/vnd.ms-office.vbaProject"
	relVBAProject = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"
)

const xmlHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

// Docx returns a WordprocessingML package whose body is text.
func Docx(text string, meta DocxMeta) ([]byte, error) { return wordPackage(text, meta, nil) }

// Docm returns the same package with a VBA project beside the document: a
// macro-enabled document, which Word opens with its macros.
func Docm(text string, meta DocxMeta, vbaProject []byte) ([]byte, error) {
	return wordPackage(text, meta, vbaProject)
}

func wordPackage(text string, meta DocxMeta, vbaProject []byte) ([]byte, error) {
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(text)); err != nil {
		return nil, err
	}
	created, modified := packageDates(meta)

	main := "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	if vbaProject != nil {
		main = "application/vnd.ms-word.document.macroEnabled.main+xml"
	}
	contentTypes := contentTypesPart(vbaProject != nil,
		override{"/word/document.xml", main},
	)

	document := xmlHeader +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">` +
		esc.String() + `</w:t></w:r></w:p></w:body></w:document>`

	words := len(strings.Fields(text))
	app := xmlHeader +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">` +
		`<Application>fsagen</Application>` +
		fmt.Sprintf(`<Pages>1</Pages><Words>%d</Words><Characters>%d</Characters>`, words, len(text)) +
		`</Properties>`

	entries := []ZipEntry{
		{Name: "[Content_Types].xml", Data: []byte(contentTypes), Modified: modified},
		{Name: "_rels/.rels", Data: []byte(packageRels("word/document.xml")), Modified: modified},
		{Name: "word/document.xml", Data: []byte(document), Modified: modified},
	}
	if vbaProject != nil {
		entries = append(entries,
			ZipEntry{Name: "word/_rels/document.xml.rels", Data: []byte(rels(rel{"rId1", relVBAProject, "vbaProject.bin"})), Modified: modified},
			ZipEntry{Name: "word/vbaProject.bin", Data: vbaProject, Modified: modified},
		)
	}
	entries = append(entries,
		ZipEntry{Name: "docProps/core.xml", Data: []byte(coreProps(meta, created, modified)), Modified: modified},
		ZipEntry{Name: "docProps/app.xml", Data: []byte(app), Modified: modified},
	)
	return BuildZip(entries, "")
}

// MaxCellText is the most characters a spreadsheet cell holds, and
// MaxSheetRows the most rows a sheet has.
const (
	MaxCellText  = 32767
	MaxSheetRows = 1048576
)

// Xlsx returns a SpreadsheetML workbook with one sheet, Sheet1, whose
// column A holds text, a line to a row. Given a VBA project it is a
// macro-enabled workbook, whose workbook and sheet carry the code names of
// the project's document modules.
func Xlsx(text string, meta DocxMeta, vbaProject []byte) ([]byte, error) {
	rows, err := sheetRows(text)
	if err != nil {
		return nil, err
	}
	created, modified := packageDates(meta)

	main, workbookPr, sheetPr := "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", "", ""
	if vbaProject != nil {
		main = "application/vnd.ms-excel.sheet.macroEnabled.main+xml"
		workbookPr, sheetPr = `<workbookPr codeName="ThisWorkbook"/>`, `<sheetPr codeName="Sheet1"/>`
	}
	contentTypes := contentTypesPart(vbaProject != nil,
		override{"/xl/workbook.xml", main},
		override{"/xl/worksheets/sheet1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"},
		override{"/xl/styles.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"},
	)

	workbook := xmlHeader +
		`<workbook xmlns="` + nsSpreadsheet + `" xmlns:r="` + nsOfficeDoc + `">` + workbookPr +
		`<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`

	workbookRels := []rel{
		{"rId1", nsOfficeDoc + "/worksheet", "worksheets/sheet1.xml"},
		{"rId2", nsOfficeDoc + "/styles", "styles.xml"},
	}
	if vbaProject != nil {
		workbookRels = append(workbookRels, rel{"rId3", relVBAProject, "vbaProject.bin"})
	}

	sheet := xmlHeader +
		`<worksheet xmlns="` + nsSpreadsheet + `">` + sheetPr + `<sheetData>` + rows + `</sheetData></worksheet>`

	// The one style every cell takes: the smallest table Excel accepts.
	styles := xmlHeader +
		`<styleSheet xmlns="` + nsSpreadsheet + `">` +
		`<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>` +
		`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
		`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
		`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
		`<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>` +
		`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>` +
		`</styleSheet>`

	app := xmlHeader +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">` +
		`<Application>fsagen</Application></Properties>`

	entries := []ZipEntry{
		{Name: "[Content_Types].xml", Data: []byte(contentTypes), Modified: modified},
		{Name: "_rels/.rels", Data: []byte(packageRels("xl/workbook.xml")), Modified: modified},
		{Name: "xl/workbook.xml", Data: []byte(workbook), Modified: modified},
		{Name: "xl/_rels/workbook.xml.rels", Data: []byte(rels(workbookRels...)), Modified: modified},
		{Name: "xl/worksheets/sheet1.xml", Data: []byte(sheet), Modified: modified},
		{Name: "xl/styles.xml", Data: []byte(styles), Modified: modified},
	}
	if vbaProject != nil {
		entries = append(entries, ZipEntry{Name: "xl/vbaProject.bin", Data: vbaProject, Modified: modified})
	}
	entries = append(entries,
		ZipEntry{Name: "docProps/core.xml", Data: []byte(coreProps(meta, created, modified)), Modified: modified},
		ZipEntry{Name: "docProps/app.xml", Data: []byte(app), Modified: modified},
	)
	return BuildZip(entries, "")
}

// sheetRows is text as rows of column A, one inline string per line. An
// empty line is an empty row, which a sheet leaves out.
func sheetRows(text string) (string, error) {
	if text == "" {
		return "", nil
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > MaxSheetRows {
		return "", fmt.Errorf("%d lines is more than the %d rows a sheet has", len(lines), MaxSheetRows)
	}
	var b strings.Builder
	for i, line := range lines {
		if line == "" {
			continue
		}
		if n := len(utf16.Encode([]rune(line))); n > MaxCellText {
			return "", fmt.Errorf("line %d has %d characters, more than the %d a cell holds", i+1, n, MaxCellText)
		}
		fmt.Fprintf(&b, `<row r="%d"><c r="A%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c></row>`, i+1, i+1, escape(line))
	}
	return b.String(), nil
}

// packageDates are a package's creation and modification dates; the second
// defaults to the first.
func packageDates(meta DocxMeta) (created, modified time.Time) {
	if meta.Modified.IsZero() {
		return meta.Created, meta.Created
	}
	return meta.Created, meta.Modified
}

// override is one part's content type.
type override struct{ part, contentType string }

// contentTypesPart is [Content_Types].xml: the defaults every package needs,
// the one a VBA project needs, and the parts' own types.
func contentTypesPart(vba bool, parts ...override) string {
	out := xmlHeader + `<Types xmlns="` + nsContentTypes + `">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>`
	if vba {
		out += `<Default Extension="bin" ContentType="` + ctVBAProject + `"/>`
	}
	parts = append(parts,
		override{"/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"},
		override{"/docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml"},
	)
	for _, p := range parts {
		out += `<Override PartName="` + p.part + `" ContentType="` + p.contentType + `"/>`
	}
	return out + `</Types>`
}

// packageRels is the package's own relationships: its main part and the
// two property parts.
func packageRels(main string) string {
	return rels(
		rel{"rId1", nsOfficeDoc + "/officeDocument", main},
		rel{"rId2", nsOfficeDoc + "/metadata/core-properties", "docProps/core.xml"},
		rel{"rId3", nsOfficeDoc + "/extended-properties", "docProps/app.xml"},
	)
}

// rel is one relationship: its id, type and target.
type rel struct{ id, typ, target string }

func rels(rs ...rel) string {
	out := xmlHeader + `<Relationships xmlns="` + nsRelationship + `">`
	for _, r := range rs {
		out += `<Relationship Id="` + r.id + `" Type="` + r.typ + `" Target="` + r.target + `"/>`
	}
	return out + `</Relationships>`
}

// coreProps is docProps/core.xml: the title, author and dates a metadata
// tool reports.
func coreProps(meta DocxMeta, created, modified time.Time) string {
	author := or(meta.Author, "fsagen")
	return xmlHeader +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"` +
		` xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"` +
		` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<dc:title>` + escape(meta.Title) + `</dc:title>` +
		`<dc:creator>` + escape(author) + `</dc:creator>` +
		`<cp:lastModifiedBy>` + escape(author) + `</cp:lastModifiedBy>` +
		w3cdtf("dcterms:created", created) + w3cdtf("dcterms:modified", modified) +
		`</cp:coreProperties>`
}

// w3cdtf writes one dcterms date, or nothing when the scenario gives none:
// an empty date element is worse than an absent one.
func w3cdtf(tag string, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return `<` + tag + ` xsi:type="dcterms:W3CDTF">` + t.UTC().Format("2006-01-02T15:04:05Z") + `</` + tag + `>`
}

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// CheckSheetText reports text a sheet cannot hold: a line longer than a cell
// or more lines than a sheet has rows.
func CheckSheetText(text string) error {
	_, err := sheetRows(text)
	return err
}
