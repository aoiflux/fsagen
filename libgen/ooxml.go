package libgen

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// A .docx is a zip of XML parts. fsagen writes the four a reader needs plus
// the two property parts, because the dates inside docProps/core.xml are what
// a document-metadata tool reports, and a corpus whose documents have no
// internal dates teaches such a tool nothing. Members are stored
// uncompressed and in a fixed order, so the bytes depend on the arguments
// alone and not on the Go release.

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
)

// Docx returns a WordprocessingML package whose body is text.
func Docx(text string, meta DocxMeta) ([]byte, error) {
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(text)); err != nil {
		return nil, err
	}
	author := or(meta.Author, "fsagen")
	created, modified := meta.Created, meta.Modified
	if modified.IsZero() {
		modified = created
	}

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Types xmlns="` + nsContentTypes + `">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		`<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>` +
		`</Types>`

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Relationships xmlns="` + nsRelationship + `">` +
		`<Relationship Id="rId1" Type="` + nsOfficeDoc + `/officeDocument" Target="word/document.xml"/>` +
		`<Relationship Id="rId2" Type="` + nsOfficeDoc + `/metadata/core-properties" Target="docProps/core.xml"/>` +
		`<Relationship Id="rId3" Type="` + nsOfficeDoc + `/extended-properties" Target="docProps/app.xml"/>` +
		`</Relationships>`

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">` +
		esc.String() + `</w:t></w:r></w:p></w:body></w:document>`

	core := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"` +
		` xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"` +
		` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<dc:title>` + escape(meta.Title) + `</dc:title>` +
		`<dc:creator>` + escape(author) + `</dc:creator>` +
		`<cp:lastModifiedBy>` + escape(author) + `</cp:lastModifiedBy>` +
		w3cdtf("dcterms:created", created) + w3cdtf("dcterms:modified", modified) +
		`</cp:coreProperties>`

	words := len(strings.Fields(text))
	app := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">` +
		`<Application>fsagen</Application>` +
		fmt.Sprintf(`<Pages>1</Pages><Words>%d</Words><Characters>%d</Characters>`, words, len(text)) +
		`</Properties>`

	entries := []ZipEntry{
		{Name: "[Content_Types].xml", Data: []byte(contentTypes), Modified: modified},
		{Name: "_rels/.rels", Data: []byte(rels), Modified: modified},
		{Name: "word/document.xml", Data: []byte(document), Modified: modified},
		{Name: "docProps/core.xml", Data: []byte(core), Modified: modified},
		{Name: "docProps/app.xml", Data: []byte(app), Modified: modified},
	}
	return BuildZip(entries, "")
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
