package libgen

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"time"
)

// docxParts are the parts of a minimal WordprocessingML package, in the
// order they are written. The order is fixed so the archive's bytes are.
var docxParts = []struct{ name, body string }{
	{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
	{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
	{"word/document.xml", ""}, // filled in by docx
}

// docx returns a .docx holding text as one 12-point paragraph. Members are
// stored uncompressed, in a fixed order, with the given modification time, so
// the bytes depend on nothing but the arguments (not the Go release, as
// deflate would).
func docx(text string, modified time.Time) ([]byte, error) {
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(text)); err != nil {
		return nil, err
	}
	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">` + esc.String() + `</w:t></w:r></w:p></w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range docxParts {
		body := p.body
		if p.name == "word/document.xml" {
			body = document
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p.name, Method: zip.Store, Modified: modified.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
