package libgen

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// PDFMeta is the document metadata written into the PDF trailer. Forensic
// exercises lean on these values, so every one is settable and the dates are
// pinned rather than taken from the wall clock: gofpdf emits a constant /ID,
// which makes a pinned-date render byte-for-byte reproducible.
type PDFMeta struct {
	Title    string
	Author   string
	Subject  string
	Keywords string
	Creator  string
	Producer string
	Created  time.Time
	Modified time.Time
	PageSize string
}

const (
	pdfMarginLeft  = 20.0
	pdfMarginTop   = 20.0
	pdfMarginRight = 20.0
	pdfLineHeight  = 5.0
	pdfCellPad     = 1.5
)

// RenderPDF turns a lightweight Markdown subset into a paginated PDF.
//
// Recognised syntax: "#", "##" and "###" headings; "-" or "*" bullets;
// "|a|b|c|" tables with an optional "|---|---|" separator marking the row above
// as a header; fenced blocks delimited by ``` set in a monospace face; "---" on
// its own as a horizontal rule; and blank lines as paragraph breaks. Anything
// else is body text, wrapped to the page width.
//
// Inline markers are deliberately NOT interpreted or stripped. Report bodies
// carry redaction masks, glob patterns and regexes; silently rewriting
// "Wint3r-R0t****-2026" into something that reads like a real password is worse
// than showing a literal asterisk.
func RenderPDF(body string, meta PDFMeta) ([]byte, error) {
	size := "A4"
	switch strings.ToUpper(strings.TrimSpace(meta.PageSize)) {
	case "LETTER":
		size = "Letter"
	case "A3":
		size = "A3"
	case "A5":
		size = "A5"
	case "", "A4":
		size = "A4"
	default:
		return nil, fmt.Errorf("unsupported pdf page_size %q (want A4, A3, A5 or Letter)", meta.PageSize)
	}

	pdf := gofpdf.New("P", "mm", size, "")
	pdf.SetMargins(pdfMarginLeft, pdfMarginTop, pdfMarginRight)
	pdf.SetAutoPageBreak(true, 20)
	// Without this, font resources are emitted in Go map order and two runs of
	// the same input produce different bytes. Reproducibility is the whole
	// point of --seed, and it is what lets one artifact be attached to a
	// message and land byte-identical to its copy on disk.
	pdf.SetCatalogSort(true)

	// isUTF8 makes gofpdf store the value as UTF-16BE. Flagging it only when
	// the string actually needs it keeps plain metadata greppable in the raw
	// PDF, which is how these values usually get discovered.
	if meta.Title != "" {
		pdf.SetTitle(meta.Title, needsUTF16(meta.Title))
	}
	if meta.Author != "" {
		pdf.SetAuthor(meta.Author, needsUTF16(meta.Author))
	}
	if meta.Subject != "" {
		pdf.SetSubject(meta.Subject, needsUTF16(meta.Subject))
	}
	if meta.Keywords != "" {
		pdf.SetKeywords(meta.Keywords, needsUTF16(meta.Keywords))
	}
	if meta.Creator != "" {
		pdf.SetCreator(meta.Creator, needsUTF16(meta.Creator))
	}
	if meta.Producer != "" {
		pdf.SetProducer(meta.Producer, needsUTF16(meta.Producer))
	}
	if !meta.Created.IsZero() {
		pdf.SetCreationDate(meta.Created)
	}
	if !meta.Modified.IsZero() {
		pdf.SetModificationDate(meta.Modified)
	}

	r := &pdfRenderer{
		pdf: pdf,
		// Core fonts are cp1252; without this an em dash or curly quote in the
		// source becomes mojibake.
		tr: pdf.UnicodeTranslatorFromDescriptor(""),
	}
	r.width, _ = pdf.GetPageSize()
	r.width -= pdfMarginLeft + pdfMarginRight

	pdf.AddPage()
	r.writeBody(body)

	if pdf.Err() {
		return nil, fmt.Errorf("render pdf: %w", pdf.Error())
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write pdf: %w", err)
	}
	return buf.Bytes(), nil
}

type pdfRenderer struct {
	pdf   *gofpdf.Fpdf
	tr    func(string) string
	width float64
}

func (r *pdfRenderer) writeBody(body string) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		trimmed := strings.TrimSpace(line)

		switch {
		// The two block cases consume more than one line. Each returns the
		// index of the last line it used, and the loop advances past it, so
		// both follow the same convention.
		case strings.HasPrefix(trimmed, codeFence):
			var block []string
			block, i = fencedBlock(lines, i)
			r.writeCode(block)

		case isTableRow(trimmed):
			var block []string
			block, i = tableBlock(lines, i)
			r.writeTable(block)

		case trimmed == "":
			r.pdf.Ln(pdfLineHeight * 0.6)

		case trimmed == "---" || trimmed == "***" || trimmed == "___":
			r.writeRule()

		case strings.HasPrefix(trimmed, "### "):
			r.writeHeading(strings.TrimPrefix(trimmed, "### "), 11, 3)
		case strings.HasPrefix(trimmed, "## "):
			r.writeHeading(strings.TrimPrefix(trimmed, "## "), 13, 4)
		case strings.HasPrefix(trimmed, "# "):
			r.writeHeading(strings.TrimPrefix(trimmed, "# "), 16, 5)

		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			r.writeBullet(trimmed[2:])

		default:
			r.writeParagraph(line)
		}
	}
}

func (r *pdfRenderer) writeHeading(text string, size float64, gap float64) {
	r.pdf.Ln(gap * 0.6)
	r.pdf.SetFont("Arial", "B", size)
	r.pdf.MultiCell(r.width, size*0.55, r.tr(text), "", "L", false)
	r.pdf.Ln(1.5)
}

func (r *pdfRenderer) writeParagraph(text string) {
	r.pdf.SetFont("Arial", "", 10)
	r.pdf.MultiCell(r.width, pdfLineHeight, r.tr(text), "", "L", false)
}

func (r *pdfRenderer) writeBullet(text string) {
	r.pdf.SetFont("Arial", "", 10)
	x := r.pdf.GetX()
	r.pdf.CellFormat(5, pdfLineHeight, r.tr("•"), "", 0, "L", false, 0, "")
	r.pdf.SetX(x + 5)
	r.pdf.MultiCell(r.width-5, pdfLineHeight, r.tr(text), "", "L", false)
	r.pdf.SetX(x)
}

func (r *pdfRenderer) writeCode(lines []string) {
	r.pdf.SetFont("Courier", "", 9)
	r.pdf.SetFillColor(245, 245, 245)
	for _, l := range lines {
		r.pdf.MultiCell(r.width, 4.2, r.tr(l), "", "L", true)
	}
	r.pdf.Ln(2)
}

func (r *pdfRenderer) writeRule() {
	y := r.pdf.GetY() + 1
	r.pdf.SetDrawColor(180, 180, 180)
	r.pdf.Line(pdfMarginLeft, y, pdfMarginLeft+r.width, y)
	r.pdf.Ln(3)
}

// writeTable renders a pipe-delimited block. Cells wrap, so row height is the
// tallest cell in the row, and a header row repeats after a page break.
func (r *pdfRenderer) writeTable(block []string) {
	var rows [][]string
	headerRows := 0
	for _, line := range block {
		cells := splitTableRow(line)
		if !isTableSeparator(cells) {
			rows = append(rows, cells)
			continue
		}
		// The rule under the first row is what makes those cells a header.
		if len(rows) > 0 && headerRows == 0 {
			headerRows = len(rows)
		}
	}
	if len(rows) == 0 {
		return
	}

	cols := 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
	}
	widths := r.columnWidths(rows, cols)

	r.pdf.Ln(1)
	for idx, row := range rows {
		r.writeTableRow(row, widths, idx < headerRows)
	}
	r.pdf.Ln(2)
}

// columnWidths distributes the page width in proportion to the longest cell in
// each column, with a floor so a narrow column stays readable.
func (r *pdfRenderer) columnWidths(rows [][]string, cols int) []float64 {
	weights := make([]float64, cols)
	var total float64
	for c := 0; c < cols; c++ {
		weights[c] = float64(min(longestCell(rows, c), maxWeightedCell))
		total += weights[c]
	}

	widths := make([]float64, cols)
	minWidth := 14.0
	if minWidth*float64(cols) > r.width {
		minWidth = r.width / float64(cols)
	}
	var assigned float64
	for c := range widths {
		widths[c] = r.width * weights[c] / total
		if widths[c] < minWidth {
			widths[c] = minWidth
		}
		assigned += widths[c]
	}
	// Rescale if the minimum-width floor pushed the row past the page.
	if assigned > r.width {
		for c := range widths {
			widths[c] *= r.width / assigned
		}
	}
	return widths
}

func (r *pdfRenderer) writeTableRow(row []string, widths []float64, header bool) {
	style := ""
	if header {
		style = "B"
	}
	r.pdf.SetFont("Arial", style, 9)

	// Wrap every cell first so the row can be drawn at a uniform height.
	wrapped := make([][]string, len(widths))
	maxLines := 1
	for c := range widths {
		text := ""
		if c < len(row) {
			text = row[c]
		}
		lines := r.pdf.SplitLines([]byte(r.tr(text)), widths[c]-2*pdfCellPad)
		if len(lines) == 0 {
			lines = [][]byte{{}}
		}
		for _, l := range lines {
			wrapped[c] = append(wrapped[c], string(l))
		}
		if len(wrapped[c]) > maxLines {
			maxLines = len(wrapped[c])
		}
	}
	height := float64(maxLines)*4.2 + 2*pdfCellPad

	if r.pdf.GetY()+height > r.pageBreakLimit() {
		r.pdf.AddPage()
	}

	x, y := pdfMarginLeft, r.pdf.GetY()
	if header {
		r.pdf.SetFillColor(232, 232, 232)
	} else {
		r.pdf.SetFillColor(255, 255, 255)
	}
	r.pdf.SetDrawColor(150, 150, 150)

	for c := range widths {
		r.pdf.Rect(x, y, widths[c], height, "FD")
		r.pdf.SetXY(x+pdfCellPad, y+pdfCellPad)
		for _, line := range wrapped[c] {
			r.pdf.CellFormat(widths[c]-2*pdfCellPad, 4.2, line, "", 2, "L", false, 0, "")
		}
		x += widths[c]
	}
	r.pdf.SetXY(pdfMarginLeft, y+height)
}

func (r *pdfRenderer) pageBreakLimit() float64 {
	_, pageHeight := r.pdf.GetPageSize()
	_, _, _, bottom := r.pdf.GetMargins()
	return pageHeight - bottom
}

func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func isTableSeparator(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		c = strings.TrimSpace(strings.Trim(c, ":"))
		if c == "" || strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

// needsUTF16 reports whether a metadata value contains anything outside
// printable ASCII and therefore cannot be stored as a plain PDF string.
func needsUTF16(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return true
		}
	}
	return false
}

// codeFence opens and closes a fenced code block.
const codeFence = "```"

// maxWeightedCell caps how much one long cell may widen its column, so a single
// wide value cannot squeeze every other column to nothing.
const maxWeightedCell = 40

// isTableRow reports whether a line is a row of a pipe table.
func isTableRow(trimmed string) bool {
	return strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|")
}

// fencedBlock is the lines inside a fenced code block, and the index of the
// line the block ends on. An unterminated fence runs to the end of the body.
func fencedBlock(lines []string, open int) ([]string, int) {
	var block []string
	i := open + 1
	for ; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), codeFence) {
			break
		}
		block = append(block, lines[i])
	}
	return block, min(i, len(lines)-1)
}

// tableBlock is the run of table rows starting at first, and the index of the
// last one.
func tableBlock(lines []string, first int) ([]string, int) {
	var block []string
	i := first
	for ; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if !isTableRow(t) {
			break
		}
		block = append(block, t)
	}
	return block, i - 1
}

// longestCell is the length, in runes, of the longest value in one column. It
// is at least 1, so an empty column still has a width.
func longestCell(rows [][]string, c int) int {
	longest := 1
	for _, row := range rows {
		if c < len(row) {
			longest = max(longest, len([]rune(row[c])))
		}
	}
	return longest
}
