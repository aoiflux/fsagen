package manifest

import (
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// mp4Duration is how long the video a scenario asks for claims to be. It is
// fixed because nothing reads it but a metadata tool, and a knob nobody turns
// is a knob that goes untested.
const mp4Duration = 3 * time.Second

// defaultPESections are the sections an executable gets when the scenario
// does not list its own: the shape of an ordinary small binary.
var defaultPESections = []spec.PeSection{
	{Name: ".text", Size: 1024},
	{Name: ".rdata", Size: 512},
	{Name: ".data", Size: 256},
}

// buildContent is the bytes an operation writes. Without a format that is its
// content, or the filler compile decided it needs; with one, it is a file of
// that type built around them.
func buildContent(c compile.Op) ([]byte, error) {
	op := c.Operation
	body := contentOf(c)

	switch op.Format {
	case "", "raw", "text":
		return body, nil

	case "pdf":
		meta, err := pdfMeta(op)
		if err != nil {
			return nil, err
		}
		return libgen.RenderPDF(string(body), meta)

	case "docx":
		meta, err := docxMeta(op, c.When)
		if err != nil {
			return nil, err
		}
		return libgen.Docx(string(body), meta)

	case "pe":
		return buildPE(c, body)

	case "zip":
		return libgen.ZipFiller("data.bin", body, c.When)

	case "png":
		return libgen.PNG(libgen.DefaultImageSize, libgen.DefaultImageSize, c.Rand.Derive("image").Stream(), body)

	case "jpeg":
		return libgen.JPEG(libgen.DefaultImageSize, libgen.DefaultImageSize, c.Rand.Derive("image").Stream(), body)

	case "mp4":
		return libgen.MP4(c.When, mp4Duration, 320, 240, body), nil

	case "chrome_history", "firefox_places":
		hist, err := historyOf(c)
		if err != nil {
			return nil, err
		}
		s := c.Rand.Derive("history").Stream()
		if op.Format == "chrome_history" {
			return libgen.ChromeHistory(hist, s)
		}
		return libgen.FirefoxPlaces(hist, s)
	}
	return nil, fmt.Errorf("unknown format %q (want one of: %s)", op.Format, strings.Join(compile.TypedFormats, ", "))
}

func docxMeta(op spec.Operation, when time.Time) (libgen.DocxMeta, error) {
	if op.Docx == nil {
		return libgen.DocxMeta{Created: when, Modified: when}, nil
	}
	created, err := timeOr(op.Docx.Created, "docx.created", when)
	if err != nil {
		return libgen.DocxMeta{}, err
	}
	modified, err := timeOr(op.Docx.Modified, "docx.modified", created)
	if err != nil {
		return libgen.DocxMeta{}, err
	}
	return libgen.DocxMeta{
		Title:    op.Docx.Title,
		Author:   op.Docx.Author,
		Created:  created,
		Modified: modified,
	}, nil
}

// timeOr reads an optional RFC 3339 time, falling back when the scenario does
// not give one. The fallback is always another scenario time, never the wall
// clock, which is what keeps a metadata date reproducible.
func timeOr(value, field string, fallback time.Time) (time.Time, error) {
	t, err := optionalTime(value, field)
	if err != nil {
		return time.Time{}, err
	}
	if t.IsZero() {
		return fallback, nil
	}
	return t, nil
}

// buildPE fills each section with the operation's filler and puts the
// content_len filler in the overlay, where an installer keeps its payload.
func buildPE(c compile.Op, overlay []byte) ([]byte, error) {
	in := c.Pe
	if in == nil {
		in = &spec.PeSpec{}
	}
	stamp := c.When
	switch s := strings.TrimSpace(in.Timestamp); {
	case s == "0":
		stamp = time.Time{}
	case s != "":
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, fmt.Errorf("pe.timestamp: %w", err)
		}
		stamp = t
	}

	sections := in.Sections
	if len(sections) == 0 {
		sections = defaultPESections
	}
	out := make([]libgen.PESection, 0, len(sections))
	for _, sec := range sections {
		size := sec.Size
		if size == 0 {
			size = 512
		}
		out = append(out, libgen.PESection{
			Name:  sec.Name,
			Data:  libgen.Filler(c.ContentKind, size, c.Rand.Derive("pe.section", sec.Name).Stream()),
			Flags: sec.Flags,
		})
	}
	imports, err := libgen.ParseImports(in.Imports)
	if err != nil {
		return nil, err
	}
	var version *libgen.PEVersion
	if v := in.Version; v != nil {
		version = &libgen.PEVersion{
			FileVersion: v.FileVersion, ProductVersion: v.ProductVersion,
			CompanyName: v.CompanyName, FileDescription: v.FileDescription,
			InternalName: v.InternalName, OriginalFilename: v.OriginalFilename,
			ProductName: v.ProductName, LegalCopyright: v.LegalCopyright,
		}
	}
	return libgen.BuildPE(libgen.PESpec{
		Machine:   in.Machine,
		Subsystem: in.Subsystem,
		DLL:       in.Dll,
		Timestamp: stamp,
		Sections:  out,
		Imports:   imports,
		Version:   version,
		Overlay:   overlay,
	})
}

// historyOf turns the scenario's visits into the builder's, filling in the
// operation's time where a visit gives none.
func historyOf(c compile.Op) (libgen.HistorySpec, error) {
	var out libgen.HistorySpec
	in := c.History
	if in == nil {
		return out, fmt.Errorf("format: %s needs a history block", c.Format)
	}
	at := func(value, field string) (time.Time, error) { return timeOr(value, field, c.When) }
	for i, v := range in.Visits {
		when, err := at(v.Time, fmt.Sprintf("history.visits[%d].time", i))
		if err != nil {
			return out, err
		}
		out.Visits = append(out.Visits, libgen.Visit{
			URL: v.URL, Title: v.Title, Time: when, Transition: v.Transition, FromVisit: v.FromVisit,
		})
	}
	for i, d := range in.Downloads {
		start, err := at(d.Start, fmt.Sprintf("history.downloads[%d].start", i))
		if err != nil {
			return out, err
		}
		end, err := optionalTime(d.End, fmt.Sprintf("history.downloads[%d].end", i))
		if err != nil {
			return out, err
		}
		if end.IsZero() {
			end = start
		}
		out.Downloads = append(out.Downloads, libgen.Download{
			URL: d.URL, TargetPath: d.TargetPath, Start: start, End: end,
			Received: d.ReceivedBytes, Total: d.TotalBytes, MimeType: d.MimeType,
		})
	}
	return out, nil
}

func pdfMeta(op spec.Operation) (libgen.PDFMeta, error) {
	if op.Pdf == nil {
		return libgen.PDFMeta{}, nil
	}
	created, err := optionalTime(op.Pdf.Created, "pdf.created")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	modified, err := optionalTime(op.Pdf.Modified, "pdf.modified")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	return libgen.PDFMeta{
		Title:    op.Pdf.Title,
		Author:   op.Pdf.Author,
		Subject:  op.Pdf.Subject,
		Keywords: op.Pdf.Keywords,
		Creator:  op.Pdf.Creator,
		Producer: op.Pdf.Producer,
		Created:  created,
		Modified: modified,
		PageSize: op.Pdf.PageSize,
	}, nil
}
