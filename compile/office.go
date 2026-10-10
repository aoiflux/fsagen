package compile

import (
	"cmp"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// VBAHost is the application whose project a macro-enabled format carries,
// or "" for a format with none.
func VBAHost(format spec.Format) string {
	switch format {
	case spec.FormatDOCM:
		return libgen.VBAWord
	case spec.FormatXLSM:
		return libgen.VBAExcel
	}
	return ""
}

// VBAOf is the macro an operation's document carries: what its vba block
// says, with the host's default entry point. An empty marker is left for the
// builder to draw from the seed.
func VBAOf(op spec.Operation) libgen.VBASpec {
	host := VBAHost(op.Format)
	s := libgen.VBASpec{Host: host, EntryPoint: libgen.VBAEntryPoints[host][0]}
	if v := op.Vba; v != nil {
		s.EntryPoint = cmp.Or(v.EntryPoint, s.EntryPoint)
		s.Module, s.Marker = v.ModuleName, v.Marker
	}
	return s
}

// checkOffice checks what a Word or Excel document asks for: a macro its
// project can hold, and text its sheet can.
func checkOffice(op *Op, at func(field, format string, args ...any)) {
	if VBAHost(op.Format) != "" {
		s := VBAOf(op.Operation)
		s.Marker = cmp.Or(s.Marker, "drawn")
		if err := libgen.CheckVBA(s); err != nil {
			at("vba", "%v", err)
		}
	}
	if op.Format != spec.FormatXLSX && op.Format != spec.FormatXLSM {
		return
	}
	switch {
	case givesContent(op):
		if err := libgen.CheckSheetText(op.Content); err != nil {
			at("content", "%v", err)
		}
	case op.ContentLen > libgen.MaxCellText:
		at("content_len", "the filler is one line, so one cell, which holds at most %d characters", libgen.MaxCellText)
	}
}
