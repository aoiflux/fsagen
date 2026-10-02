package compile

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/spec"
)

// inferredFormats is what an extension means when the scenario gives no
// content of its own. Writing base32 text into a file called .exe is exactly
// the silent wrong output this tool must not produce, so an extension that
// promises a structured file now gets one.
//
// .pdf is deliberately absent: a PDF needs its dates settled while the
// operation is compiled, before the path has been rendered, so it stays an
// explicit format: pdf.
var inferredFormats = map[string]spec.Format{
	".exe": spec.FormatPE, ".dll": spec.FormatPE, ".sys": spec.FormatPE, ".scr": spec.FormatPE,
	".zip": spec.FormatZip, ".jar": spec.FormatZip,
	".png": spec.FormatPNG, ".jpg": spec.FormatJPEG, ".jpeg": spec.FormatJPEG,
	".docx": spec.FormatDOCX,
	".mp4":  spec.FormatMP4,
}

// refusedExtensions promise a format fsagen still cannot build. Refusing is
// the whole point: a file named .xlsx holding random text would be reported
// as a corrupt spreadsheet by every tool that opened it.
var refusedExtensions = map[string]string{
	".xlsx": "an OOXML spreadsheet", ".pptx": "an OOXML presentation",
	".gif": "a GIF image", ".bmp": "a BMP image", ".mov": "a QuickTime video",
	".pdf":    "a PDF (use format: pdf to render text into one)",
	".sqlite": "an SQLite database (use format: chrome_history or firefox_places for a browser profile)",
	".db":     "an SQLite database (use format: chrome_history or firefox_places for a browser profile)",
	".eml":    "an RFC 5322 message (use action: email)",
	".mbox":   "an mbox mailbox (use action: email)",
}

// DocumentText reports a format whose content is the document's text rather
// than filler bytes.
func DocumentText(format spec.Format) bool {
	return format == spec.FormatPDF || format == spec.FormatDOCX
}

// blockFormats says which formats each typed block belongs to.
var blockFormats = map[string][]spec.Format{
	"pdf":     {spec.FormatPDF},
	"docx":    {spec.FormatDOCX},
	"pe":      {spec.FormatPE},
	"history": {spec.FormatChromeHistory, spec.FormatFirefoxPlaces},
}

// checkTyped validates the typed blocks and the rules that tie a block to the
// format beside it. at reports one problem against a field.
func checkTyped(op *Op, at func(field, format string, args ...any)) {
	k := op.keys

	if k.has("content_kind") && !slices.Contains(ContentKinds, op.ContentKind) {
		at("content_kind", "unknown content_kind %q (want one of: %s)", op.ContentKind, strings.Join(ContentKinds, ", "))
	}
	for block, formats := range blockFormats {
		if k.has(block) && !slices.Contains(formats, op.Format) {
			at(block, "only applies with format: %s", strings.Join(spec.FormatNames(formats), " or "))
		}
	}
	if Structured(op.Format) && !DocumentText(op.Format) {
		rejectBodyKeys(op, at)
	}
	if k.has("content_len") && (op.Format == spec.FormatChromeHistory || op.Format == spec.FormatFirefoxPlaces) {
		at("content_len", "a history database is as big as its contents make it; give history.visits instead")
	}

	if (op.Format == spec.FormatChromeHistory || op.Format == spec.FormatFirefoxPlaces) && op.History == nil {
		at("format", "%s needs a history block saying what was browsed", op.Format)
	}
	if op.Pe != nil {
		checkPE(op, at)
	}
	if op.History != nil {
		checkHistory(op, at)
	}
	if op.Docx != nil {
		checkBlockTimes(at, "docx", field{"created", op.Docx.Created}, field{"modified", op.Docx.Modified})
	}
	if op.Archive != nil {
		checkArchive(op, at)
	}
	if op.Edit != nil {
		checkEdit(op, at)
	}
}

func checkTime(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err != nil {
		return fmt.Errorf("%q is not an RFC 3339 time (for example 2026-03-11T09:00:00Z)", v)
	}
	return nil
}

func checkPE(op *Op, at func(string, string, ...any)) {
	p := op.Pe
	if p.Machine != "" && !slices.Contains(libgen.PEMachines, p.Machine) {
		at("pe", "machine %q (want one of: %s)", p.Machine, strings.Join(libgen.PEMachines, ", "))
	}
	if p.Subsystem != "" && !slices.Contains(libgen.PESubsystems, p.Subsystem) {
		at("pe", "subsystem %q (want one of: %s)", p.Subsystem, strings.Join(libgen.PESubsystems, ", "))
	}
	// A zero timestamp is a real thing to want: it is what a reproducible
	// build writes, and tools report it as such.
	if s := strings.TrimSpace(p.Timestamp); s != "" && s != "0" {
		if err := checkTime(s); err != nil {
			at("pe", "timestamp: %v", err)
		}
	}
	seen := map[string]bool{}
	for i, sec := range p.Sections {
		checkPeSection(sec, i, seen, at)
	}
	if _, err := libgen.ParseImports(p.Imports); err != nil {
		at("pe", "%v", err)
	}
}

func checkHistory(op *Op, at func(string, string, ...any)) {
	h := op.History
	if len(h.Visits) == 0 && len(h.Downloads) == 0 {
		at("history", "needs at least one visit or download")
	}
	for i, v := range h.Visits {
		if strings.TrimSpace(v.URL) == "" {
			at("history", "visits[%d] has no url", i)
		}
		if v.Transition != "" && !slices.Contains(libgen.Transitions, v.Transition) {
			at("history", "visits[%d]: unknown transition %q (want one of: %s)", i, v.Transition, strings.Join(libgen.Transitions, ", "))
		}
		if err := checkTime(v.Time); err != nil {
			at("history", "visits[%d].time: %v", i, err)
		}
		if v.FromVisit < 0 || v.FromVisit > len(h.Visits) {
			at("history", "visits[%d]: from_visit %d names no visit (they are numbered 1 to %d)", i, v.FromVisit, len(h.Visits))
		}
		if v.FromVisit == i+1 {
			at("history", "visits[%d]: from_visit points at itself", i)
		}
	}
	for i, d := range h.Downloads {
		if strings.TrimSpace(d.URL) == "" {
			at("history", "downloads[%d] has no url", i)
		}
		if strings.TrimSpace(d.TargetPath) == "" {
			at("history", "downloads[%d] has no target_path", i)
		}
		checkDownloadTimes(d, i, at)
		if d.ReceivedBytes < 0 || d.TotalBytes < 0 {
			at("history", "downloads[%d]: a byte count cannot be negative", i)
		}
	}
}

func checkArchive(op *Op, at func(string, string, ...any)) {
	a := op.Archive
	if a.Method != "" && !slices.Contains(ArchiveMethods, a.Method) {
		at("archive", "method %q (want one of: %s)", a.Method, strings.Join(ArchiveMethods, ", "))
	}
	if len(a.Members) == 0 && len(a.MemberRefs) == 0 {
		at("archive", "needs members (glob patterns) or member_refs (ids)")
	}
	for i, g := range a.Members {
		if strings.TrimSpace(g) == "" {
			at("archive", "members[%d] is empty", i)
			continue
		}
		if _, err := path.Match(g, "x"); err != nil {
			at("archive", "members[%d]: %q is not a valid pattern: %v", i, g, err)
		}
		if strings.HasPrefix(g, "/") || strings.Contains(g, `\`) {
			at("archive", "members[%d]: %q must be a relative, slash-separated pattern", i, g)
		}
	}
	if a.Base != "" {
		clean, _, err := pathpolicy.Output("", a.Base)
		if err != nil {
			at("archive", "base: %v", err)
		} else {
			// Cleaned here so that an actor base joined with "." is the
			// actor's own directory rather than a path with a dot in it.
			a.Base = clean
		}
	}
	if strings.ContainsAny(a.Comment, "\x00") {
		at("archive", "comment cannot hold a NUL")
	}
	if len(a.Comment) > 0xffff {
		at("archive", "comment is %d bytes; a zip archive holds at most 65535", len(a.Comment))
	}
}

var reLineRange = regexp.MustCompile(`^(\d+)(?:-(\d+))?$`)

func checkEdit(op *Op, at func(string, string, ...any)) {
	e := op.Edit
	if e.DeleteLines == "" && e.DeleteMatching == "" && len(e.Replace) == 0 && len(e.InsertAfter) == 0 {
		at("edit", "needs delete_lines, delete_matching, replace or insert_after")
	}
	if s := strings.TrimSpace(e.DeleteLines); s != "" {
		if from, to, err := ParseLineRange(s); err != nil {
			at("edit", "delete_lines: %v", err)
		} else if to < from {
			at("edit", "delete_lines: %q ends before it starts", s)
		}
	}
	if e.DeleteMatching != "" {
		if _, err := regexp.Compile(e.DeleteMatching); err != nil {
			at("edit", "delete_matching: %v", err)
		}
	}
	for i, r := range e.Replace {
		if r.Pattern == "" {
			at("edit", "replace[%d] has no pattern", i)
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			at("edit", "replace[%d].pattern: %v", i, err)
		}
		if r.Count < 0 {
			at("edit", "replace[%d]: count %d is negative (0 means every match)", i, r.Count)
		}
	}
	for i, ins := range e.InsertAfter {
		if ins.Pattern == "" {
			at("edit", "insert_after[%d] has no pattern", i)
		} else if _, err := regexp.Compile(ins.Pattern); err != nil {
			at("edit", "insert_after[%d].pattern: %v", i, err)
		}
	}
}

// ParseLineRange reads "40" or "40-60" as a 1-based inclusive range.
func ParseLineRange(s string) (from, to int, err error) {
	m := reLineRange.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, fmt.Errorf("%q is not a line or a range of lines (for example 40 or 40-60)", s)
	}
	// The pattern only admits digits, so the one error Atoi can return is a
	// value too large for an int, which it reports along with a clamped result.
	// Left unchecked, a 20-digit line number would pass as MaxInt.
	from, err = strconv.Atoi(m[1])
	if err != nil {
		return 0, 0, fmt.Errorf("%q names a line beyond any file", m[1])
	}
	to = from
	if m[2] != "" {
		if to, err = strconv.Atoi(m[2]); err != nil {
			return 0, 0, fmt.Errorf("%q names a line beyond any file", m[2])
		}
	}
	if from < 1 {
		return 0, 0, fmt.Errorf("lines are numbered from 1")
	}
	return from, to, nil
}

// cloneTyped copies the blocks an operation carries, so a playbook action
// repeated by a step never shares one with another occurrence.
func cloneTyped(op *spec.Operation) {
	if op.Pdf != nil {
		v := *op.Pdf
		op.Pdf = &v
	}
	if op.Docx != nil {
		v := *op.Docx
		op.Docx = &v
	}
	if op.Vault != nil {
		v := *op.Vault
		op.Vault = &v
	}
	if op.Pe != nil {
		v := *op.Pe
		v.Sections = append([]spec.PeSection(nil), op.Pe.Sections...)
		for i := range v.Sections {
			v.Sections[i].Flags = append([]string(nil), v.Sections[i].Flags...)
		}
		v.Imports = append([]string(nil), op.Pe.Imports...)
		if op.Pe.Version != nil {
			ver := *op.Pe.Version
			v.Version = &ver
		}
		op.Pe = &v
	}
	if op.History != nil {
		v := *op.History
		v.Visits = append([]spec.HistoryVisit(nil), op.History.Visits...)
		v.Downloads = append([]spec.HistoryDownload(nil), op.History.Downloads...)
		op.History = &v
	}
	if op.Archive != nil {
		v := *op.Archive
		v.Members = append([]string(nil), op.Archive.Members...)
		v.MemberRefs = append([]string(nil), op.Archive.MemberRefs...)
		op.Archive = &v
	}
	if op.Edit != nil {
		v := *op.Edit
		v.Replace = append([]spec.EditReplace(nil), op.Edit.Replace...)
		v.InsertAfter = append([]spec.EditInsert(nil), op.Edit.InsertAfter...)
		op.Edit = &v
	}
	if op.Email != nil {
		op.Email = cloneEmail(op.Email)
	}
}

// rejectBodyKeys reports the content keys that a self-building format ignores.
// Such a format takes its filler from content_len and its shape from its own
// block, so a body given beside it would be silently dropped.
func rejectBodyKeys(op *Op, at func(string, string, ...any)) {
	for _, f := range []string{"content", "content_file", "template", "render"} {
		if op.keys.has(f) {
			at(f, "does not apply to format: %s, which builds the file itself; content_len says how much filler it carries, and its own block says what is in it", op.Format)
		}
	}
}

// checkBlockTimes rejects any date in a typed block that is given but is not
// RFC 3339. Leaving one out is allowed; it defaults to the operation time.
func checkBlockTimes(at func(string, string, ...any), block string, fields ...field) {
	for _, f := range fields {
		if err := checkTime(f.val); err != nil {
			at(block, "%s: %v", f.key, err)
		}
	}
}

// checkPeSection checks one section of an image: it needs a name that fits the
// header and has not been used, a size that is not negative, and flags the
// format knows. seen carries the names already used.
func checkPeSection(sec spec.PeSection, i int, seen map[string]bool, at func(string, string, ...any)) {
	switch {
	case strings.TrimSpace(sec.Name) == "":
		at("pe", "sections[%d] has no name", i)
	case libgen.ReservedPESection(sec.Name):
		at("pe", "sections[%d]: %q is the name fsagen gives the section it builds itself; its contents would be overwritten", i, sec.Name)
	case len(sec.Name) > libgen.MaxPESectionName:
		at("pe", "sections[%d]: %q is longer than the eight bytes a section name holds", i, sec.Name)
	case seen[sec.Name]:
		at("pe", "sections[%d]: %q appears twice", i, sec.Name)
	}
	seen[sec.Name] = true
	if sec.Size < 0 {
		at("pe", "sections[%d]: size %d is negative", i, sec.Size)
	}
	for _, f := range sec.Flags {
		if slices.Contains(libgen.PESectionFlags, f) {
			continue
		}
		at("pe", "sections[%d]: unknown flag %q (want one of: %s)", i, f, strings.Join(libgen.PESectionFlags, ", "))
	}
}

// checkDownloadTimes rejects a download's start or end that is given but is not
// RFC 3339.
func checkDownloadTimes(d spec.HistoryDownload, i int, at func(string, string, ...any)) {
	for _, f := range []field{{"start", d.Start}, {"end", d.End}} {
		if err := checkTime(f.val); err != nil {
			at("history", "downloads[%d].%s: %v", i, f.key, err)
		}
	}
}
