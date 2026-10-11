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
	".docm": spec.FormatDOCM,
	".xlsx": spec.FormatXLSX,
	".xlsm": spec.FormatXLSM,
	".mp4":  spec.FormatMP4,
	".lnk":  spec.FormatLNK,
	".pf":   spec.FormatPrefetch,
	".evtx": spec.FormatEvtx,
	".hve":  spec.FormatRegistry,
}

// refusedExtensions promise a format fsagen still cannot build. Refusing is
// the whole point: a file named .pptx holding random text would be reported
// as a corrupt presentation by every tool that opened it.
var refusedExtensions = map[string]string{
	".pptx": "an OOXML presentation",
	".gif":  "a GIF image", ".bmp": "a BMP image", ".mov": "a QuickTime video",
	".pdf":    "a PDF (use format: pdf to render text into one)",
	".sqlite": "an SQLite database (use format: chrome_history or firefox_places for a browser profile)",
	".db":     "an SQLite database (use format: chrome_history or firefox_places for a browser profile)",
	".eml":    "an RFC 5322 message (use action: email)",
	".mbox":   "an mbox mailbox (use action: email)",
}

// inferredByName is what a file's whole name means, for the files known by
// name rather than extension: a registry hive (NTUSER.DAT, SYSTEM), a login
// record (wtmp) or an audit log.
func inferredByName(base string) (spec.Format, bool) {
	switch {
	case libgen.HiveKind(base) != "":
		return spec.FormatRegistry, true
	case slices.Contains(UtmpFiles, base):
		return spec.FormatUtmp, true
	case base == "audit.log":
		return spec.FormatAuditd, true
	}
	return "", false
}

// DocumentText reports a format whose content is the document's text rather
// than filler bytes: a workbook's is its cells, a line to a row.
func DocumentText(format spec.Format) bool {
	switch format {
	case spec.FormatPDF, spec.FormatDOCX, spec.FormatDOCM, spec.FormatXLSX, spec.FormatXLSM:
		return true
	}
	return false
}

// blockFormats says which formats each typed block belongs to.
var blockFormats = map[string][]spec.Format{
	"pdf":      {spec.FormatPDF},
	"docx":     {spec.FormatDOCX, spec.FormatDOCM},
	"xlsx":     {spec.FormatXLSX, spec.FormatXLSM},
	"vba":      {spec.FormatDOCM, spec.FormatXLSM},
	"pe":       {spec.FormatPE},
	"history":  {spec.FormatChromeHistory, spec.FormatFirefoxPlaces},
	"lnk":      {spec.FormatLNK},
	"prefetch": {spec.FormatPrefetch},
	"evtx":     {spec.FormatEvtx},
	"registry": {spec.FormatRegistry},
	"utmp":     {spec.FormatUtmp},
	"auditd":   {spec.FormatAuditd},
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
	if k.has("content_len") && op.Format == spec.FormatLNK {
		at("content_len", "a shell link has no region for filler; it is as big as what it records")
	}
	if op.Format == spec.FormatLNK && op.Lnk == nil {
		at("format", "lnk needs an lnk block saying what the link points at, at least its target")
	}
	if op.Lnk != nil {
		checkLNK(op, at)
	}
	if k.has("content_len") && op.Format == spec.FormatPrefetch {
		at("content_len", "a prefetch file has no region for filler; it is as big as what it records")
	}
	if op.Format == spec.FormatPrefetch && op.Prefetch == nil {
		at("format", "prefetch needs a prefetch block saying which program ran, at least its executable")
	}
	if op.Prefetch != nil {
		checkPrefetch(op, at)
	}
	if k.has("content_len") && op.Format == spec.FormatEvtx {
		at("content_len", "an event log has no region for filler; it is as big as its events make it")
	}
	if op.Format == spec.FormatEvtx && op.Evtx == nil {
		at("format", "evtx needs an evtx block saying which events were logged")
	}
	if op.Evtx != nil {
		checkEvtx(op, at)
	}
	if k.has("content_len") && op.Format == spec.FormatRegistry {
		at("content_len", "a registry hive has no region for filler; it is as big as its keys make it")
	}
	if op.Format == spec.FormatRegistry && op.Registry == nil {
		at("format", "regf needs a registry block saying which keys the hive holds")
	}
	if op.Registry != nil {
		checkRegistry(op, at)
	}
	for _, f := range []struct {
		format spec.Format
		block  bool
		what   string
	}{{spec.FormatUtmp, op.Utmp != nil, "utmp needs a utmp block listing its records"}, {spec.FormatAuditd, op.Auditd != nil, "auditd needs an auditd block listing its events"}} {
		if k.has("content_len") && op.Format == f.format {
			at("content_len", "a %s file has no region for filler; it is as big as its records make it", f.format)
		}
		if op.Format == f.format && !f.block {
			at("format", "%s", f.what)
		}
	}
	if op.Utmp != nil {
		checkUtmp(op, at)
	}
	if op.Auditd != nil {
		checkAuditd(op, at)
	}
	if op.Slack != nil {
		checkSlack(op, at)
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
	if op.Xlsx != nil {
		checkBlockTimes(at, "xlsx", field{"created", op.Xlsx.Created}, field{"modified", op.Xlsx.Modified})
	}
	checkOffice(op, at)
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
	if op.Xlsx != nil {
		v := *op.Xlsx
		op.Xlsx = &v
	}
	if op.Vba != nil {
		v := *op.Vba
		op.Vba = &v
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
	if op.Slack != nil {
		v := *op.Slack
		op.Slack = &v
	}
	if op.Lnk != nil {
		v := *op.Lnk
		v.TargetAttributes = append([]string(nil), op.Lnk.TargetAttributes...)
		op.Lnk = &v
	}
	if op.Prefetch != nil {
		v := *op.Prefetch
		v.LastRunTimes = append([]string(nil), op.Prefetch.LastRunTimes...)
		v.ReferencedFiles = append([]string(nil), op.Prefetch.ReferencedFiles...)
		v.Volumes = append([]spec.PrefetchVolume(nil), op.Prefetch.Volumes...)
		if op.Prefetch.Compressed != nil {
			c := *op.Prefetch.Compressed
			v.Compressed = &c
		}
		op.Prefetch = &v
	}
	if op.Evtx != nil {
		op.Evtx = cloneEvtx(op.Evtx)
	}
	if op.Registry != nil {
		op.Registry = cloneRegistry(op.Registry)
	}
	if op.Utmp != nil {
		op.Utmp = cloneUtmp(op.Utmp)
	}
	if op.Auditd != nil {
		op.Auditd = cloneAuditd(op.Auditd)
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
