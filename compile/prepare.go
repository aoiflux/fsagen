package compile

import (
	"encoding/hex"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
	"github.com/aoiflux/fsagen/util"
)

// contentFieldName is handled explicitly rather than by the reflective walk,
// because whether it gets templated depends on where it came from.
const contentFieldName = "Content"

// Prepare resolves an operation into a form the executor can run directly:
// every ${...} token substituted, and content_file loaded through the confined
// source reader.
//
// Templating of the content body defaults differently depending on its source.
// Inline content: templated. content_file: NOT templated, because shell
// scripts, PEM keys and source code routinely contain ${...} sequences of
// their own that must survive verbatim. An explicit render: true or
// render: false overrides either default.
//
// Each field's random tokens are keyed by the field's name (see
// render.Context), so the order of work does not affect any value.
func Prepare(op spec.Operation, src *sandbox.Sources, rctx render.Context) (spec.Operation, error) {
	var errs ErrorList
	renderStringFields(reflect.ValueOf(&op).Elem(), rctx, "", &errs)

	renderContent := op.ContentFile == ""
	if op.Render != nil {
		renderContent = *op.Render
	}

	if op.ContentFile != "" {
		if src == nil {
			return op, fmt.Errorf("content_file: no source directory")
		}
		data, err := src.ReadFile(op.ContentFile)
		if err != nil {
			errs.add(fmt.Errorf("content_file: %w", err))
		} else {
			op.Content = string(data)
		}
	}

	if renderContent {
		errs.add(renderContentBodies(&op, rctx))
	}

	op.ContentFile = ""
	return op, errs.err()
}

func attachmentsOf(op *spec.Operation) []spec.Attachment {
	if op.Email == nil {
		return nil
	}
	return op.Email.Attachments
}

// renderContentBodies templates the operation's content and each inline
// attachment's. Content is handled here rather than by the reflective walk
// because whether it is templated depends on where it came from.
func renderContentBodies(op *spec.Operation, rctx render.Context) ErrorList {
	var errs ErrorList
	var err error
	rctx.Field = "content"
	if op.Content, err = render.Apply(op.Content, rctx); err != nil {
		errs.add(fmt.Errorf("content: %w", err))
	}
	for i := range attachmentsOf(op) {
		a := &attachmentsOf(op)[i]
		where := fmt.Sprintf("email.attachments[%d].content", i)
		rctx.Field = where
		if a.Content, err = render.Apply(a.Content, rctx); err != nil {
			errs.add(fmt.Errorf("%s: %w", where, err))
		}
	}
	return errs
}

// renderStringFields walks the operation and templates every string and
// []string it finds, skipping content bodies and fields tagged render:"-"
// (ids and refs are literal names). Reflection keeps the nested specs (pdf,
// email, vault) from each needing their own hand-written pass.
func renderStringFields(v reflect.Value, rctx render.Context, where string, errs *ErrorList) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			renderStringFields(v.Elem(), rctx, where, errs)
		}
	case reflect.Struct:
		renderStructFields(v, rctx, where, errs)
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			renderStringFields(v.Index(i), rctx, fmt.Sprintf("%s[%d]", where, i), errs)
		}
	case reflect.Map:
		// Variable maps are the source of substitution, not a target of it.
	case reflect.String:
		renderStringValue(v, rctx, where, errs)
	}
}

// renderStructFields templates every field of a struct except the content body
// and the fields tagged render:"-", whose values are literal names.
func renderStructFields(v reflect.Value, rctx render.Context, where string, errs *ErrorList) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := t.Field(i)
		if f.Name == contentFieldName || f.Tag.Get("render") == "-" || !v.Field(i).CanSet() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		renderStringFields(v.Field(i), rctx, join(where, name), errs)
	}
}

// renderStringValue templates one string in place. An empty string has nothing
// to substitute, and a failed substitution leaves the value alone.
func renderStringValue(v reflect.Value, rctx render.Context, where string, errs *ErrorList) {
	s := v.String()
	if s == "" {
		return
	}
	rctx.Field = where
	out, err := render.Apply(s, rctx)
	if err != nil {
		errs.add(fmt.Errorf("%s: %w", where, err))
		return
	}
	v.SetString(out)
}

// checkValues validates a rendered operation's values and settles what the
// executor needs from them: the cleaned paths, the format the extension
// promises, and how much random content to write. It never draws randomness.
//
// The order here is load-bearing: the path is cleaned before the extension is
// read off it, and the format is settled before the content length is decided.
func checkValues(op *Op, src *sandbox.Sources) ErrorList {
	var errs ErrorList
	r := op.report(&errs)

	checkClosedSets(op, r)
	checkExplicitTimes(op, r)
	checkPdfDates(op, r)
	checkContentFields(op, r)
	checkStreamFields(op, r)
	checkVault(op, r)
	checkDirectoryFields(op, r)
	if op.Email != nil {
		errs.add(checkEmail(op, src))
	}

	normalizePaths(op, r)
	// An operation targeted by ref or refs has no path of its own yet, so what
	// its extension implies can only be settled once simulate has resolved
	// which file it acts on: see settleContent.
	if op.keys.has("path") {
		settleContent(op, r)
	}
	checkTyped(op, r.at)
	return errs
}

// settleContent settles what the operation's path implies about its content: the
// format an extension promises, and then how much invented content to write,
// which depends on that format.
func settleContent(op *Op, r reporter) {
	inferFormatFromExtension(op, r)
	op.Random = randomLength(op)
}

// checkClosedSets rejects a value outside the closed set its key allows.
func checkClosedSets(op *Op, r reporter) {
	k := op.keys
	if k.has("type") && !contains(Types, op.Type) {
		r.at("type", "unknown type %q (want file or dir)", op.Type)
	}
	if formats, ok := Formats[op.Action]; ok && k.has("format") && !contains(formats, op.Format) {
		r.at("format", "unknown format %q for %s (want one of: %s)", op.Format, op.Action, strings.Join(formats, ", "))
	}
	if k.has("pdf") && op.Format != "pdf" {
		r.at("pdf", "only applies with format: pdf")
	}
}

// checkExplicitTimes rejects an explicit time that is not RFC 3339. A key that
// is present but empty is a mistake too, since it would otherwise be ignored.
func checkExplicitTimes(op *Op, r reporter) {
	for _, f := range []field{{"atime", op.Atime}, {"mtime", op.Mtime}, {"ctime", op.Ctime}, {"crtime", op.Crtime}} {
		if !op.keys.has(f.key) {
			continue
		}
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(f.val)); err != nil {
			r.at(f.key, "%q is not an RFC 3339 time (for example 2026-03-11T09:00:00Z)", f.val)
		}
	}
}

// checkPdfDates rejects a pdf date that is given but not RFC 3339. Leaving one
// out is allowed; it then defaults to the operation time.
func checkPdfDates(op *Op, r reporter) {
	if op.Pdf == nil {
		return
	}
	for _, f := range []field{{"created", op.Pdf.Created}, {"modified", op.Pdf.Modified}} {
		if checkTime(f.val) != nil {
			r.at("pdf", "%s: %q is not an RFC 3339 time", f.key, f.val)
		}
	}
}

// checkContentFields checks the permission mode, the invented content length
// and the extension to append.
func checkContentFields(op *Op, r reporter) {
	k := op.keys
	if k.has("mode") {
		if _, _, err := util.ParseFileMode(op.Mode); err != nil {
			r.at("mode", "%v", err)
		}
	}
	if k.has("content_len") && op.ContentLen < 1 {
		r.at("content_len", "must be at least 1 (use content: \"\" for an empty file)")
	}
	if k.has("ext") && (!strings.HasPrefix(op.Ext, ".") || strings.ContainsAny(op.Ext, "/\\:\x00")) {
		r.at("ext", "%q must start with '.' and name an extension only", op.Ext)
	}
}

// checkStreamFields checks the Windows-only keys: the mark-of-the-web zone and
// urls, and the name of the stream an ads writes.
func checkStreamFields(op *Op, r reporter) {
	k := op.keys
	if k.has("zone_id") && (op.ZoneID < minZoneID || op.ZoneID > maxZoneID) {
		r.at("zone_id", "%d is out of range (0 My Computer, 1 Local Intranet, 2 Trusted, 3 Internet, 4 Restricted)", op.ZoneID)
	}
	for _, f := range []field{{"host_url", op.HostURL}, {"referrer_url", op.ReferrerURL}} {
		if strings.ContainsAny(f.val, "\r\n") {
			r.at(f.key, "must not contain line breaks")
		}
	}
	if k.has("stream") {
		if err := pathpolicy.Stream(op.Stream); err != nil {
			r.at("stream", "%v", err)
		}
	}
}

// checkVault checks the ansible-vault block: it needs a password, and a salt
// given by hand has to be exactly the length the cipher takes.
func checkVault(op *Op, r reporter) {
	if op.Vault == nil {
		return
	}
	if op.Vault.Password == "" {
		r.at("vault", "password is empty")
	}
	salt := strings.TrimSpace(op.Vault.Salt)
	if salt == "" {
		return
	}
	if b, err := hex.DecodeString(salt); err != nil || len(b) != vaultSaltLen {
		r.at("vault", "salt must be 64 hex characters (32 bytes)")
	}
}

// checkDirectoryFields rejects the content keys a directory cannot carry.
func checkDirectoryFields(op *Op, r reporter) {
	if op.Type != "dir" {
		return
	}
	for _, f := range []string{"content", "content_len", "content_file", "template", "ext", "format", "pdf"} {
		if op.keys.has(f) {
			r.at(f, "does not apply to a directory (type: dir)")
		}
	}
}

// normalizePaths cleans both of the paths an operation can name.
func normalizePaths(op *Op, r reporter) {
	if op.keys.has("path") {
		normalizeTarget(op, r)
	}
	if !op.keys.has("new_path") {
		return
	}
	clean, _, err := pathpolicy.Output("", op.NewPath)
	if err != nil {
		r.at("new_path", "%v", err)
		return
	}
	op.NewPath = clean
}

// normalizeTarget cleans the target path, settles whether the operation names a
// directory, and appends the extension to a create whose path carries none. A
// trailing '/' marks a directory on every platform.
func normalizeTarget(op *Op, r reporter) {
	clean, dir, err := pathpolicy.Output("", op.Path)
	if err != nil {
		r.at("path", "%v", err)
		return
	}
	if dir && op.keys.has("ext") {
		r.at("ext", "path %q ends in '/', which makes it a directory; drop the slash or the ext", op.Path)
	}
	op.Dir = op.Action == "create" && (op.Type == "dir" || dir)
	if dir && op.Action == "create" && op.Type == "file" {
		r.at("path", "ends in '/' (a directory) but type is file")
	}
	if op.Action == "create" && !op.Dir && op.Ext != "" && path.Ext(clean) == "" {
		clean += op.Ext
	}
	op.Path = clean
}

// inferFormatFromExtension settles the format an extension promises. Writing
// base32 text into a ".exe" is exactly the silent wrong output this tool must
// not produce. Literal content is the author's own bytes and is written
// through; format: text marks a placeholder as deliberate.
func inferFormatFromExtension(op *Op, r reporter) {
	if op.keys.has("format") || !randomContent(op) {
		return
	}
	ext := strings.ToLower(path.Ext(op.Path))
	format, known := inferredFormats[ext]
	switch {
	case known && (op.Action == "create" || op.Action == "update"):
		op.Format = format
	case known:
		r.at("path", "%s implies a %s file; adding filler to one would corrupt it, so give content or content_file, or format: text to write placeholder text on purpose", ext, format)
	case refusedExtensions[ext] != "":
		r.at("path", "%s implies %s, which fsagen cannot build; set format: text to write placeholder text on purpose, or supply content or content_file", ext, refusedExtensions[ext])
	}
}

// randomContent reports whether an operation's file content will be drawn
// at random (content_len, or the default length when nothing is given).
// Stream content is not a file's, so ads is left out.
func randomContent(op *Op) bool {
	switch op.Action {
	case "create":
		if op.Dir {
			return false
		}
	case "update", "append":
	default:
		return false
	}
	return !givesContent(op)
}

func givesContent(op *Op) bool {
	k := op.keys
	return k.has("content") || k.has("content_file") || k.has("template")
}

// randomLength is how many random characters the operation writes: its
// content_len, or a default per action, when it gives no content of its
// own. An explicit content, even an empty one, is written as it is.
func randomLength(op *Op) int {
	if !randomContent(op) && !(op.Action == "ads" && !givesContent(op)) {
		return 0
	}
	if op.ContentLen > 0 {
		return op.ContentLen
	}
	// A format that builds its own file needs no filler unless asked: the
	// minimal valid file is the honest default.
	if Structured(op.Format) && !DocumentText(op.Format) {
		return 0
	}
	switch op.Action {
	case "append":
		return 256
	case "ads":
		return 128
	}
	return 1024
}

func checkEmail(op *Op, src *sandbox.Sources) ErrorList {
	var errs ErrorList
	e := op.Email
	r := op.report(&errs)
	fail := func(format string, args ...any) { r.at("email", format, args...) }
	if checkTime(e.Date) != nil {
		fail("date %q is not an RFC 3339 time", strings.TrimSpace(e.Date))
	}
	if e.BodyText != "" && e.BodyTextFile != "" {
		fail("body_text and body_text_file are mutually exclusive")
	}
	if e.BodyHTML != "" && e.BodyHTMLFile != "" {
		fail("body_html and body_html_file are mutually exclusive")
	}
	for _, f := range []string{e.BodyTextFile, e.BodyHTMLFile} {
		if err := checkSource(src, f); err != nil {
			fail("%v", err)
		}
	}
	for i := range e.Attachments {
		checkAttachment(&e.Attachments[i], i, src, fail)
	}
	return errs
}

// checkSource reports whether a source file the scenario names can be read. An
// empty name is not a source, and with no source directory there is nothing to
// check it against.
func checkSource(src *sandbox.Sources, name string) error {
	if name == "" || src == nil {
		return nil
	}
	return src.Check(name)
}

// checkAttachment checks one attachment: exactly one way of supplying its
// bytes, a source that can be read, and a disposition MIME allows. It also
// cleans an output-relative source path.
func checkAttachment(a *spec.Attachment, i int, src *sandbox.Sources, fail func(string, ...any)) {
	if countNonEmpty(a.SourceFile, a.SourceRoot, a.Ref, a.Content) != 1 {
		fail("attachments[%d]: give exactly one of source_file, source_root, ref and content", i)
		return
	}
	switch {
	case a.SourceFile != "":
		if err := checkSource(src, a.SourceFile); err != nil {
			fail("attachments[%d]: %v", i, err)
		}
	case a.SourceRoot != "":
		clean, _, err := pathpolicy.Output("", a.SourceRoot)
		if err != nil {
			fail("attachments[%d].source_root: %v", i, err)
			break
		}
		a.SourceRoot = clean
	}
	if a.Disposition != "" && a.Disposition != "attachment" && a.Disposition != "inline" {
		fail("attachments[%d]: disposition %q (want attachment or inline)", i, a.Disposition)
	}
}

// countNonEmpty is how many of these strings carry a value.
func countNonEmpty(values ...string) int {
	n := 0
	for _, v := range values {
		if v != "" {
			n++
		}
	}
	return n
}
