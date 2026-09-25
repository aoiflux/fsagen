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
		var err error
		rctx.Field = "content"
		if op.Content, err = render.Apply(op.Content, rctx); err != nil {
			errs.add(fmt.Errorf("content: %w", err))
		}
		for i := range attachmentsOf(&op) {
			a := &attachmentsOf(&op)[i]
			rctx.Field = fmt.Sprintf("email.attachments[%d].content", i)
			if a.Content, err = render.Apply(a.Content, rctx); err != nil {
				errs.add(fmt.Errorf("email.attachments[%d].content: %w", i, err))
			}
		}
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
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.Name == contentFieldName || f.Tag.Get("render") == "-" || !v.Field(i).CanSet() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			renderStringFields(v.Field(i), rctx, join(where, name), errs)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			renderStringFields(v.Index(i), rctx, fmt.Sprintf("%s[%d]", where, i), errs)
		}
	case reflect.Map:
		// Variable maps are the source of substitution, not a target of it.
	case reflect.String:
		if s := v.String(); s != "" {
			rctx.Field = where
			out, err := render.Apply(s, rctx)
			if err != nil {
				errs.add(fmt.Errorf("%s: %w", where, err))
				return
			}
			v.SetString(out)
		}
	}
}

// checkValues validates a rendered operation's values, and settles its final
// path. It never draws randomness.
func checkValues(op *Op, src *sandbox.Sources) ErrorList {
	var errs ErrorList
	at := func(field, format string, args ...any) {
		e := &Error{Src: op.Src, Field: field, Msg: fmt.Sprintf(format, args...)}
		if n := op.keys[field]; n != nil {
			e.Line, e.Col = n.Line, n.Column
		}
		errs.add(e)
	}
	k := op.keys

	if k.has("type") && !contains(Types, op.Type) {
		at("type", "unknown type %q (want file or dir)", op.Type)
	}
	if formats, ok := Formats[op.Action]; ok && k.has("format") && !contains(formats, op.Format) {
		at("format", "unknown format %q for %s (want one of: %s)", op.Format, op.Action, strings.Join(formats, ", "))
	}
	if k.has("pdf") && op.Format != "pdf" {
		at("pdf", "only applies with format: pdf")
	}

	for _, f := range []struct{ key, val string }{{"atime", op.Atime}, {"mtime", op.Mtime}, {"ctime", op.Ctime}, {"crtime", op.Crtime}} {
		if k.has(f.key) {
			if _, err := time.Parse(time.RFC3339, strings.TrimSpace(f.val)); err != nil {
				at(f.key, "%q is not an RFC 3339 time (for example 2026-03-11T09:00:00Z)", f.val)
			}
		}
	}
	if op.Pdf != nil {
		for _, f := range []struct{ key, val string }{{"created", op.Pdf.Created}, {"modified", op.Pdf.Modified}} {
			if strings.TrimSpace(f.val) != "" {
				if _, err := time.Parse(time.RFC3339, strings.TrimSpace(f.val)); err != nil {
					at("pdf", "%s: %q is not an RFC 3339 time", f.key, f.val)
				}
			}
		}
	}
	if k.has("mode") {
		if _, _, err := util.ParseFileMode(op.Mode); err != nil {
			at("mode", "%v", err)
		}
	}
	if k.has("content_len") && op.ContentLen < 1 {
		at("content_len", "must be at least 1 (use content: \"\" for an empty file)")
	}
	if k.has("zone_id") && (op.ZoneID < 0 || op.ZoneID > 4) {
		at("zone_id", "%d is out of range (0 My Computer, 1 Local Intranet, 2 Trusted, 3 Internet, 4 Restricted)", op.ZoneID)
	}
	for _, f := range []struct{ key, val string }{{"host_url", op.HostURL}, {"referrer_url", op.ReferrerURL}} {
		if strings.ContainsAny(f.val, "\r\n") {
			at(f.key, "must not contain line breaks")
		}
	}
	if k.has("stream") {
		if err := pathpolicy.Stream(op.Stream); err != nil {
			at("stream", "%v", err)
		}
	}
	if k.has("ext") && (!strings.HasPrefix(op.Ext, ".") || strings.ContainsAny(op.Ext, "/\\:\x00")) {
		at("ext", "%q must start with '.' and name an extension only", op.Ext)
	}
	if op.Vault != nil {
		if op.Vault.Password == "" {
			at("vault", "password is empty")
		}
		if s := strings.TrimSpace(op.Vault.Salt); s != "" {
			if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
				at("vault", "salt must be 64 hex characters (32 bytes)")
			}
		}
	}
	if op.Type == "dir" {
		for _, f := range []string{"content", "content_len", "content_file", "template", "ext", "format", "pdf"} {
			if k.has(f) {
				at(f, "does not apply to a directory (type: dir)")
			}
		}
	}
	if op.Email != nil {
		errs.add(checkEmail(op, src))
	}

	// Paths. A trailing '/' marks a directory on every platform.
	if k.has("path") {
		clean, dir, err := pathpolicy.Output("", op.Path)
		if err != nil {
			at("path", "%v", err)
		} else {
			if dir && k.has("ext") {
				at("ext", "path %q ends in '/', which makes it a directory; drop the slash or the ext", op.Path)
			}
			op.Dir = op.Action == "create" && (op.Type == "dir" || dir)
			if dir && op.Action == "create" && op.Type == "file" {
				at("path", "ends in '/' (a directory) but type is file")
			}
			if op.Action == "create" && !op.Dir && op.Ext != "" && path.Ext(clean) == "" {
				clean += op.Ext
			}
			op.Path = clean
		}
	}
	if k.has("new_path") {
		clean, _, err := pathpolicy.Output("", op.NewPath)
		if err != nil {
			at("new_path", "%v", err)
		} else {
			op.NewPath = clean
		}
	}

	// Random content under an extension that promises a structured format is
	// exactly the silent wrong output this tool must not produce: a ".exe" of
	// base32 text is not an executable. Literal content is the author's own
	// bytes and always allowed; format: text marks a placeholder as deliberate.
	op.Random = randomLength(op)
	if randomContent(op) && !k.has("format") {
		if format, ok := typedExtensions[strings.ToLower(path.Ext(op.Path))]; ok {
			at("path", "%s implies %s, which fsagen cannot generate from random content yet; set format: text to write placeholder text on purpose, or supply content or content_file", path.Ext(op.Path), format)
		}
	}
	return errs
}

// typedExtensions maps extensions to the structured format they promise.
var typedExtensions = map[string]string{
	".exe": "a PE executable", ".dll": "a PE executable", ".sys": "a PE executable", ".scr": "a PE executable",
	".zip": "a zip archive", ".jar": "a zip archive", ".docx": "an OOXML document", ".xlsx": "an OOXML document", ".pptx": "an OOXML document",
	".png": "a PNG image", ".jpg": "a JPEG image", ".jpeg": "a JPEG image", ".gif": "a GIF image", ".bmp": "a BMP image",
	".pdf":    "a PDF (use format: pdf to render text into one)",
	".sqlite": "an SQLite database", ".db": "an SQLite database",
	".mp4": "an MP4 video", ".mov": "a QuickTime video",
	".eml": "an RFC 5322 message (use action: email)", ".mbox": "an mbox mailbox (use action: email)",
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
	fail := func(format string, args ...any) {
		err := &Error{Src: op.Src, Field: "email", Msg: fmt.Sprintf(format, args...)}
		if n := op.keys["email"]; n != nil {
			err.Line, err.Col = n.Line, n.Column
		}
		errs.add(err)
	}
	if d := strings.TrimSpace(e.Date); d != "" {
		if _, err := time.Parse(time.RFC3339, d); err != nil {
			fail("date %q is not an RFC 3339 time", d)
		}
	}
	if e.BodyText != "" && e.BodyTextFile != "" {
		fail("body_text and body_text_file are mutually exclusive")
	}
	if e.BodyHTML != "" && e.BodyHTMLFile != "" {
		fail("body_html and body_html_file are mutually exclusive")
	}
	for _, f := range []string{e.BodyTextFile, e.BodyHTMLFile} {
		if f != "" && src != nil {
			if err := src.Check(f); err != nil {
				fail("%v", err)
			}
		}
	}
	for i := range e.Attachments {
		a := &e.Attachments[i]
		n := 0
		for _, s := range []string{a.SourceFile, a.SourceRoot, a.Content} {
			if s != "" {
				n++
			}
		}
		if n != 1 {
			fail("attachments[%d]: give exactly one of source_file, source_root and content", i)
			continue
		}
		switch {
		case a.SourceFile != "" && src != nil:
			if err := src.Check(a.SourceFile); err != nil {
				fail("attachments[%d]: %v", i, err)
			}
		case a.SourceRoot != "":
			clean, _, err := pathpolicy.Output("", a.SourceRoot)
			if err != nil {
				fail("attachments[%d].source_root: %v", i, err)
			} else {
				a.SourceRoot = clean
			}
		}
		if a.Disposition != "" && a.Disposition != "attachment" && a.Disposition != "inline" {
			fail("attachments[%d]: disposition %q (want attachment or inline)", i, a.Disposition)
		}
	}
	return errs
}
