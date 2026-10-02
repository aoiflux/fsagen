package compile

import (
	"slices"
	"sort"
	"strings"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// Fields lists, per action, every YAML key a manifest operation or playbook
// action may carry besides "action" itself. It is the single source for both
// validation and the JSON Schema, so the two cannot drift. A key an action
// does not use is an error rather than a silently ignored no-op.
var Fields = map[spec.ActionName][]string{
	spec.ActionCreate:   {"path", "id", "type", "ext", "content", "content_len", "content_kind", "content_file", "render", "template", "mode", "format", "pdf", "docx", "pe", "history", "atime", "mtime", "ctime", "crtime"},
	spec.ActionUpdate:   {"path", "ref", "content", "content_len", "content_kind", "content_file", "render", "template", "mode", "format", "pdf", "docx", "pe", "history", "atime", "mtime", "ctime", "crtime"},
	spec.ActionAppend:   {"path", "ref", "id", "content", "content_len", "content_kind", "content_file", "render", "template", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionEdit:     {"path", "ref", "refs", "edit", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionDelete:   {"path", "ref", "refs", "missing_ok", "atime", "mtime"},
	spec.ActionMACE:     {"path", "ref", "refs", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionRename:   {"path", "ref", "new_path", "id"},
	spec.ActionCopy:     {"path", "ref", "new_path", "id", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionTruncate: {"path", "ref", "refs", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionRotate:   {"path", "ref", "new_path", "mode", "atime", "mtime"},
	spec.ActionArchive:  {"path", "id", "archive", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionEmail:    {"path", "id", "email", "format", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionVault:    {"path", "id", "vault", "content", "content_file", "render", "mode", "atime", "mtime", "ctime", "crtime"},
	spec.ActionADS:      {"path", "ref", "refs", "stream", "content", "content_len", "content_kind", "content_file", "render", "atime", "mtime"},
	spec.ActionMOTW:     {"path", "ref", "refs", "zone_id", "host_url", "referrer_url", "atime", "mtime"},
}

// field is a YAML key together with the value given for it, for the checks
// that run one rule over several keys.
type field struct{ key, val string }

// Value limits the closed sets cannot express.
const (
	// minZoneID and maxZoneID bound a mark-of-the-web zone: My Computer,
	// Local Intranet, Trusted, Internet, Restricted.
	minZoneID, maxZoneID = 0, 4
	// vaultSaltLen is the salt an Ansible vault takes, in bytes.
	vaultSaltLen = 32
)

// ZoneIdentifierStream is the named stream a mark of the web lives in, which
// is where Windows reads the zone a download came from.
const ZoneIdentifierStream = "Zone.Identifier"

// TimeFields are the explicit time keys, in the order access, modification,
// change, birth.
var TimeFields = []string{"atime", "mtime", "ctime", "crtime"}

// Required lists the keys an action cannot do without (beyond a target).
var Required = map[spec.ActionName][]string{
	spec.ActionArchive: {"archive"},
	spec.ActionEdit:    {"edit"},
	spec.ActionRename:  {"new_path"},
	spec.ActionCopy:    {"new_path"},
	spec.ActionRotate:  {"new_path"},
	spec.ActionEmail:   {"email"},
	spec.ActionVault:   {"vault"},
	spec.ActionADS:     {"stream"},
}

// Closed value sets.
var (
	Conditions = []string{"odd", "even", "first", "last"}
	Templates  = []string{"email", "log", "script", "doc"}
	Types      = []string{"file", "dir"}
	// ContentKinds is what the bytes fsagen invents may look like.
	ContentKinds = []string{libgen.KindText, libgen.KindBytes, libgen.KindZeros, libgen.KindPattern, libgen.KindLorem}
	// ArchiveMethods are how a member may be stored. Store is the default
	// because deflated bytes come from compress/flate and so are only
	// reproducible for the Go toolchain go.mod pins.
	ArchiveMethods = []string{"store", "deflate"}
	// Formats lists the format values each action accepts. raw and text write
	// the bytes through unchanged; the rest build a file of that type.
	Formats = map[spec.ActionName][]spec.Format{
		spec.ActionCreate: TypedFormats,
		spec.ActionUpdate: TypedFormats,
		spec.ActionEmail:  {spec.FormatEML, spec.FormatMbox},
	}
	// TypedFormats are the file types a create or an update can build.
	TypedFormats = []spec.Format{
		spec.FormatRaw, spec.FormatText, spec.FormatPDF, spec.FormatDOCX,
		spec.FormatPE, spec.FormatZip, spec.FormatPNG, spec.FormatJPEG,
		spec.FormatMP4, spec.FormatChromeHistory, spec.FormatFirefoxPlaces,
	}
)

// Structured reports whether a format builds a file rather than writing the
// content through. A structured format takes its shape from its own block and
// its filler from content_len, so it cannot also be given content.
func Structured(format spec.Format) bool {
	switch format {
	case "", spec.FormatRaw, spec.FormatText:
		return false
	}
	return true
}

// AllowedFields lists every key an action may carry in a manifest (playbook
// false) or a playbook (true), sorted.
func AllowedFields(action spec.ActionName, playbook bool) []string { return allowed(action, playbook) }

func allowed(action spec.ActionName, playbook bool) []string {
	out := []string{"action"}
	for _, f := range Fields[action] {
		if f == "template" && !playbook {
			continue
		}
		out = append(out, f)
	}
	if playbook {
		out = append(out, "offset", "condition")
	}
	sort.Strings(out)
	return out
}

// checkFields applies the field matrix and the rules that depend only on
// which keys are present. It runs before rendering, so nothing it rejects
// consumes a random draw.
func checkFields(src SourceRef, k keys, action spec.ActionName, playbook bool) ErrorList {
	var errs ErrorList
	r := reporter{errs: &errs, src: src, keys: k}

	if !k.has("action") {
		r.whole("missing field %q", "action")
		return errs
	}
	if _, ok := Fields[action]; !ok {
		r.at("action", "unknown action %q (want one of: %s)", action, strings.Join(spec.ActionNames(), ", "))
		return errs
	}

	ok := allowed(action, playbook)
	for _, name := range sortedKeyNames(k) {
		if !slices.Contains(ok, name) {
			r.at(name, "does not apply to %s (it takes: %s)", action, strings.Join(ok, ", "))
		}
	}

	checkTargets(r, k, action)
	for _, req := range Required[action] {
		if !k.has(req) {
			r.whole("%s needs %s", action, req)
		}
	}
	checkKeyCombinations(r, k, action)
	return errs
}

// sortedKeyNames lists the keys present, in a fixed order, so the errors for
// one operation come out the same way every run.
func sortedKeyNames(k keys) []string {
	names := make([]string, 0, len(k))
	for name := range k {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkTargets requires exactly one of path, ref and refs.
func checkTargets(r reporter, k keys, action spec.ActionName) {
	targets := 0
	for _, t := range []string{"path", "ref", "refs"} {
		if k.has(t) {
			targets++
		}
	}
	switch {
	case targets == 0 && slices.Contains(Fields[action], "ref"):
		r.whole("%s needs path, ref or refs", action)
	case targets == 0:
		r.whole("%s needs path", action)
	case targets > 1:
		r.at("path", "give exactly one of path, ref and refs")
	}
}

// checkKeyCombinations rejects keys that contradict or silently override each
// other. Each rule names the key that would be ignored, so the message points
// at what to delete.
func checkKeyCombinations(r reporter, k keys, action spec.ActionName) {
	if action == spec.ActionMACE && !slices.ContainsFunc(TimeFields, k.has) {
		r.whole("mace needs at least one of atime, mtime, ctime and crtime")
	}
	if k.has("template") && (k.has("content") || k.has("content_file")) {
		r.at("template", "cannot be combined with content or content_file; the template would silently replace them")
	}
	if k.has("content") && k.has("content_file") {
		r.at("content_file", "content and content_file are mutually exclusive")
	}
	if k.has("content_len") && (k.has("content") || k.has("content_file") || k.has("template")) {
		r.at("content_len", "has no effect when content, content_file or template is given")
	}
	if k.has("render") && !k.has("content") && !k.has("content_file") {
		r.at("render", "only applies to content or content_file")
	}
	if k.has("content_kind") && (k.has("content") || k.has("content_file") || k.has("template")) {
		r.at("content_kind", "says what invented bytes look like; it has no effect beside content, content_file or template")
	}
}
