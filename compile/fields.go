package compile

import (
	"fmt"
	"sort"
	"strings"
)

// Actions is the closed set of action names, in documentation order.
var Actions = []string{
	"create", "update", "append", "delete", "mace", "rename", "copy",
	"truncate", "rotate", "email", "ansible-vault", "ads", "motw",
}

// Fields lists, per action, every YAML key a manifest operation or playbook
// action may carry besides "action" itself. It is the single source for both
// validation and the JSON Schema, so the two cannot drift. A key an action
// does not use is an error rather than a silently ignored no-op.
var Fields = map[string][]string{
	"create":        {"path", "id", "type", "ext", "content", "content_len", "content_file", "render", "template", "mode", "format", "pdf", "atime", "mtime", "ctime", "crtime"},
	"update":        {"path", "ref", "content", "content_len", "content_file", "render", "template", "mode", "format", "pdf", "atime", "mtime", "ctime", "crtime"},
	"append":        {"path", "ref", "id", "content", "content_len", "content_file", "render", "template", "mode", "atime", "mtime", "ctime", "crtime"},
	"delete":        {"path", "ref", "refs", "missing_ok", "atime", "mtime"},
	"mace":          {"path", "ref", "refs", "mode", "atime", "mtime", "ctime", "crtime"},
	"rename":        {"path", "ref", "new_path", "id"},
	"copy":          {"path", "ref", "new_path", "id", "mode", "atime", "mtime", "ctime", "crtime"},
	"truncate":      {"path", "ref", "refs", "mode", "atime", "mtime", "ctime", "crtime"},
	"rotate":        {"path", "ref", "new_path", "mode", "atime", "mtime"},
	"email":         {"path", "id", "email", "format", "mode", "atime", "mtime", "ctime", "crtime"},
	"ansible-vault": {"path", "id", "vault", "content", "content_file", "render", "mode", "atime", "mtime", "ctime", "crtime"},
	"ads":           {"path", "ref", "refs", "stream", "content", "content_len", "content_file", "render", "atime", "mtime"},
	"motw":          {"path", "ref", "refs", "zone_id", "host_url", "referrer_url", "atime", "mtime"},
}

// TimeFields are the explicit time keys, in the order access, modification,
// change, birth.
var TimeFields = []string{"atime", "mtime", "ctime", "crtime"}

// PlaybookOnly are keys that exist on playbook actions but not on manifest
// operations. "template" is further limited to the actions that list it.
var PlaybookOnly = []string{"offset", "condition", "template"}

// Required lists the keys an action cannot do without (beyond a target).
var Required = map[string][]string{
	"rename":        {"new_path"},
	"copy":          {"new_path"},
	"rotate":        {"new_path"},
	"email":         {"email"},
	"ansible-vault": {"vault"},
	"ads":           {"stream"},
}

// Closed value sets.
var (
	Conditions = []string{"odd", "even", "first", "last"}
	Templates  = []string{"email", "log", "script", "doc"}
	Types      = []string{"file", "dir"}
	// Formats lists the format values each action accepts.
	Formats = map[string][]string{
		"create": {"raw", "text", "pdf"},
		"update": {"raw", "text", "pdf"},
		"email":  {"eml", "mbox"},
	}
)

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// AllowedFields lists every key an action may carry in a manifest (playbook
// false) or a playbook (true), sorted.
func AllowedFields(action string, playbook bool) []string { return allowed(action, playbook) }

func allowed(action string, playbook bool) []string {
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
func checkFields(src SourceRef, k keys, action string, playbook bool) ErrorList {
	var errs ErrorList
	at := func(field, format string, args ...any) {
		e := &Error{Src: src, Field: field, Msg: fmt.Sprintf(format, args...)}
		if n := k[field]; n != nil {
			e.Line, e.Col = n.Line, n.Column
		}
		errs.add(e)
	}

	if !k.has("action") {
		errs.add(&Error{Src: src, Msg: "missing field \"action\""})
		return errs
	}
	if _, ok := Fields[action]; !ok {
		at("action", "unknown action %q (want one of: %s)", action, strings.Join(Actions, ", "))
		return errs
	}

	ok := allowed(action, playbook)
	names := make([]string, 0, len(k))
	for name := range k {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !contains(ok, name) {
			at(name, "does not apply to %s (it takes: %s)", action, strings.Join(ok, ", "))
		}
	}

	targets := 0
	for _, t := range []string{"path", "ref", "refs"} {
		if k.has(t) {
			targets++
		}
	}
	switch {
	case targets == 0:
		if contains(Fields[action], "ref") {
			errs.add(&Error{Src: src, Msg: action + " needs path, ref or refs"})
		} else {
			errs.add(&Error{Src: src, Msg: action + " needs path"})
		}
	case targets > 1:
		at("path", "give exactly one of path, ref and refs")
	}
	for _, req := range Required[action] {
		if !k.has(req) {
			errs.add(&Error{Src: src, Msg: fmt.Sprintf("%s needs %s", action, req)})
		}
	}

	if action == "mace" && !k.has("atime") && !k.has("mtime") && !k.has("ctime") && !k.has("crtime") {
		errs.add(&Error{Src: src, Msg: "mace needs at least one of atime, mtime, ctime and crtime"})
	}
	if k.has("template") && (k.has("content") || k.has("content_file")) {
		at("template", "cannot be combined with content or content_file; the template would silently replace them")
	}
	if k.has("content") && k.has("content_file") {
		at("content_file", "content and content_file are mutually exclusive")
	}
	if k.has("content_len") && (k.has("content") || k.has("content_file") || k.has("template")) {
		at("content_len", "has no effect when content, content_file or template is given")
	}
	if k.has("render") && !k.has("content") && !k.has("content_file") {
		at("render", "only applies to content or content_file")
	}
	if k.has("pdf") && !k.has("format") {
		at("pdf", "needs format: pdf")
	}
	return errs
}
