package compile

import (
	"fmt"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// compileManifest renders a manifest's operations in declaration order.
// ${SEQ} is the 1-based operation number.
func compileManifest(file string, root *yaml.Node, m *spec.Manifest, opts Options, src *sandbox.Sources) ([]Op, bool, error) {
	var errs ErrorList
	if len(m.Operations) == 0 {
		return nil, false, fmt.Errorf("%s: no operations", file)
	}
	rootKeys := mappingKeys(root)
	fileRef := SourceRef{File: file, Line: root.Line, Col: root.Column}
	start, startNow, err := parseStart(m.Start, rootKeys.has("start"), false, fileRef, rootKeys, opts)
	if err != nil {
		return nil, false, err
	}

	vars := render.MergeVariables(m.Variables, opts.Vars)
	nodes := seqItems(mappingValue(root, "operations"))
	opKeys := newOpKeys(opts.Seed)

	out := make([]Op, 0, len(m.Operations))
	for i, raw := range m.Operations {
		n := nodes[i]
		ref := SourceRef{File: file, Line: n.Line, Col: n.Column, Op: i + 1, Name: raw.Action}
		k := mappingKeys(n)
		if fieldErrs := checkFields(ref, k, raw.Action, false); len(fieldErrs) > 0 {
			errs.add(fieldErrs)
			continue
		}

		// An operation's reference time is its own mtime, else its atime,
		// else the manifest's start. With none of them it has none: ${DATE}
		// and unpinned pdf or email dates are then errors, never the wall
		// clock, and the file system keeps the times it gives the files.
		refTime := start
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw.Mtime)); err == nil {
			refTime = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw.Atime)); err == nil {
			refTime = t.UTC()
		}
		if err := defaultDates(&raw, refTime); err != nil {
			errs.add(&Error{Src: ref, Field: err.field, Msg: err.msg})
			continue
		}

		kind, value := identity(raw.ID, n)
		rctx := render.Context{Seq: i + 1, Timestamp: refTime, Variables: vars, Rand: opKeys.key("manifest", kind, value)}
		prepared, err := Prepare(raw, src, rctx)
		if err != nil {
			errs.add(&Error{Src: ref, Msg: err.Error()})
			continue
		}
		out = append(out, Op{Operation: prepared, Src: ref, When: refTime, Rand: rctx.Rand, keys: k})
	}
	return out, startNow, errs.err()
}

// parseStart reads a top-level start: an RFC 3339 time, or "now", which is
// read from the injected clock and marks the run as not reproducible.
func parseStart(value string, given, required bool, fileRef SourceRef, rootKeys keys, opts Options) (time.Time, bool, error) {
	fail := func(format string, args ...any) (time.Time, bool, error) {
		e := &Error{Src: fileRef, Field: "start", Msg: fmt.Sprintf(format, args...)}
		if n := rootKeys["start"]; n != nil {
			e.Line, e.Col = n.Line, n.Column
		}
		var errs ErrorList
		errs.add(e)
		return time.Time{}, false, errs.err()
	}
	switch s := strings.TrimSpace(value); {
	case s == "" && given:
		return fail("is empty: give an RFC 3339 time, or \"now\" for a run that cannot be reproduced")
	case s == "" && required:
		return fail("is required: give an RFC 3339 time, or \"now\" for a run that cannot be reproduced")
	case s == "":
		return time.Time{}, false, nil
	case s == "now":
		return opts.now(), true, nil
	default:
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fail("%q is not an RFC 3339 time or \"now\"", value)
		}
		return t, false, nil
	}
}

type fieldError struct{ field, msg string }

// defaultDates fills the dates a typed generator would otherwise take from
// the wall clock: a pdf's creation and modification dates (either one
// given stands in for the other) and an email's Date header default to the
// reference time. The nested specs are copied first, so an action repeated
// by a playbook never shares them between iterations.
func defaultDates(op *spec.Operation, ref time.Time) *fieldError {
	if op.Pdf != nil {
		p := *op.Pdf
		op.Pdf = &p
	}
	if op.Vault != nil {
		v := *op.Vault
		op.Vault = &v
	}
	if op.Email != nil {
		op.Email = cloneEmail(op.Email)
	}
	stamp := ref.UTC().Format(time.RFC3339)

	if op.Format == "pdf" {
		if op.Pdf == nil {
			op.Pdf = &spec.PdfSpec{}
		}
		created, modified := strings.TrimSpace(op.Pdf.Created), strings.TrimSpace(op.Pdf.Modified)
		switch {
		case created == "" && modified != "":
			op.Pdf.Created = modified
		case modified == "" && created != "":
			op.Pdf.Modified = created
		case created == "" && modified == "":
			if ref.IsZero() {
				return &fieldError{"format", "a pdf needs its dates: set pdf.created and pdf.modified, or give the operation an mtime or the manifest a start"}
			}
			op.Pdf.Created, op.Pdf.Modified = stamp, stamp
		}
	}
	if op.Action == "email" && op.Email != nil && strings.TrimSpace(op.Email.Date) == "" {
		if ref.IsZero() {
			return &fieldError{"email", "the message needs a date: set email.date, or give the operation an mtime or the manifest a start"}
		}
		op.Email.Date = stamp
	}
	return nil
}

func cloneEmail(e *spec.EmailSpec) *spec.EmailSpec {
	c := *e
	c.To = append([]string(nil), e.To...)
	c.Cc = append([]string(nil), e.Cc...)
	c.Bcc = append([]string(nil), e.Bcc...)
	c.References = append([]string(nil), e.References...)
	c.Headers = append([]spec.Header(nil), e.Headers...)
	c.Attachments = append([]spec.Attachment(nil), e.Attachments...)
	return &c
}
