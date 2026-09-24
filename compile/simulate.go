package compile

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/pathpolicy"
)

// simulate runs the operations, in execution order, against an in-memory
// model of the tree. It expands ref/refs into concrete paths and rejects
// anything that would fail, or silently do nothing, on disk.
func simulate(ops []Op, t *model.Tree, opts Options) ([]Op, error) {
	var errs ErrorList
	declared := map[string]SourceRef{} // id -> the YAML action that declares it

	fail := func(op *Op, field, format string, args ...any) {
		e := &Error{Src: op.Src, Field: field, Msg: fmt.Sprintf(format, args...)}
		if n := op.keys[field]; n != nil {
			e.Line, e.Col = n.Line, n.Column
		}
		errs.add(e)
	}

	out := make([]Op, 0, len(ops))
	for i := range ops {
		op := &ops[i]

		if op.ID != "" {
			if prev, ok := declared[op.ID]; ok && (prev.Line != op.Src.Line || prev.Col != op.Src.Col || prev.File != op.Src.File) {
				fail(op, "id", "id %q is already declared at %s:%d:%d", op.ID, prev.File, prev.Line, prev.Col)
				continue
			}
			declared[op.ID] = op.Src
		}

		targets := []string{op.Path}
		switch {
		case op.Ref != "":
			live, known := t.Live(op.Ref)
			switch {
			case !known:
				fail(op, "ref", "unknown id %q (ids are declared with id: on an earlier action)", op.Ref)
				continue
			case len(live) == 0:
				fail(op, "ref", "every path created under id %q has already been deleted", op.Ref)
				continue
			case len(live) > 1:
				fail(op, "ref", "id %q names %d paths; use refs: to act on all of them", op.Ref, len(live))
				continue
			}
			targets = live
		case op.Refs != "":
			live, known := t.Live(op.Refs)
			switch {
			case !known:
				fail(op, "refs", "unknown id %q (ids are declared with id: on an earlier action)", op.Refs)
				continue
			case len(live) == 0:
				fail(op, "refs", "every path created under id %q has already been deleted", op.Refs)
				continue
			}
			targets = live
		}

		for _, p := range targets {
			o := *op
			o.Path, o.Ref, o.Refs = p, "", ""
			if err := apply(t, &o, opts); err != nil {
				field := "path"
				if op.Ref != "" {
					field = "ref"
				} else if op.Refs != "" {
					field = "refs"
				}
				fail(&o, field, "%v", err)
				continue
			}
			out = append(out, o)
		}
	}
	return out, errs.err()
}

// apply performs one operation on the model, enforcing the preconditions
// the executor relies on.
func apply(t *model.Tree, op *Op, opts Options) error {
	p := op.Path
	portable := func(paths ...string) error {
		if opts.AllowNonportable {
			return nil
		}
		for _, q := range paths {
			if err := pathpolicy.Portable(q); err != nil {
				return fmt.Errorf("%w (pass --allow-nonportable for a scenario that only has to work on one platform)", err)
			}
		}
		return nil
	}
	mustFile := func(what string) error {
		o := t.Get(p)
		switch {
		case o == nil:
			return fmt.Errorf("%s: %s does not exist%s", what, p, hintFor(op.Action))
		case o.Kind != model.File:
			return fmt.Errorf("%s: %s is a directory", what, p)
		}
		return nil
	}
	tag := func(q string) {
		if op.ID != "" {
			t.Tag(q, op.ID)
		}
	}

	switch op.Action {
	case "create":
		if err := portable(p); err != nil {
			return err
		}
		if op.Dir {
			if err := t.MkdirAll(p); err != nil {
				return err
			}
		} else if _, err := t.CreateFile(p); err != nil {
			return err
		}
		tag(p)

	case "append":
		if o := t.Get(p); o != nil && o.Kind != model.File {
			return fmt.Errorf("append: %s is a directory", p)
		}
		if t.Get(p) == nil {
			if err := portable(p); err != nil {
				return err
			}
			// Appending is how a log comes into being, so a missing file is
			// created, and recorded as created.
			if _, err := t.CreateFile(p); err != nil {
				return err
			}
		}
		tag(p)

	case "update", "truncate":
		return mustFile(op.Action)

	case "delete":
		if t.Get(p) == nil {
			if op.MissingOK {
				op.NoOp = "path does not exist (missing_ok)"
				return nil
			}
			return fmt.Errorf("delete: %s does not exist (set missing_ok: true if that is expected)", p)
		}
		return t.Remove(p)

	case "mace":
		if t.Get(p) == nil {
			return fmt.Errorf("mace: %s does not exist", p)
		}

	case "rename":
		if err := portable(op.NewPath); err != nil {
			return err
		}
		if err := renameErr(t.Rename(p, op.NewPath), p, op.NewPath); err != nil {
			return err
		}
		tag(op.NewPath)

	case "copy":
		if err := mustFile("copy"); err != nil {
			return err
		}
		if err := portable(op.NewPath); err != nil {
			return err
		}
		if err := renameErr(t.Copy(p, op.NewPath), p, op.NewPath); err != nil {
			return err
		}
		tag(op.NewPath)

	case "rotate":
		if err := mustFile("rotate"); err != nil {
			return err
		}
		if err := portable(op.NewPath); err != nil {
			return err
		}
		if err := renameErr(t.Rename(p, op.NewPath), p, op.NewPath); err != nil {
			return err
		}
		if _, err := t.CreateFile(p); err != nil {
			return err
		}

	case "email":
		if err := portable(p); err != nil {
			return err
		}
		if op.Email != nil {
			for i, a := range op.Email.Attachments {
				if a.SourceRoot == "" {
					continue
				}
				if o := t.Get(a.SourceRoot); o == nil || o.Kind != model.File {
					return fmt.Errorf("email.attachments[%d].source_root: %s does not exist in the output at this point", i, a.SourceRoot)
				}
			}
		}
		if emailFormat(op) == "mbox" {
			if o := t.Get(p); o != nil && o.Kind != model.File {
				return fmt.Errorf("email: %s is a directory", p)
			}
		}
		if t.Get(p) == nil || emailFormat(op) == "eml" {
			if _, err := t.CreateFile(p); err != nil {
				return err
			}
		}
		tag(p)

	case "ansible-vault":
		if err := portable(p); err != nil {
			return err
		}
		if _, err := t.CreateFile(p); err != nil {
			return err
		}
		tag(p)

	case "ads", "motw":
		stream := op.Stream
		if op.Action == "motw" {
			stream = "Zone.Identifier"
		}
		if t.Get(p) == nil {
			return fmt.Errorf("%s: base %s does not exist; create it first (a stream cannot exist without its file)", op.Action, p)
		}
		return t.AddStream(p, stream)
	}
	return nil
}

func renameErr(err error, from, to string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, model.ErrExist):
		return fmt.Errorf("%s already exists; moving %s onto it would silently replace it", to, from)
	case errors.Is(err, model.ErrNotExist):
		return fmt.Errorf("%s does not exist", from)
	}
	return err
}

func hintFor(action string) string {
	if action == "update" || action == "truncate" {
		return "; use create to make a new file"
	}
	return ""
}

// emailFormat is the effective format of an email operation: explicit, or
// inferred from a .mbox extension.
func emailFormat(op *Op) string {
	if op.Format != "" {
		return op.Format
	}
	if strings.EqualFold(path.Ext(op.Path), ".mbox") {
		return "mbox"
	}
	return "eml"
}
