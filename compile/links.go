package compile

import (
	"errors"
	"fmt"
	"slices"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/spec"
)

// TargetTypes are what a symlink can say it points at. Windows records the
// difference in the link, so a link to a target that is not there yet still
// has to say which it will be.
var TargetTypes = []string{"file", "dir"}

// checkLinkFields checks what a symlink or junction points at, once its own
// path is clean. A symlink's target is relative to its directory, as the
// file system stores it, and may leave the output only when the scenario
// says so; a junction's is a directory in the output, written as a path is.
func checkLinkFields(op *Op, r reporter) {
	switch op.Action {
	case spec.ActionSymlink:
		if op.keys.has("target_type") && !slices.Contains(TargetTypes, op.TargetType) {
			r.at("target_type", "unknown target_type %q (want file or dir)", op.TargetType)
		}
		if op.Path == "" {
			return
		}
		_, external, err := pathpolicy.LinkTarget(op.Path, op.Target)
		switch {
		case err != nil:
			r.at("target", "%v", err)
		case external && !op.AllowExternalTarget:
			r.at("target", "%q points outside the output; fsagen writes such a target as given and never follows it, but only with allow_external_target: true", op.Target)
		case !external && op.AllowExternalTarget:
			r.at("allow_external_target", "has no effect: %q points inside the output", op.Target)
		}
	case spec.ActionJunction:
		clean, _, err := pathpolicy.Output("", op.Target)
		if err != nil {
			r.at("target", "%v", err)
			return
		}
		op.Target = clean
	}
}

// applyHardlink gives an existing file a second name. The file's change
// time moves, as its link count does, and the new name's $FILE_NAME times
// are the file's own times at that moment.
func applyHardlink(s *simulation) error {
	op := s.op
	if err := s.portable(op.NewPath); err != nil {
		return err
	}
	if err := linkErr(s.tree.Link(op.Path, op.NewPath), op.Path, op.NewPath); err != nil {
		return err
	}
	s.tag(op.NewPath)
	s.primary = op.NewPath
	return nil
}

// applySymlink makes a symlink. Its target is recorded as written and never
// resolved through; what it is matters only for the link's type.
func applySymlink(s *simulation) error {
	op := s.op
	if err := s.portable(op.Path); err != nil {
		return err
	}
	kind, err := symlinkType(s.tree, op)
	if err != nil {
		return err
	}
	op.TargetType = kind
	if err := s.tree.CreateLink(op.Path, model.Symlink, op.Target); err != nil {
		return existErr("symlink", err, op.Path)
	}
	s.tag(op.Path)
	return nil
}

// symlinkType settles whether a symlink points at a file or a directory:
// what the scenario says, which must agree with a target that is already
// there, or else what the target is, or a file for a target that is not
// there or not in the output.
func symlinkType(t *model.Tree, op *Op) (string, error) {
	resolved, external, _ := pathpolicy.LinkTarget(op.Path, op.Target)
	var found string
	if o := t.Get(resolved); !external && o != nil {
		switch o.Kind {
		case model.File:
			found = "file"
		case model.Dir:
			found = "dir"
		}
	} else if !external && resolved == "." {
		found = "dir"
	}
	switch {
	case op.TargetType != "" && found != "" && op.TargetType != found:
		return "", fmt.Errorf("target_type is %s, but %s is a %s", op.TargetType, resolved, kindNoun(found))
	case op.TargetType != "":
		return op.TargetType, nil
	case found != "":
		return found, nil
	}
	return "file", nil
}

func kindNoun(t string) string {
	if t == "dir" {
		return "directory"
	}
	return t
}

// applyJunction makes a junction, which Windows only lets point at a
// directory that exists.
func applyJunction(s *simulation) error {
	op := s.op
	if err := s.portable(op.Path); err != nil {
		return err
	}
	if o := s.tree.Get(op.Target); o == nil || o.Kind != model.Dir {
		return fmt.Errorf("junction: target %s is not a directory in the output at this point; a junction can only point at one", op.Target)
	}
	if err := s.tree.CreateLink(op.Path, model.Junction, op.Target); err != nil {
		return existErr("junction", err, op.Path)
	}
	s.tag(op.Path)
	return nil
}

func linkErr(err error, from, to string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, model.ErrExist):
		return fmt.Errorf("hardlink: %s already exists", to)
	case errors.Is(err, model.ErrNotExist):
		return fmt.Errorf("hardlink: %s does not exist", from)
	}
	return fmt.Errorf("hardlink: %w", err)
}

func existErr(action string, err error, p string) error {
	if errors.Is(err, model.ErrExist) {
		return fmt.Errorf("%s: %s already exists", action, p)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// notFile explains why the object an action needs as a file is not one. A
// link is never written, read or copied through: that would follow it.
func notFile(what, p string, k model.Kind) error {
	switch k {
	case model.Dir:
		return fmt.Errorf("%s: %s is a directory", what, p)
	case model.Symlink, model.Junction:
		return fmt.Errorf("%s: %s is a link; fsagen never follows one, so it is not written, read or copied through", what, p)
	}
	return fmt.Errorf("%s: %s is not a file", what, p)
}

// linkTargetDir is the directory a junction's target names, for joining an
// actor's base; a symlink's target is relative to the link and is left as
// it is.
func linkTargetDir(op spec.Operation, base string) string {
	if op.Action != spec.ActionJunction {
		return op.Target
	}
	return joinPath(base, op.Target)
}
