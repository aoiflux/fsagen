// Package compile turns a manifest or playbook into the exact list of
// operations fsagen will perform, and proves it can be performed before
// anything touches the disk.
//
//	load (strict YAML, positions) -> compile (render tokens, schedule)
//	  -> check (field matrix, values, paths) -> simulate (ids/refs, existence,
//	  collisions, against an in-memory model of the tree) -> pre-flight
//	  (platform capabilities)
//
// Every problem is reported with the file, line and column, the operation or
// step/action it belongs to, and the field at fault.
package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// Mode is the kind of input file.
type Mode string

const (
	ModeManifest Mode = "manifest"
	ModePlaybook Mode = "playbook"
)

// Op is one fully resolved operation: every token rendered, every path
// cleaned and confined, every ref expanded.
type Op struct {
	spec.Operation
	Src SourceRef
	// At is the playbook's scheduled time for the action; zero in manifests.
	At time.Time
	// Dir is set on a create whose path names a directory.
	Dir bool
	// NoOp explains why the operation has nothing to do (a delete of a
	// missing path with missing_ok); the executor skips it.
	NoOp string
	// Skip explains why the platform cannot perform the operation, when the
	// run was told to skip rather than fail (--on-unsupported=skip).
	Skip string

	keys keys
}

// Options tune compilation.
type Options struct {
	// Vars are --vars-file/--var values; they override the file's own.
	Vars map[string]string
	// AllowExternalSources lets content_file and friends read outside the
	// YAML file's directory.
	AllowExternalSources bool
	// AllowNonportable waives the portability checks (reserved device names,
	// case collisions, path length budget).
	AllowNonportable bool
	// Existing seeds the model with a tree that is already on disk
	// (--into-existing).
	Existing *model.Tree
}

// Program is a compiled input.
type Program struct {
	Mode    Mode
	File    string
	SHA256  string
	Ops     []Op
	Sources *sandbox.Sources
	Model   *model.Tree
	// StartNow records a playbook that starts at the wall-clock time and so
	// cannot be reproduced.
	StartNow bool
}

// Close releases the source reader.
func (p *Program) Close() error {
	if p.Sources != nil {
		return p.Sources.Close()
	}
	return nil
}

// Load reads, compiles, checks and simulates one manifest or playbook.
func Load(mode Mode, file string, opts Options) (*Program, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	src, err := sandbox.OpenSources(filepath.Dir(file), opts.AllowExternalSources)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	prog := &Program{Mode: mode, File: file, SHA256: hex.EncodeToString(sum[:]), Sources: src}

	switch mode {
	case ModeManifest:
		var m spec.Manifest
		root, err := decodeFile(file, data, &m)
		if err != nil {
			src.Close()
			return nil, err
		}
		prog.Ops, err = compileManifest(file, root, &m, opts, src)
		if err != nil {
			src.Close()
			return nil, err
		}
	case ModePlaybook:
		var pb spec.Playbook
		root, err := decodeFile(file, data, &pb)
		if err != nil {
			src.Close()
			return nil, err
		}
		prog.Ops, prog.StartNow, err = compilePlaybook(file, root, &pb, opts, src)
		if err != nil {
			src.Close()
			return nil, err
		}
	default:
		src.Close()
		return nil, fmt.Errorf("unknown input mode %q", mode)
	}

	var errs ErrorList
	for i := range prog.Ops {
		errs.add(checkValues(&prog.Ops[i], src))
	}
	if err := errs.err(); err != nil {
		src.Close()
		return nil, err
	}

	tree := opts.Existing
	if tree == nil {
		tree = model.New()
	}
	if !opts.AllowNonportable {
		tree.SetFold(pathpolicy.FoldKey)
	}
	prog.Model = tree
	if prog.Ops, err = simulate(prog.Ops, tree, opts); err != nil {
		src.Close()
		return nil, err
	}
	return prog, nil
}
