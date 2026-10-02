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
	"github.com/aoiflux/fsagen/prng"
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
	// When is the time the operation happens, which the time rules stamp
	// on what it creates or changes: the scheduled time (plus any sub-second
	// jitter) in a playbook; the operation's mtime, else its atime, else the
	// manifest's start in a manifest; an email's Date. Zero means the
	// scenario does not say, and the file system keeps whatever times it
	// gives.
	When time.Time
	// Object is the model's serial number for the object the operation
	// leaves behind (for a delete, the one it removes), and Times are that
	// object's intended times afterwards (for a delete, just before).
	Object int
	Kind   model.Kind
	Times  model.Times
	// Moved is, for a rotate, the object renamed to NewPath; Object is then
	// the empty file left at Path.
	Moved int
	// Members are, for an archive, the files it holds, resolved against the
	// model at the moment the archive is written.
	Members []Member
	// Pre are stamped just before the operation runs: a deleted object gets
	// its final times first, so what is left of it carries scenario times.
	// Stamps are applied just after it.
	Pre, Stamps []Stamp
	// Dropped lists explicit time fields this platform cannot set, dropped
	// because the run was told to skip what it cannot do.
	Dropped []string
	// Dir is set on a create whose path names a directory.
	Dir bool
	// NoOp explains why the operation has nothing to do (a delete of a
	// missing path with missing_ok); the executor skips it.
	NoOp string
	// Skip explains why the platform cannot perform the operation, when the
	// run was told to skip rather than fail (--on-unsupported=skip).
	Skip string
	// Rand is the operation's random key; every value the executor
	// generates for it (random content, MIME boundaries, a vault salt) is
	// drawn from a stream derived from it.
	Rand prng.Key
	// Random is the number of random characters to write as the content,
	// when the operation gives no content of its own; zero means the content
	// is exactly Content, which may be empty.
	Random int

	keys keys
}

// Member is one file an archive holds: where it is in the output tree, the
// name it is stored under, and the modification time it had when the archive
// was made.
type Member struct {
	Path  string
	Name  string
	Times model.Times
}

// Stamp is the set of intended times for one path.
type Stamp struct {
	Path  string
	Times model.Times
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
	// Seed keys every random value.
	Seed int64
	// SkipUnsupported makes manifest.ExecuteFile's pre-flight skip what the
	// platform cannot do and record it, as --on-unsupported=skip does,
	// instead of refusing the run.
	SkipUnsupported bool
	// Now is read only for start: now. Nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// Program is a compiled input.
type Program struct {
	Mode    Mode
	File    string
	SHA256  string
	Ops     []Op
	Sources *sandbox.Sources
	Model   *model.Tree
	// StartNow records an input that starts at the wall-clock time and so
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
	// The returned program owns the source root and releases it through
	// Program.Close; every path that does not return one has to release it
	// here instead. One deferred close covers them all, so a failure added
	// below cannot be the one that leaks a directory handle.
	loaded := false
	defer func() {
		if !loaded {
			src.Close()
		}
	}()

	sum := sha256.Sum256(data)
	prog := &Program{Mode: mode, File: file, SHA256: hex.EncodeToString(sum[:]), Sources: src}

	switch mode {
	case ModeManifest:
		var m spec.Manifest
		root, err := decodeFile(file, data, &m)
		if err != nil {
			return nil, err
		}
		if prog.Ops, prog.StartNow, err = compileManifest(file, root, &m, opts, src); err != nil {
			return nil, err
		}
	case ModePlaybook:
		var pb spec.Playbook
		root, err := decodeFile(file, data, &pb)
		if err != nil {
			return nil, err
		}
		if prog.Ops, prog.StartNow, err = compilePlaybook(file, root, &pb, opts, src); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown input mode %q", mode)
	}

	var errs ErrorList
	for i := range prog.Ops {
		errs.add(checkValues(&prog.Ops[i], src))
	}
	if err := errs.err(); err != nil {
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
		return nil, err
	}
	loaded = true
	return prog, nil
}
