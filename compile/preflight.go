package compile

import (
	"fmt"
	"runtime"
)

// Caps is what the platform and output volume can do.
type Caps struct {
	// NamedStreams: the volume stores alternate data streams (NTFS, ReFS).
	NamedStreams bool
}

// DefaultCaps is the capability set assumed when no output volume is known
// (for --validate and --dry-run without an output path).
func DefaultCaps() Caps { return Caps{NamedStreams: runtime.GOOS == "windows"} }

// unsupported explains why caps cannot perform op, or returns "".
func unsupported(op *Op, caps Caps) string {
	switch op.Action {
	case "ads", "motw":
		if !caps.NamedStreams {
			return fmt.Sprintf("%s writes an alternate data stream, which this platform or volume does not support", op.Action)
		}
	}
	return ""
}

// Preflight checks every operation against the capability set before
// anything is written. By default any unsupported operation fails the whole
// run, listing all of them; with skip, each is marked and left for the run
// manifest to record, and the rest of the scenario is generated.
func Preflight(p *Program, caps Caps, skip bool) error {
	var errs ErrorList
	for i := range p.Ops {
		op := &p.Ops[i]
		reason := unsupported(op, caps)
		if reason == "" {
			continue
		}
		if skip {
			op.Skip = reason
			continue
		}
		errs.add(&Error{Src: op.Src, Msg: reason + " (pass --on-unsupported=skip to generate the rest and record the skip)"})
	}
	return errs.err()
}

// Skipped lists the operations Preflight marked as skipped.
func (p *Program) Skipped() []Op {
	var out []Op
	for _, op := range p.Ops {
		if op.Skip != "" {
			out = append(out, op)
		}
	}
	return out
}
