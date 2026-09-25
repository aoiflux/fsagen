package compile

import (
	"fmt"
	"runtime"
	"strings"
)

// Caps is what the platform and output volume can do.
type Caps struct {
	// NamedStreams: the volume stores alternate data streams (NTFS, ReFS).
	NamedStreams bool
	// BirthTime: a file's creation time can be set (Windows).
	BirthTime bool
	// ChangeTime: a file's metadata change time can be set and is stored
	// (Windows on NTFS or ReFS).
	ChangeTime bool
}

// DefaultCaps is the capability set assumed when no output volume is known
// (for --validate and --dry-run without an output path).
func DefaultCaps() Caps {
	w := runtime.GOOS == "windows"
	return Caps{NamedStreams: w, BirthTime: w, ChangeTime: w}
}

// unsettable lists the explicit time fields of op that caps cannot set.
func unsettable(op *Op, caps Caps) []string {
	var out []string
	if strings.TrimSpace(op.Ctime) != "" && !caps.ChangeTime {
		out = append(out, "ctime")
	}
	if strings.TrimSpace(op.Crtime) != "" && !caps.BirthTime {
		out = append(out, "crtime")
	}
	return out
}

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
// anything is written. By default any unsupported operation, or explicit
// time the platform cannot set, fails the whole run, listing all of them;
// with skip, each is marked and left for the run manifest to record, and the
// rest of the scenario is generated. (A time the scenario only implies, such
// as the creation time of a file created on Linux, is never an error: the
// ledger records it as uncontrolled.)
func Preflight(p *Program, caps Caps, skip bool) error {
	var errs ErrorList
	for i := range p.Ops {
		op := &p.Ops[i]
		if op.NoOp != "" {
			continue
		}
		for _, f := range unsettable(op, caps) {
			if skip {
				op.Dropped = append(op.Dropped, f)
				continue
			}
			what := map[string]string{"ctime": "change time", "crtime": "creation time"}[f]
			e := &Error{Src: op.Src, Field: f, Msg: fmt.Sprintf("the %s cannot be set on this platform or volume (pass --on-unsupported=skip to generate without it and record that)", what)}
			if n := op.keys[f]; n != nil {
				e.Line, e.Col = n.Line, n.Column
			}
			errs.add(e)
		}
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
