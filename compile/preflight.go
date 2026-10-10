package compile

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
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
	// FilenameTimes: the times NTFS keeps in each $FILE_NAME attribute can
	// be set. No live volume allows it: Windows sets them itself, and no
	// call a program can make changes them.
	FilenameTimes bool
	// Hardlinks, Symlinks and Junctions: the volume stores them, and this
	// process may make them (a Windows symlink needs Developer Mode or the
	// privilege).
	Hardlinks, Symlinks, Junctions bool
	// Slack is how far the target keeps bytes written past the end of a
	// file, and ClusterSize the size of its clusters (0 when not known, as
	// for --validate with no output volume).
	Slack       SlackSupport
	ClusterSize int
}

// DefaultCaps is the capability set assumed when no output volume is known
// (for --validate and --dry-run without an output path).
func DefaultCaps() Caps {
	w := runtime.GOOS == "windows"
	slack := SlackNone
	if w {
		slack = SlackBestEffort
	}
	return Caps{
		NamedStreams: w, BirthTime: w, ChangeTime: w, Slack: slack,
		Hardlinks: true, Symlinks: sandbox.SymlinksAllowed(), Junctions: w,
	}
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
	if !caps.FilenameTimes {
		for _, f := range fileNameTimeFields(op) {
			if strings.TrimSpace(f.val) != "" {
				out = append(out, f.key)
			}
		}
	}
	return out
}

// unsupported explains why caps cannot perform op, or returns "".
func unsupported(op *Op, caps Caps) string {
	switch op.Action {
	case spec.ActionADS, spec.ActionMOTW:
		if !caps.NamedStreams {
			return fmt.Sprintf("%s writes an alternate data stream, which this platform or volume does not support", op.Action)
		}
	case spec.ActionHardlink:
		if !caps.Hardlinks {
			return "this volume does not store hard links"
		}
	case spec.ActionSymlink:
		if !caps.Symlinks {
			return "symlinks cannot be made here: the volume does not store them, or on Windows the process has neither Developer Mode nor the privilege to create one"
		}
	case spec.ActionJunction:
		if !caps.Junctions {
			return "junctions are an NTFS feature of Windows, and this platform or volume has none"
		}
	}
	return ""
}

// unskippable reports an action that cannot be left out and the rest still
// run: a link is a name later actions and the settle pass rely on.
func unskippable(op *Op) bool {
	switch op.Action {
	case spec.ActionHardlink, spec.ActionSymlink, spec.ActionJunction:
		return true
	}
	return false
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
		if op := &p.Ops[i]; op.NoOp == "" {
			preflightOp(op, caps, skip, &errs)
		}
	}
	return errs.err()
}

// timeFieldNames are the words used to report a time this platform cannot set.
// A field missing from here would read as "the  cannot be set", so every field
// unsettable can return needs an entry.
var timeFieldNames = map[string]string{
	"ctime": "change time", "crtime": "creation time",
	"fn_atime": "$FILE_NAME access time", "fn_mtime": "$FILE_NAME modification time",
	"fn_ctime": "$FILE_NAME change time", "fn_crtime": "$FILE_NAME creation time",
}

// preflightOp records every time field this platform cannot set for one
// operation, and whether the action itself is unsupported here.
func preflightOp(op *Op, caps Caps, skip bool, errs *ErrorList) {
	r := op.report(errs)
	for _, f := range unsettable(op, caps) {
		switch {
		case skip:
			op.Dropped = append(op.Dropped, f)
		case strings.HasPrefix(f, "fn_"):
			r.at(f, "the %s cannot be set on a live volume: Windows sets the $FILE_NAME times itself and no program can change them (pass --on-unsupported=skip to set the other times only and record that)", timeFieldNames[f])
		default:
			r.at(f, "the %s cannot be set on this platform or volume (pass --on-unsupported=skip to generate without it and record that)", timeFieldNames[f])
		}
	}
	switch reason := unsupported(op, caps); {
	case reason == "":
	case unskippable(op):
		r.whole("%s; a link cannot be skipped, since later actions and the settle pass would act on a name that is not there", reason)
	case skip:
		op.Skip = reason
	default:
		r.whole("%s (pass --on-unsupported=skip to generate the rest and record the skip)", reason)
	}
	switch reason := slackUnsupported(op, caps); {
	case reason == "":
	case skip:
		op.SlackDropped = reason
	default:
		r.at("slack", "%s (pass --on-unsupported=skip to write the file without its slack and record that)", reason)
	}
}
