package compile

import (
	"path"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/util"
)

// The time rules. T is the operation's time (Op.When; an email's Date).
// Explicit atime, mtime, ctime and crtime always win over what a rule
// derives.
//
//	create, ansible-vault, eml   born: all four times T
//	update, append, truncate     written: access, modification, change T;
//	                             birth kept (append to a missing file and a
//	                             first mbox message are born instead)
//	mace                         only the explicit times
//	ads, motw                    the file's times unchanged
//	rename                       the object keeps its times, change T
//	rotate                       the rotated file as rename; the new empty
//	                             file at the old path born at T
//	copy                         the copy born at T with the source's mtime
//	delete                       the object keeps its final times; explicit
//	                             times describe the directory it leaves
//	directories                  born with the operation that makes them,
//	                             explicitly or as a missing parent; each
//	                             entry added, removed or renamed sets
//	                             modification and change to T
//
// When T is zero (a manifest operation with no times and no start) the
// derived times are zero too, which means uncontrolled: the file system
// keeps the times it gives, and the ledger says so.

// opTime is the time the operation happens.
func opTime(op *Op) time.Time {
	if op.Action == "email" && op.Email != nil {
		if d, err := time.Parse(time.RFC3339, strings.TrimSpace(op.Email.Date)); err == nil {
			return d.UTC()
		}
	}
	if op.When.IsZero() {
		return time.Time{}
	}
	return op.When.UTC()
}

func born(t *model.Tree, p string, when time.Time) {
	if o := t.Get(p); o != nil {
		o.Times = model.All(when)
	}
}

func written(t *model.Tree, p string, when time.Time) {
	if o := t.Get(p); o != nil {
		o.Times.Atime, o.Times.Mtime, o.Times.Ctime = when, when, when
	}
}

// explicitTimes are the times the operation states itself; checkValues has
// already validated them.
func explicitTimes(op *Op) model.Times {
	parse := func(s string) time.Time {
		s = strings.TrimSpace(s)
		if s == "" {
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}
		}
		return t.UTC()
	}
	return model.Times{Atime: parse(op.Atime), Mtime: parse(op.Mtime), Ctime: parse(op.Ctime), Btime: parse(op.Crtime)}
}

func overlay(dst *model.Times, ex model.Times) {
	if !ex.Atime.IsZero() {
		dst.Atime = ex.Atime
	}
	if !ex.Mtime.IsZero() {
		dst.Mtime = ex.Mtime
	}
	if !ex.Ctime.IsZero() {
		dst.Ctime = ex.Ctime
	}
	if !ex.Btime.IsZero() {
		dst.Btime = ex.Btime
	}
}

// stampsAfter lists what to stamp once the operation has run: the objects
// it names, then the directories whose entries it changed. The settle pass
// stamps everything again at the end; these stamps are what an object
// carries if a later operation deletes it.
func stampsAfter(t *model.Tree, paths ...string) []Stamp {
	var files, dirs []Stamp
	seen := map[string]bool{".": true, "": true}
	add := func(q string) {
		if seen[q] {
			return
		}
		seen[q] = true
		o := t.Get(q)
		if o == nil {
			return
		}
		if o.Kind == model.Dir {
			dirs = append(dirs, Stamp{Path: q, Times: o.Times})
			return
		}
		files = append(files, Stamp{Path: q, Times: o.Times})
	}
	for _, q := range paths {
		add(q)
	}
	for _, q := range paths {
		if q != "" {
			add(path.Dir(q))
		}
	}
	return append(files, dirs...)
}

// settleTimes records what the operation intends for the object it leaves
// behind: the times and mode that object should end up with, and the stamps to
// apply once the operation has run.
func settleTimes(s *simulation) {
	if o := s.tree.Get(s.primary); o != nil {
		overlay(&o.Times, explicitTimes(s.op))
	}
	// A delete leaves nothing behind to describe; it recorded the removed
	// object's identity and times before removing it.
	if s.op.Action != "delete" {
		s.recordPrimary()
	}
	s.op.Stamps = stampsAfter(s.tree, s.op.Path, s.op.NewPath, s.primary)
}

// recordPrimary copies the primary object's identity, kind and settled times
// onto the operation, and applies an explicit mode to exactly that object.
func (s *simulation) recordPrimary() {
	o := s.tree.Get(s.primary)
	if o == nil {
		return
	}
	if mode, ok, _ := util.ParseFileMode(s.op.Mode); ok {
		o.Mode = mode
	}
	s.op.Object, s.op.Kind, s.op.Times = o.Serial, o.Kind, o.Times
}
