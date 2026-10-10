package timeline

import (
	"io/fs"
	"strconv"

	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// Controlled says which of the times a run can set beyond access and
// modification, which it always can. A time the run cannot set is unknown
// in a modelled timeline, never the scenario's wish presented as fact.
// FileName says the times of each name's NTFS $FILE_NAME are set too.
type Controlled struct {
	Birth, Change, FileName bool
}

// Modelled builds the timeline the scenario intends from the model of the
// tree after the last operation and the run's ledger: every object that is
// left, with its settled times, and every object the scenario deleted, with
// the times it had when it went, marked deleted. Sizes and digests are the
// ledger's; the inode column is the ledger's object number, so each line can
// be traced to the operations that made it. The mode is the one fsagen
// requests, before any umask.
//
// Where the run sets the times NTFS keeps in each name's $FILE_NAME (an NTFS
// image), each name the run left also has an entry for its $FILE_NAME, with
// those times, as The Sleuth Kit lists one.
//
// It reads nothing from disk, so it is the same bytes on every run with the
// same inputs and capability set.
func Modelled(tree *model.Tree, entries []ledger.Entry, c Controlled) *Timeline {
	type state struct {
		size    int64
		md5     string
		streams []ledger.Stream
	}
	last := map[int]state{}
	for _, e := range entries {
		if e.Outcome != ledger.Done || e.Object == 0 || e.Action == spec.ActionDelete {
			continue
		}
		st := last[e.Object]
		if e.Size != nil {
			st.size, st.md5 = *e.Size, e.MD5After
		}
		st.streams = e.Streams
		last[e.Object] = st
	}

	tl := &Timeline{Source: SourceModelled}
	add := func(o *model.Object, p string, deleted bool) Entry {
		st := last[o.Serial]
		e := Entry{
			Path:    p,
			Type:    TypeFile,
			Mode:    o.Mode,
			Size:    st.size,
			Inode:   strconv.Itoa(o.Serial),
			Object:  o.Serial,
			Atime:   o.Times.Atime,
			Mtime:   o.Times.Mtime,
			MD5:     st.md5,
			Deleted: deleted,
			alias:   p != o.Path,
		}
		if c.Change {
			e.Ctime = o.Times.Ctime
		}
		if c.Birth {
			e.Btime = o.Times.Btime
		}
		if len(o.Names) > 1 {
			e.Links = len(o.Names)
		}
		setKindFields(&e, o)
		tl.Entries = append(tl.Entries, e)
		for _, s := range st.streams {
			se := e
			se.Type, se.Stream, se.Size, se.MD5 = TypeStream, s.Name, int64(s.Size), s.MD5
			tl.Entries = append(tl.Entries, se)
		}
		return e
	}
	// Each name of a hard-linked file is an entry, as each is a directory
	// entry a tool lists.
	for _, o := range tree.Settle() {
		for _, n := range o.Names {
			e := add(o, n.Path, false)
			if c.FileName {
				tl.Entries = append(tl.Entries, fileNameEntry(e, n.FN))
			}
		}
	}
	for _, o := range tree.Removed() {
		add(o, o.Path, true)
	}
	sortEntries(tl.Entries)
	return tl
}

// fileNameEntry is the entry for the $FILE_NAME of the name e is, with its
// times t: a record of the name, so it has no content to hash.
func fileNameEntry(e Entry, t model.Times) Entry {
	e.FileName, e.MD5 = true, ""
	e.Atime, e.Mtime, e.Ctime, e.Btime = t.Atime, t.Mtime, t.Ctime, t.Btime
	return e
}

// Finals lists, for a modelled timeline, where each object ended up (or was
// deleted from) and its controlled modification and creation times: what
// the answer key's final-state facts are drawn from. A hard-linked file is
// listed once, under its first name.
func (tl *Timeline) Finals() []ledger.Final {
	var out []ledger.Final
	for _, e := range tl.Entries {
		if e.Object == 0 || e.Type == TypeStream || e.alias || e.FileName {
			continue
		}
		out = append(out, ledger.Final{
			Object: e.Object, Kind: string(e.Type), Path: e.Path, Deleted: e.Deleted,
			Mtime: e.Mtime, Crtime: e.Btime,
		})
	}
	return out
}

// setKindFields settles the fields that follow from what an object is. A
// directory or link has no content to size or hash, a link carries its
// target, and an object the scenario gave no mode takes the default one a
// run would have created it with.
func setKindFields(e *Entry, o *model.Object) {
	switch o.Kind {
	case model.Dir:
		e.Type, e.Size, e.MD5 = TypeDir, 0, ""
		if e.Mode == 0 {
			e.Mode = sandbox.DirMode
		}
		e.Mode |= fs.ModeDir
	case model.Symlink, model.Junction:
		e.Type, e.Size, e.MD5, e.LinkTarget = TypeLink, 0, "", o.Target
		if e.Mode == 0 {
			e.Mode = 0o777
		}
	default:
		if e.Mode == 0 {
			e.Mode = sandbox.FileMode
		}
	}
}
