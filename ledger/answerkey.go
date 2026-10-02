package ledger

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/aoiflux/fsagen/spec"
)

// AnswerKeyFileName is the answer key's name in the sidecar directory.
const AnswerKeyFileName = "answer-key.jsonl"

// Events in the answer key.
const (
	// Created: an object first appears (create, append to a missing file,
	// copy, the empty file a rotate leaves, email, ansible-vault).
	Created = "created"
	// Modified: an existing file's content changed.
	Modified = "modified"
	// Renamed: an object moved (rename, and the file a rotate moves aside).
	Renamed = "renamed"
	// Deleted: an object was removed.
	Deleted = "deleted"
	// StreamWritten: a named stream was written (ads, motw, and the streams
	// a copy carries).
	StreamWritten = "stream"
	// Stomped: a mace operation set times explicitly.
	Stomped = "stomped"
	// MtimeBeforeCrtime: an object ends (or was deleted) with a
	// modification time earlier than its creation time. A copy has one
	// without being stomped, as copies do in the wild.
	MtimeBeforeCrtime = "mtime_before_crtime"
)

// Fact is one line of the answer key: something a forensic tool examining
// the output should be able to find.
type Fact struct {
	Event  string `json:"event"`
	N      int    `json:"n,omitempty"` // the ledger entry it comes from
	At     string `json:"at,omitempty"`
	Object int    `json:"object"`
	Kind   string `json:"kind,omitempty"`
	Path   string `json:"path"`
	// From is where a renamed object was.
	From   string `json:"from,omitempty"`
	Stream string `json:"stream,omitempty"`
	Size   *int64 `json:"size,omitempty"`
	// SHA256Before is a modified file's previous content digest.
	SHA256Before string `json:"sha256_before,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	// Times are the object's intended times after a stomp.
	Times *Times `json:"times,omitempty"`
	// Fields are the times a stomp set.
	Fields []string `json:"fields,omitempty"`
	// Mtime and Crtime are the times of an mtime_before_crtime fact.
	Mtime  string `json:"mtime,omitempty"`
	Crtime string `json:"crtime,omitempty"`
	// Deleted marks an mtime_before_crtime fact about an object the
	// scenario deleted.
	Deleted bool `json:"deleted,omitempty"`
}

// Final is an object's last intended state, for the facts that depend on
// where a scenario leaves things rather than on one operation: where it
// ended up (or was deleted from) and the times the platform controls (zero
// when it does not).
type Final struct {
	Object        int
	Kind, Path    string
	Deleted       bool
	Mtime, Crtime time.Time
}

// AnswerKey derives the answer key from a run's ledger, in ledger order,
// followed by the facts about final states, by object number. Operations
// that were skipped or had nothing to do contribute nothing. Directories a
// run makes as missing parents have no ledger entry of their own, so they
// are not listed as created.
func AnswerKey(entries []Entry, finals []Final) []Fact {
	var facts []Fact
	// seen marks an object an earlier operation already created, so a later
	// write to it is a modification rather than a second creation.
	seen := map[int]bool{}
	for _, e := range entries {
		if e.Outcome != Done || e.Object == 0 {
			continue
		}
		facts = append(facts, actionFacts(e, seen)...)
		seen[e.Object] = true
	}
	return append(facts, impossibleTimeFacts(finals)...)
}

// actionFacts is what one finished operation left for a tool to find: what the
// action itself did, and what became of the content it touched.
func actionFacts(e Entry, seen map[int]bool) []Fact {
	base := Fact{N: e.N, At: e.At, Object: e.Object, Kind: e.Kind, Path: e.Path}
	if e.Action == spec.ActionCopy {
		// A copy is answerable for the file it wrote, not the one it read.
		base.Path = e.NewPath
	}
	return append(effectFact(e, base), contentFacts(e, base, seen)...)
}

// effectFact is the mark the action itself leaves: an object gone, a path
// changed, times stomped, a stream written. Actions that only write content
// leave none, and are answered for by contentFacts.
func effectFact(e Entry, base Fact) []Fact {
	f := base
	switch e.Action {
	case spec.ActionDelete:
		f.Event, f.SHA256 = Deleted, e.SHA256Before
	case spec.ActionRename:
		f.Event, f.Path, f.From = Renamed, e.NewPath, e.Path
	case spec.ActionRotate:
		f.Event, f.Object, f.Path, f.From, f.Kind = Renamed, e.Moved, e.NewPath, e.Path, "file"
	case spec.ActionMACE:
		f.Event, f.Times, f.Fields = Stomped, e.Times, slices.Clone(e.Explicit)
	case spec.ActionADS, spec.ActionMOTW:
		return writtenStreamFacts(e, base)
	default:
		return nil
	}
	return []Fact{f}
}

// writtenStreamFacts is the one stream an ads or motw wrote. The entry lists
// every stream the file carries, so the others were already there.
func writtenStreamFacts(e Entry, base Fact) []Fact {
	var out []Fact
	for _, s := range e.Streams {
		if s.Name == e.Stream {
			out = append(out, streamFact(base, s))
		}
	}
	return out
}

// contentWriters are the actions that put bytes in a file.
var contentWriters = []spec.ActionName{
	spec.ActionCreate, spec.ActionAppend, spec.ActionUpdate, spec.ActionTruncate,
	spec.ActionCopy, spec.ActionRotate, spec.ActionEmail, spec.ActionVault,
}

// contentFacts says what became of the file's content: created when this is the
// first operation to make it, modified when the bytes changed. update and
// truncate never make a file, so one they are the first to touch was there
// before the run (--into-existing).
func contentFacts(e Entry, base Fact, seen map[int]bool) []Fact {
	if !slices.Contains(contentWriters, e.Action) {
		return nil
	}
	var out []Fact
	f := base
	switch {
	case !seen[e.Object] && e.Action != spec.ActionUpdate && e.Action != spec.ActionTruncate:
		f.Event, f.Size, f.SHA256 = Created, e.Size, e.SHA256After
		out = append(out, f)
	case e.SHA256After != e.SHA256Before:
		f.Event, f.Size, f.SHA256Before, f.SHA256 = Modified, e.Size, e.SHA256Before, e.SHA256After
		out = append(out, f)
	}
	if e.Action == spec.ActionCopy {
		// Streams travel with a copy, so the copy is answerable for each one.
		out = append(out, allStreamFacts(base, e.Streams)...)
	}
	return out
}

// allStreamFacts is one fact per stream the file carries.
func allStreamFacts(base Fact, streams []Stream) []Fact {
	out := make([]Fact, 0, len(streams))
	for _, s := range streams {
		out = append(out, streamFact(base, s))
	}
	return out
}

// impossibleTimeFacts names every object left with a modification time before
// its creation time, which cannot happen without the times being set.
func impossibleTimeFacts(finals []Final) []Fact {
	finals = slices.Clone(finals)
	sort.SliceStable(finals, func(i, j int) bool { return finals[i].Object < finals[j].Object })
	var out []Fact
	for _, o := range finals {
		if o.Mtime.IsZero() || o.Crtime.IsZero() || !o.Mtime.Before(o.Crtime) {
			continue
		}
		out = append(out, Fact{
			Event: MtimeBeforeCrtime, Object: o.Object, Kind: o.Kind, Path: o.Path, Deleted: o.Deleted,
			Mtime: o.Mtime.UTC().Format(time.RFC3339Nano), Crtime: o.Crtime.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func streamFact(base Fact, s Stream) Fact {
	size := int64(s.Size)
	f := base
	f.Event, f.Kind, f.Stream, f.Size, f.SHA256 = StreamWritten, "", s.Name, &size, s.SHA256
	return f
}

// EncodeFacts writes facts as JSON lines.
func EncodeFacts(w io.Writer, facts []Fact) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, f := range facts {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// FactBytes returns the encoded answer key.
func FactBytes(facts []Fact) []byte {
	var b bytes.Buffer
	_ = EncodeFacts(&b, facts)
	return b.Bytes()
}
