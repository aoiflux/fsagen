package ledger

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"time"
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
	seen := map[int]bool{}
	for _, e := range entries {
		if e.Outcome != Done || e.Object == 0 {
			continue
		}
		base := Fact{N: e.N, At: e.At, Object: e.Object, Kind: e.Kind, Path: e.Path}
		if e.Action == "copy" {
			base.Path = e.NewPath
		}
		switch e.Action {
		case "delete":
			f := base
			f.Event, f.SHA256 = Deleted, e.SHA256Before
			facts = append(facts, f)
		case "rename":
			f := base
			f.Event, f.Path, f.From = Renamed, e.NewPath, e.Path
			facts = append(facts, f)
		case "rotate":
			f := base
			f.Event, f.Object, f.Path, f.From, f.Kind = Renamed, e.Moved, e.NewPath, e.Path, "file"
			facts = append(facts, f)
		case "mace":
			f := base
			f.Event, f.Times, f.Fields = Stomped, e.Times, slices.Clone(e.Explicit)
			facts = append(facts, f)
		case "ads", "motw":
			for _, s := range e.Streams {
				if s.Name == e.Stream {
					facts = append(facts, streamFact(base, s))
				}
			}
		}
		switch e.Action {
		case "create", "append", "update", "truncate", "copy", "rotate", "email", "ansible-vault":
			// update and truncate never make a file; one they are the first
			// to touch was there before the run (--into-existing).
			if !seen[e.Object] && e.Action != "update" && e.Action != "truncate" {
				f := base
				f.Event, f.Size, f.SHA256 = Created, e.Size, e.SHA256After
				facts = append(facts, f)
			} else if e.SHA256After != e.SHA256Before {
				f := base
				f.Event, f.Size, f.SHA256Before, f.SHA256 = Modified, e.Size, e.SHA256Before, e.SHA256After
				facts = append(facts, f)
			}
			if e.Action == "copy" {
				for _, s := range e.Streams {
					facts = append(facts, streamFact(base, s))
				}
			}
		}
		seen[e.Object] = true
	}

	finals = slices.Clone(finals)
	sort.SliceStable(finals, func(i, j int) bool { return finals[i].Object < finals[j].Object })
	for _, o := range finals {
		if o.Mtime.IsZero() || o.Crtime.IsZero() || !o.Mtime.Before(o.Crtime) {
			continue
		}
		facts = append(facts, Fact{
			Event: MtimeBeforeCrtime, Object: o.Object, Kind: o.Kind, Path: o.Path, Deleted: o.Deleted,
			Mtime: o.Mtime.UTC().Format(time.RFC3339Nano), Crtime: o.Crtime.UTC().Format(time.RFC3339Nano),
		})
	}
	return facts
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
