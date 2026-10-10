package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/spec"
)

// AnswerKeyFileName is the answer key's name in the sidecar directory.
const AnswerKeyFileName = "answer-key.jsonl"

// Events in the answer key.
const (
	// Created: an object first appears (create, append to a missing file,
	// copy, the empty file a rotate leaves, email, ansible-vault, and a
	// symlink or junction, with its target).
	Created = "created"
	// Modified: an existing file's content changed.
	Modified = "modified"
	// Renamed: an object moved (rename, and the file a rotate moves aside).
	Renamed = "renamed"
	// Deleted: an object was removed.
	Deleted = "deleted"
	// Linked: a file was given another name (a hard link).
	Linked = "linked"
	// Unlinked: a name was removed from a file that keeps another one.
	Unlinked = "unlinked"
	// StreamWritten: a named stream was written (ads, motw, and the streams
	// a copy carries).
	StreamWritten = "stream"
	// Stomped: a mace or timestomp operation set times explicitly.
	Stomped = "stomped"
	// SlackWritten: bytes were left past the end of a file, in the rest of
	// its last cluster.
	SlackWritten = "slack"
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
	// From is where a renamed object was, or the name a hard link was made
	// from.
	From string `json:"from,omitempty"`
	// Target is what a created symlink or junction points at.
	Target string `json:"target,omitempty"`
	// Links is the number of names a linked or unlinked file has afterwards.
	Links  int    `json:"links,omitempty"`
	Stream string `json:"stream,omitempty"`
	Size   *int64 `json:"size,omitempty"`
	// SHA256Before is a modified file's previous content digest.
	SHA256Before string `json:"sha256_before,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	// MD5 is a created or modified file's content MD5, which timelines and
	// most tools report beside the SHA-256.
	MD5 string `json:"md5,omitempty"`
	// Times are the object's intended times after a stomp: for a
	// timestomp, its $STANDARD_INFORMATION times.
	Times *Times `json:"times,omitempty"`
	// Fields are the times a stomp set.
	Fields []string `json:"fields,omitempty"`
	// FnTimes are, for a timestomp, the object's intended $FILE_NAME times,
	// and FnControlled says whether they are on disk. They never are on a
	// live volume, where Windows sets them itself: they are then the times
	// the scenario means, for a reader to compare with what it finds.
	FnTimes      *Times `json:"fn_times,omitempty"`
	FnControlled *bool  `json:"fn_controlled,omitempty"`
	// Delta is, for a timestomp, how far each $STANDARD_INFORMATION time is
	// from its $FILE_NAME time.
	Delta *Delta `json:"delta,omitempty"`
	// TimestompDetected is, for a timestomp, whether its
	// $STANDARD_INFORMATION creation time is earlier than its $FILE_NAME
	// one, the comparison MFTECmd's SI<FN column makes.
	TimestompDetected *bool `json:"timestomp_detected,omitempty"`
	// Mtime and Crtime are the times of an mtime_before_crtime fact.
	Mtime  string `json:"mtime,omitempty"`
	Crtime string `json:"crtime,omitempty"`
	// Deleted marks an mtime_before_crtime fact about an object the
	// scenario deleted.
	Deleted bool `json:"deleted,omitempty"`
	// Mitre are the ATT&CK techniques of the operation the fact comes from.
	Mitre []string `json:"mitre,omitempty"`
	// Slack is, for a slack fact, where the bytes are and what they hash to.
	Slack *Slack `json:"slack,omitempty"`
}

// Delta is, per time, the $STANDARD_INFORMATION time minus the $FILE_NAME
// time in seconds, exactly: negative where the first is earlier. A time
// either set leaves unknown is left out.
type Delta struct {
	Atime  json.Number `json:"atime,omitempty"`
	Mtime  json.Number `json:"mtime,omitempty"`
	Ctime  json.Number `json:"ctime,omitempty"`
	Crtime json.Number `json:"crtime,omitempty"`
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
	base := Fact{N: e.N, At: e.At, Object: e.Object, Kind: e.Kind, Path: e.Path, Mitre: e.Mitre}
	if e.Action == spec.ActionCopy {
		// A copy is answerable for the file it wrote, not the one it read.
		base.Path = e.NewPath
	}
	facts := append(effectFact(e, base), contentFacts(e, base, seen)...)
	if e.Slack != nil {
		f := base
		f.Event, f.Slack = SlackWritten, e.Slack
		facts = append(facts, f)
	}
	return facts
}

// effectFact is the mark the action itself leaves: an object gone, a path
// changed, times stomped, a stream written. Actions that only write content
// leave none, and are answered for by contentFacts.
func effectFact(e Entry, base Fact) []Fact {
	f := base
	switch e.Action {
	case spec.ActionDelete:
		f.Event, f.SHA256 = Deleted, e.SHA256Before
		if e.Links > 0 {
			f.Event, f.Links = Unlinked, e.Links
		}
	case spec.ActionHardlink:
		f.Event, f.Path, f.From, f.Links = Linked, e.NewPath, e.Path, e.Links
	case spec.ActionSymlink, spec.ActionJunction:
		f.Event, f.Target = Created, e.Target
	case spec.ActionRename:
		f.Event, f.Path, f.From = Renamed, e.NewPath, e.Path
	case spec.ActionRotate:
		f.Event, f.Object, f.Path, f.From, f.Kind = Renamed, e.Moved, e.NewPath, e.Path, "file"
	case spec.ActionMACE:
		f.Event, f.Times, f.Fields = Stomped, e.Times, slices.Clone(e.Explicit)
	case spec.ActionTimestomp:
		f.Event, f.Times, f.Fields = Stomped, e.Times, slices.Clone(e.Explicit)
		fileNameFacts(&f, e)
	case spec.ActionADS, spec.ActionMOTW:
		return writtenStreamFacts(e, base)
	default:
		return nil
	}
	return []Fact{f}
}

// fileNameFacts adds what a timestomp's $FILE_NAME times show: the times, whether
// they are on disk, how far the two sets are apart, and whether the
// creation times give the stomp away.
func fileNameFacts(f *Fact, e Entry) {
	controlled := !slices.ContainsFunc(e.Uncontrolled, func(t string) bool { return strings.HasPrefix(t, "fn_") })
	f.FnTimes, f.FnControlled = e.FnTimes, &controlled
	if e.Times == nil || e.FnTimes == nil {
		return
	}
	si, fn := *e.Times, *e.FnTimes
	d := Delta{Atime: secondsBetween(si.Atime, fn.Atime), Mtime: secondsBetween(si.Mtime, fn.Mtime), Ctime: secondsBetween(si.Ctime, fn.Ctime), Crtime: secondsBetween(si.Crtime, fn.Crtime)}
	if d != (Delta{}) {
		f.Delta = &d
	}
	if d.Crtime != "" {
		detected := strings.HasPrefix(string(d.Crtime), "-")
		f.TimestompDetected = &detected
	}
}

// secondsBetween is a minus b in seconds, as an exact decimal, or "" when
// either is unknown. A float would lose the 100-nanosecond ticks of a stomp
// decades away.
func secondsBetween(a, b string) json.Number {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if a == "" || b == "" || errA != nil || errB != nil {
		return ""
	}
	sec, nsec := ta.Unix()-tb.Unix(), int64(ta.Nanosecond()-tb.Nanosecond())
	// Both parts take the sign of the whole, so it can be written once.
	switch {
	case sec > 0 && nsec < 0:
		sec, nsec = sec-1, nsec+1e9
	case sec < 0 && nsec > 0:
		sec, nsec = sec+1, nsec-1e9
	}
	sign := ""
	if sec < 0 || nsec < 0 {
		sign, sec, nsec = "-", -sec, -nsec
	}
	out := sign + strconv.FormatInt(sec, 10)
	if nsec != 0 {
		out += strings.TrimRight(fmt.Sprintf(".%09d", nsec), "0")
	}
	return json.Number(out)
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
		f.Event, f.Size, f.SHA256, f.MD5 = Created, e.Size, e.SHA256After, e.MD5After
		out = append(out, f)
	case e.SHA256After != e.SHA256Before:
		f.Event, f.Size, f.SHA256Before, f.SHA256, f.MD5 = Modified, e.Size, e.SHA256Before, e.SHA256After, e.MD5After
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
