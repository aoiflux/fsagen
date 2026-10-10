// Package ledger records what each operation of a run did: which object it
// acted on, the content digest before and after, the streams it left, the
// times it intended, and what the platform could not do. It is written as
// ledger.jsonl in the sidecar directory, one JSON object per line, and is
// deterministic: the same generator version, seed, inputs and capability set
// give the same bytes.
package ledger

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/aoiflux/fsagen/spec"
)

// FileName is the ledger's name in the sidecar directory.
const FileName = "ledger.jsonl"

// Outcomes.
const (
	Done    = "done"
	NoOp    = "noop"
	Skipped = "skipped"
)

// Entry is one operation.
type Entry struct {
	N       int             `json:"n"`
	Src     string          `json:"src"`
	At      string          `json:"at,omitempty"`
	Action  spec.ActionName `json:"action"`
	Path    string          `json:"path,omitempty"`
	NewPath string          `json:"new_path,omitempty"`
	ID      string          `json:"id,omitempty"`
	// Mitre are the ATT&CK techniques the operation exhibits, its step's
	// included; see compile.Op.Techniques.
	Mitre []string `json:"mitre,omitempty"`
	// Object is the model's serial number for the object the operation left
	// behind (for a delete, the one it removed); it survives renames.
	Object int `json:"object,omitempty"`
	// Moved is, for a rotate, the object renamed to new_path; object is then
	// the empty file that takes its place at path.
	Moved int `json:"moved,omitempty"`
	// Kind is "file", "dir", "symlink" or "junction".
	Kind string `json:"kind,omitempty"`
	// Target is what a symlink or junction points at, as written.
	Target string `json:"target,omitempty"`
	// Links is the number of names the object has afterwards, written when
	// it has more than one, and for a delete when it keeps any: the delete
	// then unlinked one name rather than deleting the file.
	Links int `json:"links,omitempty"`
	// Stream is the stream an ads or motw operation wrote.
	Stream       string `json:"stream,omitempty"`
	SHA256Before string `json:"sha256_before,omitempty"`
	SHA256After  string `json:"sha256_after,omitempty"`
	// MD5After is the MD5 of the same content, for timelines, which carry
	// MD5 as The Sleuth Kit does.
	MD5After string   `json:"md5_after,omitempty"`
	Size     *int64   `json:"size,omitempty"`
	Streams  []Stream `json:"streams,omitempty"`
	// Times are the object's intended times after the operation (for a
	// delete, just before it).
	Times *Times `json:"times,omitempty"`
	// FnTimes are, for a timestomp, the object's intended $FILE_NAME times
	// after it.
	FnTimes *Times `json:"fn_times,omitempty"`
	// Explicit lists the times the operation stated itself (atime, mtime,
	// ctime, crtime, and a timestomp's fn_ times) and that were applied; the
	// rest were derived from the operation's time. A delete's explicit times
	// are the times of the directory it deleted from.
	Explicit []string `json:"explicit,omitempty"`
	// Uncontrolled lists the times of the object the file system keeps as
	// it likes: the scenario does not say, or this platform cannot set them.
	// A timestomp's lists the $FILE_NAME times too (fn_atime and so on) when
	// they are not on disk.
	Uncontrolled []string `json:"uncontrolled,omitempty"`
	Outcome      string   `json:"outcome"`
	Reason       string   `json:"reason,omitempty"`
	// Slack is what the operation wrote past the end of the file, in the
	// rest of its last cluster.
	Slack *Slack `json:"slack,omitempty"`
}

// Slack is the bytes an operation left in a file's slack. Offset is where
// the file's content ends, so where the slack starts within it; Length runs
// to the end of the cluster. Verified says whether fsagen wrote the cluster
// itself (a disk image) rather than leaving the bytes for a live file system
// to keep, which only a read of the raw volume can confirm.
type Slack struct {
	Kind        string `json:"kind"`
	ClusterSize int    `json:"cluster_size"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
	SHA256      string `json:"sha256"`
	Verified    bool   `json:"verified"`
}

// Stream is one named data stream on the object.
type Stream struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5"`
}

// Times are RFC 3339 times with nanoseconds.
type Times struct {
	Atime  string `json:"atime,omitempty"`
	Mtime  string `json:"mtime,omitempty"`
	Ctime  string `json:"ctime,omitempty"`
	Crtime string `json:"crtime,omitempty"`
}

// Encode writes entries as JSON lines.
func Encode(w io.Writer, entries []Entry) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// Bytes returns the encoded ledger.
func Bytes(entries []Entry) []byte {
	var b bytes.Buffer
	_ = Encode(&b, entries)
	return b.Bytes()
}
