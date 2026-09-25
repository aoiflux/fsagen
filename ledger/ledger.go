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
	N       int    `json:"n"`
	Src     string `json:"src"`
	At      string `json:"at,omitempty"`
	Action  string `json:"action"`
	Path    string `json:"path,omitempty"`
	NewPath string `json:"new_path,omitempty"`
	ID      string `json:"id,omitempty"`
	// Object is the model's serial number for the object the operation left
	// behind (for a delete, the one it removed); it survives renames.
	Object       int      `json:"object,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	SHA256Before string   `json:"sha256_before,omitempty"`
	SHA256After  string   `json:"sha256_after,omitempty"`
	Size         *int64   `json:"size,omitempty"`
	Streams      []Stream `json:"streams,omitempty"`
	// Times are the object's intended times after the operation (for a
	// delete, just before it).
	Times *Times `json:"times,omitempty"`
	// Uncontrolled lists the times of the object the file system keeps as
	// it likes: the scenario does not say, or this platform cannot set them.
	Uncontrolled []string `json:"uncontrolled,omitempty"`
	Outcome      string   `json:"outcome"`
	Reason       string   `json:"reason,omitempty"`
}

// Stream is one named data stream on the object.
type Stream struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
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
