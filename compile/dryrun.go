package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"time"
)

// dryRunOp is one line of --dry-run output. Field order and omission rules
// are fixed so the listing is byte-stable for a given input and seed.
type dryRunOp struct {
	N             int    `json:"n"`
	Src           string `json:"src"`
	At            string `json:"at,omitempty"`
	Action        string `json:"action"`
	Path          string `json:"path,omitempty"`
	NewPath       string `json:"new_path,omitempty"`
	Dir           bool   `json:"dir,omitempty"`
	ID            string `json:"id,omitempty"`
	ContentBytes  *int   `json:"content_bytes,omitempty"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
	RandomBytes   int    `json:"random_bytes,omitempty"`
	Format        string `json:"format,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Atime         string `json:"atime,omitempty"`
	Mtime         string `json:"mtime,omitempty"`
	Stream        string `json:"stream,omitempty"`
	ZoneID        *int   `json:"zone_id,omitempty"`
	HostURL       string `json:"host_url,omitempty"`
	ReferrerURL   string `json:"referrer_url,omitempty"`
	EmailSubject  string `json:"email_subject,omitempty"`
	NoOp          string `json:"noop,omitempty"`
	Skip          string `json:"skip,omitempty"`
}

// WriteDryRun prints the compiled operations as JSON lines: what would be
// done, where, and when, without touching the disk.
func WriteDryRun(w io.Writer, p *Program) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i, op := range p.Ops {
		src := op.Src
		src.File = filepath.Base(src.File)
		line := dryRunOp{
			N:           i + 1,
			Src:         src.String(),
			Action:      op.Action,
			Path:        op.Path,
			NewPath:     op.NewPath,
			Dir:         op.Dir,
			ID:          op.ID,
			Format:      op.Format,
			Mode:        op.Mode,
			Atime:       op.Atime,
			Mtime:       op.Mtime,
			Stream:      op.Stream,
			HostURL:     op.HostURL,
			ReferrerURL: op.ReferrerURL,
			NoOp:        op.NoOp,
			Skip:        op.Skip,
		}
		if !op.At.IsZero() {
			line.At = op.At.UTC().Format(time.RFC3339Nano)
		}
		switch {
		case op.keys.has("content") || op.keys.has("content_file") || op.keys.has("template"):
			n := len(op.Content)
			sum := sha256.Sum256([]byte(op.Content))
			line.ContentBytes = &n
			line.ContentSHA256 = hex.EncodeToString(sum[:])
		case randomContent(&op) || (op.Action == "ads" && op.Content == ""):
			line.RandomBytes = randomLength(&op)
		}
		if op.Action == "motw" {
			z := op.ZoneID
			line.ZoneID = &z
		}
		if op.Email != nil {
			line.EmailSubject = op.Email.Subject
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}

// randomLength mirrors the executor's defaults for generated content.
func randomLength(op *Op) int {
	if op.ContentLen > 0 {
		return op.ContentLen
	}
	switch op.Action {
	case "append":
		return 256
	case "ads":
		return 128
	}
	return 1024
}
