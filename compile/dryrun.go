package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"time"

	"github.com/aoiflux/fsagen/model"
)

// dryRunOp is one line of --dry-run output. Field order and omission rules
// are fixed so the listing is byte-stable for a given input and seed.
type dryRunOp struct {
	N             int        `json:"n"`
	Src           string     `json:"src"`
	At            string     `json:"at,omitempty"`
	Action        string     `json:"action"`
	Path          string     `json:"path,omitempty"`
	NewPath       string     `json:"new_path,omitempty"`
	Dir           bool       `json:"dir,omitempty"`
	ID            string     `json:"id,omitempty"`
	ContentBytes  *int       `json:"content_bytes,omitempty"`
	ContentSHA256 string     `json:"content_sha256,omitempty"`
	RandomBytes   int        `json:"random_bytes,omitempty"`
	Format        string     `json:"format,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	Times         *TimesJSON `json:"times,omitempty"`
	Members       []string   `json:"members,omitempty"`
	ContentKind   string     `json:"content_kind,omitempty"`
	Stream        string     `json:"stream,omitempty"`
	ZoneID        *int       `json:"zone_id,omitempty"`
	HostURL       string     `json:"host_url,omitempty"`
	ReferrerURL   string     `json:"referrer_url,omitempty"`
	EmailSubject  string     `json:"email_subject,omitempty"`
	NoOp          string     `json:"noop,omitempty"`
	Skip          string     `json:"skip,omitempty"`
}

// TimesJSON is a set of intended times as RFC 3339 strings with nanoseconds;
// a time the scenario does not control is left out.
type TimesJSON struct {
	Atime  string `json:"atime,omitempty"`
	Mtime  string `json:"mtime,omitempty"`
	Ctime  string `json:"ctime,omitempty"`
	Crtime string `json:"crtime,omitempty"`
}

// TimesOf formats t, or returns nil when no time is controlled.
func TimesOf(t model.Times) *TimesJSON {
	f := func(v time.Time) string {
		if v.IsZero() {
			return ""
		}
		return v.UTC().Format(time.RFC3339Nano)
	}
	j := TimesJSON{Atime: f(t.Atime), Mtime: f(t.Mtime), Ctime: f(t.Ctime), Crtime: f(t.Btime)}
	if j == (TimesJSON{}) {
		return nil
	}
	return &j
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
			ContentKind: op.ContentKind,
			Mode:        op.Mode,
			Times:       TimesOf(op.Times),
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
		case op.Random > 0:
			line.RandomBytes = op.Random
		}
		if op.Action == "motw" {
			z := op.ZoneID
			line.ZoneID = &z
		}
		if op.Email != nil {
			line.EmailSubject = op.Email.Subject
		}
		for _, m := range op.Members {
			line.Members = append(line.Members, m.Name+"="+m.Path)
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}
