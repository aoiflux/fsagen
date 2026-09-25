// Package manifest executes compiled operations. Every write goes through a
// sandbox.FS confined to the output root; compile has already proved each
// operation's preconditions against a model of the tree, so a failure here is
// an I/O problem, never an input mistake.
//
// Times are stamped from the model, never from the operation's fields
// directly: each operation's objects right after it runs (and a deleted
// object right before), then every object once more in a settle pass after
// the last operation, files first and directories deepest first. A verify
// pass then reads every time back and fails the run on any difference.
package manifest

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/email"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
	"github.com/aoiflux/fsagen/timeline"
	"github.com/aoiflux/fsagen/util"
)

// ExecContext carries the state every operation needs beyond its own fields.
type ExecContext struct {
	// FS is the confined output root.
	FS *sandbox.FS
	// Sources reads email bodies and attachments from the YAML's directory.
	Sources *sandbox.Sources
	// Caps is the capability set the program was checked against. Times it
	// says cannot be set are left to the file system, even where the volume
	// could set them, so a run with an injected capability set behaves as
	// it would on that platform.
	Caps compile.Caps
}

// ExecuteManifest compiles a manifest and applies it under root with default
// options. It is the library entry point; the CLI adds root checks, the
// capability pre-flight and the run manifest around the same steps.
func ExecuteManifest(root, manifestPath string, opts compile.Options) error {
	_, err := ExecuteFile(compile.ModeManifest, root, manifestPath, opts)
	return err
}

// Result is what a run knows beyond the files it wrote: its ledger, the
// model of the tree the scenario intends, and the capability set it ran
// with, from which the modelled timeline and the answer key follow.
type Result struct {
	Ledger []ledger.Entry
	Model  *model.Tree
	Caps   compile.Caps
}

// Timeline is the modelled timeline of the run.
func (r Result) Timeline() *timeline.Timeline { return ModelledTimeline(r.Model, r.Ledger, r.Caps) }

// AnswerKey is the run's answer key.
func (r Result) AnswerKey() []ledger.Fact { return AnswerKey(r.Model, r.Ledger, r.Caps) }

// ModelledTimeline is the timeline the scenario intends, with the times
// caps cannot set left unknown.
func ModelledTimeline(tree *model.Tree, entries []ledger.Entry, caps compile.Caps) *timeline.Timeline {
	return timeline.Modelled(tree, entries, timeline.Controlled{Birth: caps.BirthTime, Change: caps.ChangeTime})
}

// AnswerKey derives the answer key from the ledger and the final state of
// the model.
func AnswerKey(tree *model.Tree, entries []ledger.Entry, caps compile.Caps) []ledger.Fact {
	return ledger.AnswerKey(entries, ModelledTimeline(tree, entries, caps).Finals())
}

// ExecuteFile compiles a manifest or playbook, applies it under root,
// settles and verifies the times, and returns the ledger and model. On a
// failure after execution began, the ledger holds what was done.
func ExecuteFile(mode compile.Mode, root, file string, opts compile.Options) (Result, error) {
	prog, err := compile.Load(mode, file, opts)
	if err != nil {
		return Result{}, err
	}
	defer prog.Close()

	fsys, err := sandbox.Open(root)
	if err != nil {
		return Result{}, err
	}
	defer fsys.Close()

	caps := Caps(fsys)
	if err := compile.Preflight(prog, caps, opts.SkipUnsupported); err != nil {
		return Result{}, err
	}
	ctx := ExecContext{FS: fsys, Sources: prog.Sources, Caps: caps}
	entries, err := Execute(ctx, prog.Ops)
	res := Result{Ledger: entries, Model: prog.Model, Caps: caps}
	if err != nil {
		return res, err
	}
	return res, SettleAndVerify(ctx, prog.Model)
}

// Caps is the capability set of an output root.
func Caps(fsys *sandbox.FS) compile.Caps {
	tc := fsys.TimeCaps()
	return compile.Caps{NamedStreams: fsys.SupportsStreams(), BirthTime: tc.Birth, ChangeTime: tc.Change}
}

// Execute applies the operations in order, leaving out those marked NoOp
// and those marked Skip (unsupported here), and returns the ledger. Every
// operation draws from its own random stream, so leaving one out changes no
// other file's bytes.
func Execute(ctx ExecContext, ops []compile.Op) ([]ledger.Entry, error) {
	digests := map[int]string{} // object serial -> content digest
	entries := make([]ledger.Entry, 0, len(ops))
	for i, op := range ops {
		e := newEntry(i, op, ctx.Caps)
		switch {
		case op.NoOp != "":
			e.Outcome, e.Reason = ledger.NoOp, op.NoOp
		case op.Skip != "":
			e.Outcome, e.Reason = ledger.Skipped, op.Skip
		default:
			fail := func(err error) error { return fmt.Errorf("%s: %s %s: %w", op.Src, op.Action, op.Path, err) }
			if err := stampAll(ctx, op.Pre); err != nil {
				return entries, fail(err)
			}
			if err := executeOp(ctx, op); err != nil {
				return entries, fail(err)
			}
			// Digests are read before stamping: a read may move the access
			// time, which the stamps then put back.
			if err := describe(ctx.FS, op, &e, digests); err != nil {
				return entries, fail(err)
			}
			if err := stampAll(ctx, op.Stamps); err != nil {
				return entries, fail(err)
			}
			e.Outcome = ledger.Done
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func stampAll(ctx ExecContext, stamps []compile.Stamp) error {
	for _, s := range stamps {
		if err := stamp(ctx, s.Path, s.Times); err != nil {
			return err
		}
	}
	return nil
}

// stamp sets the times caps allows.
func stamp(ctx ExecContext, p string, t model.Times) error {
	if !ctx.Caps.BirthTime {
		t.Btime = time.Time{}
	}
	if !ctx.Caps.ChangeTime {
		t.Ctime = time.Time{}
	}
	return ctx.FS.SetTimes(p, sandbox.Times(t))
}

func newEntry(i int, op compile.Op, caps compile.Caps) ledger.Entry {
	src := op.Src
	src.File = filepath.Base(src.File)
	e := ledger.Entry{
		N:       i + 1,
		Src:     src.String(),
		Action:  op.Action,
		Path:    op.Path,
		NewPath: op.NewPath,
		ID:      op.ID,
		Object:  op.Object,
		Moved:   op.Moved,
		Kind:    kindName(op.Kind),
	}
	switch op.Action {
	case "ads":
		e.Stream = op.Stream
	case "motw":
		e.Stream = "Zone.Identifier"
	}
	e.Explicit = explicit(op)
	if !op.At.IsZero() {
		e.At = op.At.UTC().Format(time.RFC3339Nano)
	}
	if t := compile.TimesOf(op.Times); t != nil {
		lt := ledger.Times(*t)
		e.Times = &lt
	}
	if op.Object != 0 {
		e.Uncontrolled = uncontrolled(op.Times, caps)
	}
	return e
}

func kindName(k model.Kind) string {
	switch k {
	case model.File:
		return "file"
	case model.Dir:
		return "dir"
	}
	return ""
}

// explicit lists the time fields op states, less those dropped because the
// platform cannot set them.
func explicit(op compile.Op) []string {
	var out []string
	for i, v := range []string{op.Atime, op.Mtime, op.Ctime, op.Crtime} {
		f := compile.TimeFields[i]
		if strings.TrimSpace(v) != "" && !slices.Contains(op.Dropped, f) {
			out = append(out, f)
		}
	}
	return out
}

// uncontrolled lists the times the file system keeps as it likes: those the
// scenario leaves open and those this platform cannot set.
func uncontrolled(t model.Times, caps compile.Caps) []string {
	var out []string
	if t.Atime.IsZero() {
		out = append(out, "atime")
	}
	if t.Mtime.IsZero() {
		out = append(out, "mtime")
	}
	if t.Ctime.IsZero() || !caps.ChangeTime {
		out = append(out, "ctime")
	}
	if t.Btime.IsZero() || !caps.BirthTime {
		out = append(out, "crtime")
	}
	return out
}

// target is the path of the object an operation leaves behind, or "" for a
// delete.
func target(op compile.Op) string {
	switch op.Action {
	case "rename", "copy":
		return op.NewPath
	case "delete":
		return ""
	}
	return op.Path
}

// describe records the object's digest, size and streams after the
// operation. Reads go through quiet handles, which leave access times alone
// where the platform allows.
func describe(fs *sandbox.FS, op compile.Op, e *ledger.Entry, digests map[int]string) error {
	e.SHA256Before = digests[op.Object]
	p := target(op)
	if p == "" {
		delete(digests, op.Object)
		return nil
	}
	if op.Kind == model.File {
		f, err := fs.OpenQuiet(p)
		if err != nil {
			return err
		}
		defer f.Close()
		sha, md, n, err := sums(f)
		if err != nil {
			return err
		}
		e.SHA256After, e.MD5After, e.Size = sha, md, &n
		digests[op.Object] = e.SHA256After
	}
	streams, err := fs.Streams(p)
	if err != nil {
		return err
	}
	for _, s := range streams {
		f, err := fs.OpenStreamQuiet(p, s.Name)
		if err != nil {
			return err
		}
		sha, md, n, err := sums(f)
		f.Close()
		if err != nil {
			return err
		}
		e.Streams = append(e.Streams, ledger.Stream{Name: s.Name, Size: int(n), SHA256: sha, MD5: md})
	}
	return nil
}

// sums reads r to the end and returns its SHA-256, MD5 and length.
func sums(r io.Reader) (sha, md string, n int64, err error) {
	hs, hm := sha256.New(), md5.New()
	if n, err = io.Copy(io.MultiWriter(hs, hm), r); err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(hs.Sum(nil)), hex.EncodeToString(hm.Sum(nil)), n, nil
}

// Settle stamps every object in the tree with its final intended times,
// files first and then directories deepest first, so that nothing done
// afterwards inside a directory moves its times again. Nothing may create,
// remove, rename or chmod anything under the root after this.
func Settle(ctx ExecContext, tree *model.Tree) error {
	for _, o := range tree.Settle() {
		if err := stamp(ctx, o.Path, o.Times); err != nil {
			return err
		}
	}
	return nil
}

// settleRetries are the pauses before settling again when only access times
// moved after a settle pass. With last-access updates on, anything that
// reads the new files (an antivirus scanning a fresh .bat, a search indexer)
// moves their access times; such readers usually finish within a second.
var settleRetries = []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}

// afterSettle lets a test play the part of another process reading the
// output between settling and verifying.
var afterSettle = func(round int) {}

// SettleAndVerify settles the tree and verifies it. When the only
// differences are access times, which another process can move by reading,
// it settles again after a pause, a few times, before giving up.
func SettleAndVerify(ctx ExecContext, tree *model.Tree) error {
	if err := Settle(ctx, tree); err != nil {
		return err
	}
	afterSettle(0)
	err := Verify(ctx, tree)
	for i, pause := range settleRetries {
		ve, ok := err.(*VerifyError)
		if !ok || !ve.accessOnly() {
			break
		}
		time.Sleep(pause)
		if err := Settle(ctx, tree); err != nil {
			return err
		}
		afterSettle(i + 1)
		err = Verify(ctx, tree)
	}
	if ve, ok := err.(*VerifyError); ok && ve.accessOnly() {
		ve.Hint = "only access times moved, again after settling " + fmt.Sprint(len(settleRetries)+1) + " times: another process (an antivirus scanner, a search indexer) keeps reading the output while this volume updates access times on read; exclude the output directory from scanning, or turn last-access updates off (fsutil behavior set disablelastaccess 1)"
	}
	return err
}

// Mismatch is one time that did not read back as intended.
type Mismatch struct {
	Path, Field string
	Want, Got   time.Time
}

// VerifyError lists every mismatch the verify pass found.
type VerifyError struct {
	Mismatches []Mismatch
	// Hint says what probably caused the mismatches.
	Hint string
}

func (e *VerifyError) accessOnly() bool {
	for _, m := range e.Mismatches {
		if m.Field != "atime" {
			return false
		}
	}
	return true
}

func (e *VerifyError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d time(s) on disk differ from the scenario after settling:", len(e.Mismatches))
	for i, m := range e.Mismatches {
		if i == 20 {
			fmt.Fprintf(&b, "\n  ... and %d more", len(e.Mismatches)-i)
			break
		}
		fmt.Fprintf(&b, "\n  %s %s: want %s, got %s", m.Path, m.Field, m.Want.Format(time.RFC3339Nano), m.Got.Format(time.RFC3339Nano))
	}
	if e.Hint != "" {
		b.WriteString("\n" + e.Hint)
	}
	return b.String()
}

// Verify reads back every time the scenario controls and this platform can
// set, and reports each one that differs by the volume's resolution or more.
// It reads metadata only, so it moves no access time.
func Verify(ctx ExecContext, tree *model.Tree) error {
	caps, g := ctx.Caps, ctx.FS.Granularity()
	var bad []Mismatch
	for _, o := range tree.Settle() {
		got, err := ctx.FS.Times(o.Path)
		if err != nil {
			return err
		}
		check := func(field string, want, have time.Time, res time.Duration, settable bool) {
			if !settable || want.IsZero() {
				return
			}
			d := want.Sub(have)
			if d < 0 {
				d = -d
			}
			if d >= res {
				bad = append(bad, Mismatch{o.Path, field, want, have})
			}
		}
		check("atime", o.Times.Atime, got.Atime, g.Atime, true)
		check("mtime", o.Times.Mtime, got.Mtime, g.Mtime, true)
		check("ctime", o.Times.Ctime, got.Ctime, g.Ctime, caps.ChangeTime)
		check("crtime", o.Times.Btime, got.Btime, g.Btime, caps.BirthTime)
	}
	if len(bad) > 0 {
		return &VerifyError{Mismatches: bad}
	}
	return nil
}

func executeOp(ctx ExecContext, c compile.Op) error {
	op := c.Operation
	fs := ctx.FS
	target := op.Path

	switch op.Action {
	case "create":
		if c.Dir {
			// Missing parents get the default mode; an explicit mode is for
			// the directory the operation names.
			if err := fs.MkdirAll(target, sandbox.DirMode); err != nil {
				return err
			}
			return applyMode(fs, op, target)
		}
		content, err := renderContent(op, contentOf(c))
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, content)

	case "update":
		content, err := renderContent(op, contentOf(c))
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, content)

	case "append":
		if err := fs.MkdirParent(target); err != nil {
			return err
		}
		f, err := fs.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
		if err != nil {
			return err
		}
		if _, err := f.Write(contentOf(c)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyMode(fs, op, target)

	case "delete":
		return fs.Remove(target)

	case "mace":
		return applyMode(fs, op, target)

	case "rename":
		if err := fs.MkdirParent(op.NewPath); err != nil {
			return err
		}
		return fs.Rename(target, op.NewPath)

	case "copy":
		if err := copyFile(fs, target, op.NewPath, fileModeFor(op)); err != nil {
			return err
		}
		// Streams travel with the copy, as they do with the Windows CopyFile.
		if err := fs.CopyStreams(target, op.NewPath); err != nil {
			return err
		}
		return applyMode(fs, op, op.NewPath)

	case "truncate":
		f, err := fs.OpenFile(target, os.O_WRONLY|os.O_TRUNC, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyMode(fs, op, target)

	case "rotate":
		if err := fs.MkdirParent(op.NewPath); err != nil {
			return err
		}
		if err := fs.Rename(target, op.NewPath); err != nil {
			return err
		}
		f, err := fs.OpenFile(target, os.O_CREATE|os.O_WRONLY, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyMode(fs, op, target)

	case "email":
		return writeEmail(ctx, c, target)

	case "ansible-vault":
		salt := op.Vault.Salt
		if strings.TrimSpace(salt) == "" {
			salt = hex.EncodeToString(c.Rand.Derive("vault.salt").Stream().Bytes(32))
		}
		encrypted, err := util.AnsibleVaultEncrypt([]byte(op.Content), op.Vault.Password, op.Vault.VaultID, salt)
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, encrypted)

	case "ads":
		// Writing a stream moves the base file's times on disk; the stamps
		// after the operation put back the ones the scenario intends.
		return fs.WriteStream(target, op.Stream, contentOf(c))

	case "motw":
		content := "[ZoneTransfer]\r\n" + fmt.Sprintf("ZoneId=%d\r\n", op.ZoneID)
		if op.ReferrerURL != "" {
			content += fmt.Sprintf("ReferrerUrl=%s\r\n", op.ReferrerURL)
		}
		if op.HostURL != "" {
			content += fmt.Sprintf("HostUrl=%s\r\n", op.HostURL)
		}
		return fs.WriteStream(target, "Zone.Identifier", []byte(content))
	}
	return fmt.Errorf("unknown action %q", op.Action)
}

// renderContent applies the typed generator selected by format. Without one,
// content is written through unchanged.
func renderContent(op spec.Operation, raw []byte) ([]byte, error) {
	switch op.Format {
	case "", "raw", "text":
		return raw, nil
	case "pdf":
		meta, err := pdfMeta(op)
		if err != nil {
			return nil, err
		}
		return libgen.RenderPDF(string(raw), meta)
	}
	return nil, fmt.Errorf("unknown format %q (want raw or pdf)", op.Format)
}

func pdfMeta(op spec.Operation) (libgen.PDFMeta, error) {
	if op.Pdf == nil {
		return libgen.PDFMeta{}, nil
	}
	created, err := optionalTime(op.Pdf.Created, "pdf.created")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	modified, err := optionalTime(op.Pdf.Modified, "pdf.modified")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	return libgen.PDFMeta{
		Title:    op.Pdf.Title,
		Author:   op.Pdf.Author,
		Subject:  op.Pdf.Subject,
		Keywords: op.Pdf.Keywords,
		Creator:  op.Pdf.Creator,
		Producer: op.Pdf.Producer,
		Created:  created,
		Modified: modified,
		PageSize: op.Pdf.PageSize,
	}, nil
}

// writeEmail builds the message and either writes it as a standalone .eml or
// appends it to an mbox. The format defaults from the path extension.
func writeEmail(ctx ExecContext, c compile.Op, target string) error {
	op := c.Operation
	boundaries := c.Rand.Derive("email.boundary").Stream()
	var readSource func(string) ([]byte, error)
	if ctx.Sources != nil {
		readSource = ctx.Sources.ReadFile
	}
	msg, date, err := email.Build(email.Options{
		Spec:       *op.Email,
		ReadSource: readSource,
		ReadOutput: ctx.FS.ReadFile,
		Boundary:   func() string { return "----=_fsagen_" + boundaries.Hex(24) },
	})
	if err != nil {
		return err
	}

	format := op.Format
	if format == "" {
		if strings.EqualFold(path.Ext(target), ".mbox") {
			format = "mbox"
		} else {
			format = "eml"
		}
	}

	switch format {
	case "eml":
		if err := ctx.FS.WriteFile(target, msg, fileModeFor(op)); err != nil {
			return err
		}
	case "mbox":
		// Append, so a whole thread accumulates across steps.
		if err := ctx.FS.MkdirParent(target); err != nil {
			return err
		}
		f, err := ctx.FS.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
		if err != nil {
			return err
		}
		if _, err := f.Write(email.ToMbox(msg, email.EnvelopeSender(*op.Email), date)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown email format %q (want eml or mbox)", op.Format)
	}
	return applyMode(ctx.FS, op, target)
}

// writeArtifact writes the file with the right permissions, creating its
// parent.
func writeArtifact(fs *sandbox.FS, op spec.Operation, target string, data []byte) error {
	if err := fs.WriteFile(target, data, fileModeFor(op)); err != nil {
		return err
	}
	return applyMode(fs, op, target)
}

func copyFile(fs *sandbox.FS, src, dst string, mode os.FileMode) error {
	in, err := fs.OpenFile(src, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := fs.MkdirParent(dst); err != nil {
		return err
	}
	out, err := fs.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func applyMode(fs *sandbox.FS, op spec.Operation, target string) error {
	mode, ok, err := util.ParseFileMode(op.Mode)
	if err != nil || !ok {
		return err
	}
	// WriteFile only applies the mode when it creates the file, so an existing
	// target needs an explicit chmod.
	return fs.Chmod(target, mode)
}

// fileModeFor reads a mode that compile has already validated.
func fileModeFor(op spec.Operation) os.FileMode {
	if mode, ok, _ := util.ParseFileMode(op.Mode); ok {
		return mode
	}
	return sandbox.FileMode
}

// contentOf returns what the operation writes: its random text when compile
// decided it has no content of its own, else exactly its content, which may
// be empty.
func contentOf(c compile.Op) []byte {
	if c.Random > 0 {
		return []byte(c.Rand.Derive("content").Stream().Text(c.Random))
	}
	return []byte(c.Content)
}

func optionalTime(value, field string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}
