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
	"errors"
	"fmt"
	"io"
	"os"
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
	// SettleRetries are the pauses before settling again when only access
	// times moved. Nil takes defaultSettleRetries.
	SettleRetries []time.Duration
	// AfterSettle is called with the pass number after each settle pass. It
	// lets a test play the part of another process reading the output between
	// settling and verifying. Nil does nothing.
	AfterSettle func(round int)
	// Sleep waits out one of SettleRetries. Nil takes time.Sleep; injecting
	// it is what lets a test assert which pauses were taken without
	// spending them, so the pauses it declares can be the real ones.
	Sleep func(time.Duration)
}

// settleRetries are the pauses this run waits before settling again.
func (c ExecContext) settleRetries() []time.Duration {
	if c.SettleRetries != nil {
		return c.SettleRetries
	}
	return defaultSettleRetries
}

// afterSettle runs the hook, if this run has one.
func (c ExecContext) afterSettle(round int) {
	if c.AfterSettle != nil {
		c.AfterSettle(round)
	}
}

// sleep waits out a pause between settle passes.
func (c ExecContext) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
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
		if err := recordOutcome(ctx, op, &e, digests); err != nil {
			// The entry for a failed operation is left out: the ledger says how
			// far the run got, and a half-finished operation did not get there.
			return entries, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// recordOutcome performs the operation, unless compile already settled that it
// does nothing here, and records on the entry what became of it.
func recordOutcome(ctx ExecContext, op compile.Op, e *ledger.Entry, digests map[int]string) error {
	switch {
	case op.NoOp != "":
		e.Outcome, e.Reason = ledger.NoOp, op.NoOp
	case op.Skip != "":
		e.Outcome, e.Reason = ledger.Skipped, op.Skip
	default:
		if err := runOp(ctx, op, e, digests); err != nil {
			return err
		}
		e.Outcome = ledger.Done
	}
	return nil
}

// runOp performs one operation and records what it did. Every failure names the
// operation, so a run that stops says which line of the input it stopped on.
func runOp(ctx ExecContext, op compile.Op, e *ledger.Entry, digests map[int]string) error {
	fail := func(err error) error {
		return fmt.Errorf("%s: %s %s: %w", op.Src, op.Action, op.Path, err)
	}
	if err := stampAll(ctx, op.Pre); err != nil {
		return fail(err)
	}
	if err := executeOp(ctx, op); err != nil {
		return fail(err)
	}
	// Digests are read before stamping: a read may move the access time, which
	// the stamps then put back.
	if err := describe(ctx.FS, op, e, digests); err != nil {
		return fail(err)
	}
	if err := stampAll(ctx, op.Stamps); err != nil {
		return fail(err)
	}
	return nil
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
	if op.Action == spec.ActionADS || op.Action == spec.ActionMOTW {
		e.Stream = compile.StreamOf(op.Operation)
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
	case spec.ActionRename, spec.ActionCopy:
		return op.NewPath
	case spec.ActionDelete:
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

// defaultSettleRetries are the pauses before settling again when only access
// times moved after a settle pass. With last-access updates on, anything that
// reads the new files (an antivirus scanning a fresh .bat, a search indexer)
// moves their access times; such readers usually finish within a second.
var defaultSettleRetries = []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}

// SettleAndVerify settles the tree and verifies it. When the only
// differences are access times, which another process can move by reading,
// it settles again after a pause, a few times, before giving up.
func SettleAndVerify(ctx ExecContext, tree *model.Tree) error {
	if err := Settle(ctx, tree); err != nil {
		return err
	}
	ctx.afterSettle(0)
	err := Verify(ctx, tree)
	retries := ctx.settleRetries()
	for i, pause := range retries {
		if !movedAccessOnly(err) {
			break
		}
		ctx.sleep(pause)
		if err := Settle(ctx, tree); err != nil {
			return err
		}
		ctx.afterSettle(i + 1)
		err = Verify(ctx, tree)
	}
	if movedAccessOnly(err) {
		var ve *VerifyError
		errors.As(err, &ve)
		ve.Hint = "only access times moved, again after settling " + fmt.Sprint(len(retries)+1) + " times: another process (an antivirus scanner, a search indexer) keeps reading the output while this volume updates access times on read; exclude the output directory from scanning, or turn last-access updates off (fsutil behavior set disablelastaccess 1)"
	}
	return err
}

// movedAccessOnly reports whether the only times that failed to verify were
// access times, which another process can move just by reading the output.
func movedAccessOnly(err error) bool {
	var ve *VerifyError
	return errors.As(err, &ve) && ve.accessOnly()
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
	var bad []Mismatch
	for _, o := range tree.Settle() {
		got, err := ctx.FS.Times(o.Path)
		if err != nil {
			return err
		}
		bad = append(bad, mismatches(ctx, o.Path, o.Times, got)...)
	}
	if len(bad) > 0 {
		return &VerifyError{Mismatches: bad}
	}
	return nil
}

// mismatches lists the times of one object that read back differently from what
// the scenario intends, by the volume's resolution or more. A time this platform
// cannot set is not compared, and neither is one the scenario does not pin.
func mismatches(ctx ExecContext, p string, want model.Times, have sandbox.Times) []Mismatch {
	caps, g := ctx.Caps, ctx.FS.Granularity()
	checks := []struct {
		field     string
		want, got time.Time
		res       time.Duration
		settable  bool
	}{
		{"atime", want.Atime, have.Atime, g.Atime, true},
		{"mtime", want.Mtime, have.Mtime, g.Mtime, true},
		{"ctime", want.Ctime, have.Ctime, g.Ctime, caps.ChangeTime},
		{"crtime", want.Btime, have.Btime, g.Btime, caps.BirthTime},
	}
	var bad []Mismatch
	for _, c := range checks {
		if !c.settable || c.want.IsZero() || within(c.want, c.got, c.res) {
			continue
		}
		bad = append(bad, Mismatch{p, c.field, c.want, c.got})
	}
	return bad
}

// within reports whether two times are closer together than the volume can
// tell apart.
func within(a, b time.Time, res time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d < res
}

// executors say how each action writes itself into the output. Every name in
// spec.Actions has an entry, which TestEveryActionExecutes proves.
var executors = map[spec.ActionName]func(ExecContext, compile.Op) error{
	spec.ActionCreate:   execCreate,
	spec.ActionUpdate:   execWrite,
	spec.ActionAppend:   execAppend,
	spec.ActionEdit:     execEdit,
	spec.ActionDelete:   execDelete,
	spec.ActionMACE:     execMace,
	spec.ActionRename:   execRename,
	spec.ActionCopy:     execCopy,
	spec.ActionTruncate: execTruncate,
	spec.ActionRotate:   execRotate,
	spec.ActionArchive:  writeArchive,
	spec.ActionEmail:    execEmail,
	spec.ActionVault:    execVault,
	spec.ActionADS:      execStream,
	spec.ActionMOTW:     execStream,
}

func executeOp(ctx ExecContext, c compile.Op) error {
	run, ok := executors[c.Action]
	if !ok {
		return fmt.Errorf("unknown action %q", c.Action)
	}
	return run(ctx, c)
}

// execCreate makes the directory or the file a create names.
func execCreate(ctx ExecContext, c compile.Op) error {
	if !c.Dir {
		return execWrite(ctx, c)
	}
	// Missing parents get the default mode; an explicit mode is for the
	// directory the operation names.
	if err := ctx.FS.MkdirAll(c.Path, sandbox.DirMode); err != nil {
		return err
	}
	return applyMode(ctx.FS, c.Operation, c.Path)
}

// execWrite builds the file's bytes and writes them whole. It serves create and
// update alike, which differ only in whether the file was already there.
func execWrite(ctx ExecContext, c compile.Op) error {
	content, err := buildContent(c)
	if err != nil {
		return err
	}
	return writeArtifact(ctx.FS, c.Operation, c.Path, content)
}

func execEdit(ctx ExecContext, c compile.Op) error { return editFile(ctx.FS, c) }

func execAppend(ctx ExecContext, c compile.Op) error {
	return appendTo(ctx.FS, c.Operation, c.Path, contentOf(c))
}

func execDelete(ctx ExecContext, c compile.Op) error { return ctx.FS.Remove(c.Path) }

// execMace changes no content: the times are stamped from the model after every
// operation, so a mace has only an explicit mode left to apply.
func execMace(ctx ExecContext, c compile.Op) error {
	return applyMode(ctx.FS, c.Operation, c.Path)
}

func execRename(ctx ExecContext, c compile.Op) error {
	if err := ctx.FS.MkdirParent(c.NewPath); err != nil {
		return err
	}
	return ctx.FS.Rename(c.Path, c.NewPath)
}

func execCopy(ctx ExecContext, c compile.Op) error {
	fs := ctx.FS
	if err := copyFile(fs, c.Path, c.NewPath, fileModeFor(c.Operation)); err != nil {
		return err
	}
	// Streams travel with the copy, as they do with the Windows CopyFile.
	if err := fs.CopyStreams(c.Path, c.NewPath); err != nil {
		return err
	}
	return applyMode(fs, c.Operation, c.NewPath)
}

func execTruncate(ctx ExecContext, c compile.Op) error {
	return openForEffect(ctx.FS, c.Operation, c.Path, os.O_WRONLY|os.O_TRUNC)
}

func execRotate(ctx ExecContext, c compile.Op) error {
	fs := ctx.FS
	if err := fs.MkdirParent(c.NewPath); err != nil {
		return err
	}
	if err := fs.Rename(c.Path, c.NewPath); err != nil {
		return err
	}
	// An empty file takes the rotated one's place.
	return openForEffect(fs, c.Operation, c.Path, os.O_CREATE|os.O_WRONLY)
}

func execEmail(ctx ExecContext, c compile.Op) error { return writeEmail(ctx, c, c.Path) }

// vaultSaltBytes is the salt length AES-256 takes, drawn from the operation's
// own stream when the scenario does not pin one.
const vaultSaltBytes = 32

func execVault(ctx ExecContext, c compile.Op) error {
	op := c.Operation
	salt := op.Vault.Salt
	if strings.TrimSpace(salt) == "" {
		salt = hex.EncodeToString(c.Rand.Derive("vault.salt").Stream().Bytes(vaultSaltBytes))
	}
	encrypted, err := util.AnsibleVaultEncrypt([]byte(op.Content), op.Vault.Password, op.Vault.VaultID, salt)
	if err != nil {
		return err
	}
	return writeArtifact(ctx.FS, op, c.Path, encrypted)
}

// execStream writes the named stream an ads or motw carries. Writing a stream
// moves the base file's times on disk; the stamps after the operation put back
// the ones the scenario intends.
func execStream(ctx ExecContext, c compile.Op) error {
	return ctx.FS.WriteStream(c.Path, compile.StreamOf(c.Operation), streamContent(c))
}

// streamContent is what the stream holds: a mark of the web is built from its
// own fields, and an ads carries the operation's content.
func streamContent(c compile.Op) []byte {
	if c.Action != spec.ActionMOTW {
		return contentOf(c)
	}
	var b strings.Builder
	b.WriteString("[ZoneTransfer]\r\n")
	fmt.Fprintf(&b, "ZoneId=%d\r\n", c.ZoneID)
	if c.ReferrerURL != "" {
		fmt.Fprintf(&b, "ReferrerUrl=%s\r\n", c.ReferrerURL)
	}
	if c.HostURL != "" {
		fmt.Fprintf(&b, "HostUrl=%s\r\n", c.HostURL)
	}
	return []byte(b.String())
}

// appendTo adds data to the end of a file, bringing it into being if it is not
// there yet.
func appendTo(fs *sandbox.FS, op spec.Operation, target string, data []byte) error {
	if err := fs.MkdirParent(target); err != nil {
		return err
	}
	f, err := fs.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return applyMode(fs, op, target)
}

// openForEffect opens a file for what the opening itself does: truncating it,
// or bringing it into being. It writes nothing and applies an explicit mode.
func openForEffect(fs *sandbox.FS, op spec.Operation, target string, flag int) error {
	f, err := fs.OpenFile(target, flag, fileModeFor(op))
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return applyMode(fs, op, target)
}

// editFile rewrites a file through the edit block. The whole result is built
// before anything is written, so a bad pattern leaves the file alone.
func editFile(fs *sandbox.FS, c compile.Op) error {
	before, err := fs.ReadFile(c.Path)
	if err != nil {
		return err
	}
	after, err := applyEdit(*c.Edit, before)
	if err != nil {
		return err
	}
	return writeArtifact(fs, c.Operation, c.Path, after)
}

// writeArchive packs the members compile settled against the model. Each one
// is read through a quiet handle, so making an archive of a corpus does not
// move the access times of everything in it, and is stored under the
// modification time the model says it has.
func writeArchive(ctx ExecContext, c compile.Op) error {
	a := c.Archive
	entries := make([]libgen.ZipEntry, 0, len(c.Members))
	for _, m := range c.Members {
		f, err := ctx.FS.OpenQuiet(m.Path)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}
		entries = append(entries, libgen.ZipEntry{
			Name:     m.Name,
			Data:     data,
			Modified: m.Times.Mtime,
			Deflate:  a.Method == "deflate",
		})
	}
	data, err := libgen.BuildZip(entries, a.Comment)
	if err != nil {
		return err
	}
	return writeArtifact(ctx.FS, c.Operation, c.Path, data)
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

	switch format := compile.EmailFormat(op); format {
	case "eml":
		if err := ctx.FS.WriteFile(target, msg, fileModeFor(op)); err != nil {
			return err
		}
		return applyMode(ctx.FS, op, target)
	case "mbox":
		// Append, so a whole thread accumulates across steps.
		return appendTo(ctx.FS, op, target, email.ToMbox(msg, email.EnvelopeSender(*op.Email), date))
	default:
		return fmt.Errorf("unknown email format %q (want eml or mbox)", format)
	}
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

// contentOf returns the bytes the operation supplies: the filler compile
// decided it needs when it has no content of its own, else exactly its
// content, which may be empty.
func contentOf(c compile.Op) []byte {
	if c.Random > 0 {
		return libgen.Filler(c.ContentKind, c.Random, c.Rand.Derive("content").Stream())
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
