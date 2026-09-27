package compile

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/spec"
)

// simulate runs the operations, in execution order, against an in-memory
// model of the tree. It expands ref/refs into concrete paths and rejects
// anything that would fail, or silently do nothing, on disk.
func simulate(ops []Op, t *model.Tree, opts Options) ([]Op, error) {
	var errs ErrorList
	declared := map[string]SourceRef{} // id -> the YAML action that declares it

	out := make([]Op, 0, len(ops))
	for i := range ops {
		op := &ops[i]
		r := op.report(&errs)
		if !declareID(op, declared, r) {
			continue
		}
		targets, ok := resolveTargets(t, op, r)
		if !ok {
			continue
		}
		out = append(out, applyToTargets(t, op, targets, opts, r)...)
	}
	return out, errs.err()
}

// declareID records the id an operation declares, rejecting a second action
// that claims one already taken. A repeated or batched action declares its id
// once per occurrence, all from the same YAML node, which is allowed.
func declareID(op *Op, declared map[string]SourceRef, r reporter) bool {
	if op.ID == "" {
		return true
	}
	if prev, ok := declared[op.ID]; ok && !samePosition(prev, op.Src) {
		r.at("id", "id %q is already declared at %s:%d:%d", op.ID, prev.File, prev.Line, prev.Col)
		return false
	}
	declared[op.ID] = op.Src
	return true
}

// samePosition reports whether two references name the same YAML node.
func samePosition(a, b SourceRef) bool {
	return a.File == b.File && a.Line == b.Line && a.Col == b.Col
}

// resolveTargets lists the paths an operation acts on: the one path it names,
// or every live path created under the id its ref or refs names.
func resolveTargets(t *model.Tree, op *Op, r reporter) ([]string, bool) {
	var field, id string
	switch {
	case op.Ref != "":
		field, id = "ref", op.Ref
	case op.Refs != "":
		field, id = "refs", op.Refs
	default:
		return []string{op.Path}, true
	}

	live, known := t.Live(id)
	switch {
	case !known:
		r.at(field, "unknown id %q (ids are declared with id: on an earlier action)", id)
		return nil, false
	case len(live) == 0:
		r.at(field, "every path created under id %q has already been deleted", id)
		return nil, false
	case field == "ref" && len(live) > 1:
		r.at(field, "id %q names %d paths; use refs: to act on all of them", id, len(live))
		return nil, false
	}
	return live, true
}

// applyToTargets applies one operation to each of its targets, yielding one
// operation per path. A target that cannot be applied is reported and dropped,
// so one pass reports every problem in the scenario.
func applyToTargets(t *model.Tree, op *Op, targets []string, opts Options, r reporter) []Op {
	out := make([]Op, 0, len(targets))
	for _, p := range targets {
		o := *op
		o.Path, o.Ref, o.Refs = p, "", ""
		if op.Refs != "" {
			// One action over many files: each file draws its own
			// random content, keyed by its path.
			o.Rand = op.Rand.Derive("target", p)
		}
		// A ref names its file only now, so the extension check that a
		// path-targeted operation already had at compile time happens here
		// instead. Each target is checked on its own: one refs may name files
		// of several kinds.
		if op.Path == "" {
			settleContent(&o, r)
		}
		if err := apply(t, &o, opts); err != nil {
			// An archive names the key its own problem concerns, so a message
			// about members or base is filed there rather than at the target.
			field, msg := archiveField(err, targetField(op))
			r.at(field, "%s", msg)
			continue
		}
		out = append(out, o)
	}
	return out
}

// targetField names the key that chose the operation's target, so a problem
// with a target is reported against the key the author wrote.
func targetField(op *Op) string {
	switch {
	case op.Ref != "":
		return "ref"
	case op.Refs != "":
		return "refs"
	}
	return "path"
}

// simulation is one operation being applied to the model.
type simulation struct {
	tree *model.Tree
	op   *Op
	opts Options
	// when is the time the operation happens, which the time rules stamp on
	// whatever it creates or changes.
	when time.Time
	// primary is the object the operation's explicit times describe. It starts
	// as the path the operation names and moves when the action leaves its
	// mark elsewhere: a rename's destination, a delete's parent directory.
	primary string
}

// simulators say what each action does to the model. Every name in Actions has
// an entry, which TestEveryActionSimulates proves.
var simulators = map[string]func(*simulation) error{
	"create":        applyCreate,
	"append":        applyAppend,
	"update":        applyWrite,
	"truncate":      applyWrite,
	"edit":          applyWrite,
	"archive":       applyArchive,
	"delete":        applyDelete,
	"mace":          applyMace,
	"rename":        applyRename,
	"copy":          applyCopy,
	"rotate":        applyRotate,
	"email":         applyEmail,
	"ansible-vault": applyVault,
	"ads":           applyStream,
	"motw":          applyStream,
}

// apply performs one operation on the model, enforcing the preconditions the
// executor relies on, and works out the times it intends: see times.go.
func apply(t *model.Tree, op *Op, opts Options) error {
	action, ok := simulators[op.Action]
	if !ok {
		return fmt.Errorf("unknown action %q", op.Action)
	}
	s := &simulation{tree: t, op: op, opts: opts, when: opTime(op), primary: op.Path}
	t.Clock = s.when
	if err := action(s); err != nil {
		return err
	}
	settleTimes(s)
	return nil
}

// portable rejects a path that would not work on every platform, unless the
// run has been told this scenario only has to work on one.
func (s *simulation) portable(paths ...string) error {
	if s.opts.AllowNonportable {
		return nil
	}
	for _, p := range paths {
		if err := pathpolicy.Portable(p); err != nil {
			return fmt.Errorf("%w (pass --allow-nonportable for a scenario that only has to work on one platform)", err)
		}
	}
	return nil
}

// mustFile requires the path the operation names to be a file that exists.
func (s *simulation) mustFile(what string) error {
	switch o := s.tree.Get(s.op.Path); {
	case o == nil:
		return fmt.Errorf("%s: %s does not exist%s", what, s.op.Path, hintFor(s.op.Action))
	case o.Kind != model.File:
		return fmt.Errorf("%s: %s is a directory", what, s.op.Path)
	}
	return nil
}

// tag records the operation's id against a path, so a later ref or refs can
// name what this action created.
func (s *simulation) tag(p string) {
	if s.op.ID != "" {
		s.tree.Tag(p, s.op.ID)
	}
}

// writeOrCreate records a write to the file already at the operation's path,
// or creates it and records it as born. rewrite forces a fresh file even when
// one is already there.
func (s *simulation) writeOrCreate(rewrite bool) error {
	p := s.op.Path
	if !rewrite && s.tree.Get(p) != nil {
		written(s.tree, p, s.when)
		return nil
	}
	if err := s.tree.CreateFile(p); err != nil {
		return err
	}
	born(s.tree, p, s.when)
	return nil
}

func applyCreate(s *simulation) error {
	if err := s.portable(s.op.Path); err != nil {
		return err
	}
	if err := s.createObject(); err != nil {
		return err
	}
	s.tag(s.op.Path)
	return nil
}

// createObject makes the directory or the empty file a create names.
func (s *simulation) createObject() error {
	if s.op.Dir {
		return s.tree.MkdirAll(s.op.Path)
	}
	if err := s.tree.CreateFile(s.op.Path); err != nil {
		return err
	}
	born(s.tree, s.op.Path, s.when)
	return nil
}

func applyAppend(s *simulation) error {
	p := s.op.Path
	switch o := s.tree.Get(p); {
	case o != nil && o.Kind != model.File:
		return fmt.Errorf("append: %s is a directory", p)
	case o != nil:
		written(s.tree, p, s.when)
	default:
		// Appending is how a log comes into being, so a missing file is
		// created, and recorded as created.
		if err := s.portable(p); err != nil {
			return err
		}
		if err := s.tree.CreateFile(p); err != nil {
			return err
		}
	}
	s.tag(p)
	return nil
}

// applyWrite covers the actions that change a file which must already exist.
func applyWrite(s *simulation) error {
	if err := s.mustFile(s.op.Action); err != nil {
		return err
	}
	written(s.tree, s.op.Path, s.when)
	return nil
}

func applyArchive(s *simulation) error {
	p := s.op.Path
	if err := s.portable(p); err != nil {
		return err
	}
	// The members are settled before the archive exists, so a pattern can
	// never sweep the archive into itself.
	members, err := archiveMembers(s.tree, s.op)
	if err != nil {
		return err
	}
	s.op.Members = members
	if err := s.tree.CreateFile(p); err != nil {
		return err
	}
	born(s.tree, p, s.when)
	s.tag(p)
	return nil
}

func applyDelete(s *simulation) error {
	op, p := s.op, s.op.Path
	o := s.tree.Get(p)
	if o == nil {
		if op.MissingOK {
			op.NoOp = "path does not exist (missing_ok)"
			return nil
		}
		return fmt.Errorf("delete: %s does not exist (set missing_ok: true if that is expected)", p)
	}
	op.Pre = []Stamp{{Path: p, Times: o.Times}}
	op.Object, op.Kind, op.Times = o.Serial, o.Kind, o.Times
	if err := s.tree.Remove(p); err != nil {
		return err
	}
	// A delete's own times describe the directory it was deleted from.
	s.primary = path.Dir(p)
	if s.primary == "." && (op.Atime != "" || op.Mtime != "") {
		return fmt.Errorf("delete: atime and mtime set the times of the directory %s was deleted from, and the output root's own times are not part of the scenario; drop them or put the file in a directory", p)
	}
	return nil
}

func applyMace(s *simulation) error {
	if s.tree.Get(s.op.Path) == nil {
		return fmt.Errorf("mace: %s does not exist", s.op.Path)
	}
	return nil
}

func applyRename(s *simulation) error {
	op := s.op
	if err := s.portable(op.NewPath); err != nil {
		return err
	}
	if err := renameErr(s.tree.Rename(op.Path, op.NewPath), op.Path, op.NewPath); err != nil {
		return err
	}
	s.tag(op.NewPath)
	s.primary = op.NewPath
	return nil
}

func applyCopy(s *simulation) error {
	op := s.op
	if err := s.mustFile("copy"); err != nil {
		return err
	}
	if err := s.portable(op.NewPath); err != nil {
		return err
	}
	if err := renameErr(s.tree.Copy(op.Path, op.NewPath), op.Path, op.NewPath); err != nil {
		return err
	}
	s.tag(op.NewPath)
	s.primary = op.NewPath
	return nil
}

func applyRotate(s *simulation) error {
	op := s.op
	if err := s.mustFile("rotate"); err != nil {
		return err
	}
	if err := s.portable(op.NewPath); err != nil {
		return err
	}
	// The rotated file is renamed and keeps its times; the empty file that
	// takes its place is new, and is what explicit times describe.
	op.Moved = s.tree.Get(op.Path).Serial
	if err := renameErr(s.tree.Rename(op.Path, op.NewPath), op.Path, op.NewPath); err != nil {
		return err
	}
	return s.tree.CreateFile(op.Path)
}

func applyEmail(s *simulation) error {
	op, p := s.op, s.op.Path
	if err := s.portable(p); err != nil {
		return err
	}
	if err := s.resolveAttachments(); err != nil {
		return err
	}
	// An mbox is appended to, so anything already at the path has to be a
	// file; an eml is written whole every time.
	if EmailFormat(op.Operation) == "mbox" {
		if o := s.tree.Get(p); o != nil && o.Kind != model.File {
			return fmt.Errorf("email: %s is a directory", p)
		}
	}
	if err := s.writeOrCreate(EmailFormat(op.Operation) == "eml"); err != nil {
		return err
	}
	s.tag(p)
	return nil
}

// resolveAttachments turns each attachment ref into the path it names, and
// requires every artefact a message attaches to exist in the output by now.
func (s *simulation) resolveAttachments() error {
	if s.op.Email == nil {
		return nil
	}
	if err := resolveAttachmentRefs(s.tree, s.op); err != nil {
		return err
	}
	for i, a := range s.op.Email.Attachments {
		if a.SourceRoot == "" {
			continue
		}
		if o := s.tree.Get(a.SourceRoot); o == nil || o.Kind != model.File {
			return fmt.Errorf("email.attachments[%d].source_root: %s does not exist in the output at this point", i, a.SourceRoot)
		}
	}
	return nil
}

func applyVault(s *simulation) error {
	p := s.op.Path
	if err := s.portable(p); err != nil {
		return err
	}
	if err := s.tree.CreateFile(p); err != nil {
		return err
	}
	born(s.tree, p, s.when)
	s.tag(p)
	return nil
}

// applyStream adds the stream an ads or motw writes. Streams share their
// file's times, which a stream write does not change in the scenario (the
// executor restores them).
func applyStream(s *simulation) error {
	op, p := s.op, s.op.Path
	if s.tree.Get(p) == nil {
		return fmt.Errorf("%s: base %s does not exist; create it first (a stream cannot exist without its file)", op.Action, p)
	}
	return s.tree.AddStream(p, StreamOf(op.Operation))
}

// StreamOf is the stream an ads or motw operation writes. A mark of the web
// always goes to the stream Windows reads it from.
func StreamOf(op spec.Operation) string {
	if op.Action == "motw" {
		return ZoneIdentifierStream
	}
	return op.Stream
}

func renameErr(err error, from, to string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, model.ErrExist):
		return fmt.Errorf("%s already exists; moving %s onto it would silently replace it", to, from)
	case errors.Is(err, model.ErrNotExist):
		return fmt.Errorf("%s does not exist", from)
	}
	return err
}

func hintFor(action string) string {
	if action == "update" || action == "truncate" {
		return "; use create to make a new file"
	}
	return ""
}

// EmailFormat is the effective format of an email operation: the one it gives,
// or the one its extension implies. Both the simulator and the executor decide
// from this, so they cannot disagree about what a message is written as.
func EmailFormat(op spec.Operation) string {
	if op.Format != "" {
		return op.Format
	}
	if strings.EqualFold(path.Ext(op.Path), ".mbox") {
		return "mbox"
	}
	return "eml"
}

// archiveMembers settles what an archive holds: first every live path under
// each id it names, in the order those were created, then every file each
// pattern matches, in path order. A file named twice is stored once, and the
// archive is never a member of itself.
//
// Patterns are matched with path.Match, so "*" stops at a slash: write
// "staging/*/*.pdf" to reach a level down.
func archiveMembers(t *model.Tree, op *Op) ([]Member, error) {
	a := op.Archive
	base := strings.TrimSuffix(a.Base, "/")
	seen := map[string]bool{op.Path: true}
	var out []Member

	add := func(q string) error {
		if seen[q] {
			return nil
		}
		seen[q] = true
		o := t.Get(q)
		if o == nil || o.Kind != model.File {
			return nil
		}
		name, err := memberName(q, base)
		if err != nil {
			return err
		}
		out = append(out, Member{Path: q, Name: name, Times: o.Times})
		return nil
	}

	if err := addMemberRefs(t, a.MemberRefs, add); err != nil {
		return nil, err
	}
	if err := addMemberPatterns(t, a.Members, op.Path, add); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("archive: every member named has already been deleted")
	}
	return out, nil
}

// memberName is the name a member is stored under: its path with the archive's
// base stripped, or its whole path when the archive has no base.
func memberName(p, base string) (string, error) {
	if base == "" || base == "." {
		return p, nil
	}
	if !strings.HasPrefix(p, base+"/") {
		return "", fmt.Errorf("archive.base: %s is not under %s, so it has no name inside the archive", p, base)
	}
	return strings.TrimPrefix(p, base+"/"), nil
}

// addMemberRefs adds every live path under each id the archive names, in the
// order those paths were created.
func addMemberRefs(t *model.Tree, refs []string, add func(string) error) error {
	for _, id := range refs {
		live, known := t.Live(id)
		switch {
		case !known:
			return fmt.Errorf("archive.member_refs: unknown id %q (ids are declared with id: on an earlier action)", id)
		case len(live) == 0:
			return fmt.Errorf("archive.member_refs: every path created under id %q has already been deleted", id)
		}
		if err := addEach(live, add); err != nil {
			return err
		}
	}
	return nil
}

// addMemberPatterns adds every file each pattern matches, in path order. A
// pattern that matches nothing is an error: a silently empty archive would
// pass for a full one.
func addMemberPatterns(t *model.Tree, patterns []string, self string, add func(string) error) error {
	paths := t.Paths()
	for _, g := range patterns {
		matched, err := matchingFiles(t, paths, g, self)
		if err != nil {
			return err
		}
		if len(matched) == 0 {
			return fmt.Errorf("archive.members: %q matches no file in the output at this point", g)
		}
		if err := addEach(matched, add); err != nil {
			return err
		}
	}
	return nil
}

// matchingFiles lists the files in paths that the pattern names, never the
// archive being built.
func matchingFiles(t *model.Tree, paths []string, pattern, self string) ([]string, error) {
	var out []string
	for _, q := range paths {
		ok, err := path.Match(pattern, q)
		if err != nil {
			return nil, fmt.Errorf("archive.members: %q is not a valid pattern: %w", pattern, err)
		}
		if !ok || q == self {
			continue
		}
		if o := t.Get(q); o == nil || o.Kind != model.File {
			continue
		}
		out = append(out, q)
	}
	return out, nil
}

func addEach(paths []string, add func(string) error) error {
	for _, q := range paths {
		if err := add(q); err != nil {
			return err
		}
	}
	return nil
}

// resolveAttachmentRefs turns an attachment's ref into the path it names, so
// a message can attach an artefact an earlier action created without knowing
// its generated name.
func resolveAttachmentRefs(t *model.Tree, op *Op) error {
	attachments := append([]spec.Attachment(nil), op.Email.Attachments...)
	changed := false
	for i := range attachments {
		a := &attachments[i]
		if a.Ref == "" {
			continue
		}
		live, known := t.Live(a.Ref)
		switch {
		case !known:
			return fmt.Errorf("email.attachments[%d].ref: unknown id %q (ids are declared with id: on an earlier action)", i, a.Ref)
		case len(live) == 0:
			return fmt.Errorf("email.attachments[%d].ref: every path created under id %q has already been deleted", i, a.Ref)
		case len(live) > 1:
			return fmt.Errorf("email.attachments[%d].ref: id %q names %d paths; a message attaches one file at a time", i, a.Ref, len(live))
		}
		a.SourceRoot, a.Ref, changed = live[0], "", true
	}
	if changed {
		e := *op.Email
		e.Attachments = attachments
		op.Email = &e
	}
	return nil
}

// archiveFields are the keys an archive problem can concern, each recognised by
// the prefix the message carries.
var archiveFields = []string{"archive.base", "archive.members", "archive.member_refs", "archive"}

// archiveField splits the key an error names off the front of its message, so a
// complaint about archive.members is filed under that key rather than under the
// key that chose the target, which would put its line and column there too.
func archiveField(err error, fallback string) (field, msg string) {
	msg = err.Error()
	for _, f := range archiveFields {
		if rest, ok := strings.CutPrefix(msg, f+": "); ok {
			return f, rest
		}
	}
	return fallback, msg
}
