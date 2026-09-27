package compile

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// stepInfo is what validation works out about one step and generation needs
// back: its resolved schedule, and the YAML nodes its actions came from.
type stepInfo struct {
	offset, every time.Duration
	repeat, batch int
	keys          keys
	actionKeys    []keys
	actionNodes   []*yaml.Node
}

// compilePlaybook lowers a playbook into concrete operations with resolved
// times, paths and content. Everything that can be checked without rendering
// is checked first, so every mistake in a rejected playbook is reported.
func compilePlaybook(file string, root *yaml.Node, p *spec.Playbook, opts Options, src *sandbox.Sources) ([]Op, bool, error) {
	var errs ErrorList
	rootKeys := mappingKeys(root)
	fileRef := SourceRef{File: file, Line: root.Line, Col: root.Column}
	r := reporter{errs: &errs, src: fileRef, keys: rootKeys}

	startTime, startNow, err := parseStart(p.Start, true, fileRef, rootKeys, opts)
	if err != nil {
		errs.add(err)
	}
	if len(p.Actors) == 0 {
		r.whole("no actors")
	}
	if len(p.Steps) == 0 {
		r.whole("no steps")
	}

	actors := validateActors(file, root, p.Actors, &errs)
	infos := validateSteps(file, root, p.Steps, actors, &errs)
	if err := errs.err(); err != nil {
		return nil, startNow, err
	}

	ops, err := generateOps(file, p, actors, infos, startTime, opts, src)
	return ops, startNow, err
}

// validateActors indexes the actors by lower-cased name, reporting the ones
// that have no name, are declared twice, or root themselves outside the tree.
func validateActors(file string, root *yaml.Node, list []spec.Actor, errs *ErrorList) map[string]spec.Actor {
	nodes := seqItems(mappingValue(root, "actors"))
	actors := map[string]spec.Actor{}
	for i, a := range list {
		n := nodes[i]
		r := reporter{errs: errs, src: SourceRef{File: file, Line: n.Line, Col: n.Column}}
		key := strings.ToLower(a.Name)
		switch {
		case strings.TrimSpace(a.Name) == "":
			r.at("name", "actor has no name")
		case actors[key].Name != "":
			r.at("name", "actor %q is defined twice", a.Name)
		case strings.HasPrefix(a.Base, "/"):
			r.at("base", "%q is absolute; actor bases are relative to the output root", a.Base)
		}
		actors[key] = a
	}
	return actors
}

// validateSteps checks every step and action before anything is generated, so
// one pass reports every mistake in the file.
func validateSteps(file string, root *yaml.Node, steps []spec.Step, actors map[string]spec.Actor, errs *ErrorList) []stepInfo {
	nodes := seqItems(mappingValue(root, "steps"))
	infos := make([]stepInfo, len(steps))
	for si, st := range steps {
		infos[si] = validateStep(file, nodes[si], si, st, actors, errs)
	}
	return infos
}

// validateStep checks one step's schedule and each of its actions, returning
// what generation needs to expand it.
func validateStep(file string, n *yaml.Node, si int, st spec.Step, actors map[string]spec.Actor, errs *ErrorList) stepInfo {
	sk := mappingKeys(n)
	sref := SourceRef{File: file, Line: n.Line, Col: n.Column, Step: si + 1}
	r := reporter{errs: errs, src: sref, keys: sk}
	info := stepInfo{keys: sk}

	if _, ok := actors[strings.ToLower(st.Actor)]; !ok {
		r.at("actor", "unknown actor %q", st.Actor)
	}
	var err error
	if info.offset, err = parseDurationSafe(st.Offset); err != nil {
		r.at("offset", "%v", err)
	}
	if info.every, err = parseDurationSafe(st.Every); err != nil {
		r.at("every", "%v", err)
	} else if info.every < 0 {
		r.at("every", "%q is negative", st.Every)
	}
	info.repeat = countAtLeastOne(r, sk, "repeat", st.Repeat)
	info.batch = countAtLeastOne(r, sk, "batch_count", st.BatchCount)
	if info.repeat > 1 && !sk.has("every") {
		r.at("repeat", "repeat %d without every would stack every occurrence on the same instant; set every (every: 0s to do that on purpose)", st.Repeat)
	}
	if sk.has("condition") && !contains(Conditions, st.Condition) {
		r.at("condition", "unknown condition %q (want one of: %s; a step condition tests the iteration index)", st.Condition, strings.Join(Conditions, ", "))
	}
	if len(st.Actions) == 0 {
		r.at("actions", "step has no actions")
	}

	actNodes := seqItems(mappingValue(n, "actions"))
	for ai, a := range st.Actions {
		info.actionKeys = append(info.actionKeys, validateAction(file, actNodes[ai], si, ai, a, errs))
		info.actionNodes = append(info.actionNodes, actNodes[ai])
	}
	return info
}

// countAtLeastOne reads a repeat-style count. It defaults to 1 when the key is
// absent and cannot go below it, so a given value under 1 is reported.
func countAtLeastOne(r reporter, k keys, field string, value int) int {
	if !k.has(field) {
		return 1
	}
	if value < 1 {
		r.at(field, "must be at least 1")
	}
	return max(value, 1)
}

// validateAction applies the field matrix to one action and checks the values
// that depend only on which keys are present. It returns the action's keys, so
// a later error can point at the key it concerns.
func validateAction(file string, an *yaml.Node, si, ai int, a spec.Action, errs *ErrorList) keys {
	ak := mappingKeys(an)
	aref := SourceRef{File: file, Line: an.Line, Col: an.Column, Step: si + 1, Action: ai + 1, Name: a.Action}
	errs.add(checkFields(aref, ak, a.Action, true))
	r := reporter{errs: errs, src: aref, keys: ak}

	if ak.has("condition") && !contains(Conditions, a.Condition) {
		r.at("condition", "unknown condition %q (want one of: %s; an action condition tests the batch index)", a.Condition, strings.Join(Conditions, ", "))
	}
	if ak.has("template") && !contains(Templates, a.Template) {
		r.at("template", "unknown template %q (want one of: %s)", a.Template, strings.Join(Templates, ", "))
	}
	for _, f := range []struct{ key, val string }{{"path", a.Path}, {"new_path", a.NewPath}} {
		if strings.HasPrefix(f.val, "/") {
			r.at(f.key, "%q is absolute; paths are relative to the actor base and the output root", f.val)
		}
	}
	return ak
}

// occurrence is one firing of a step: which iteration and batch index it is,
// and the time its actions are scheduled from.
type occurrence struct {
	iteration, batch int
	at               time.Time
}

// occurrences expands a step's repeat and batch counts into the firings whose
// condition admits them, in the order they run.
func occurrences(st spec.Step, info stepInfo, start time.Time) []occurrence {
	base := start.Add(info.offset)
	var out []occurrence
	for i := 0; i < info.repeat; i++ {
		if !evalCondition(st.Condition, i, info.repeat) {
			continue
		}
		at := base.Add(time.Duration(i) * info.every)
		for b := 0; b < info.batch; b++ {
			out = append(out, occurrence{iteration: i, batch: b, at: at})
		}
	}
	return out
}

// stepPlan is one validated step together with what all of its operations
// share: the actor performing it and the variables visible to it.
type stepPlan struct {
	index     int // 0-based position in the playbook, for the source reference
	step      spec.Step
	info      stepInfo
	actor     spec.Actor
	variables map[string]string
	// multi marks a step that fires more than once, so its source references
	// name the iteration and batch.
	multi bool
}

// opGen builds operations from validated steps. It holds what every operation
// needs: where the YAML came from, the run's options, the confined source
// reader and the random key tree.
type opGen struct {
	file     string
	playbook *spec.Playbook
	opts     Options
	src      *sandbox.Sources
	opKeys   *opKeys
	errs     *ErrorList
	// seq counts the operations generated so far, in declaration order, and is
	// what ${SEQ} renders to. Sorting into time order later does not change it.
	seq int
}

// generateOps renders every step into operations and puts them in time order.
func generateOps(file string, p *spec.Playbook, actors map[string]spec.Actor, infos []stepInfo, start time.Time, opts Options, src *sandbox.Sources) ([]Op, error) {
	var errs ErrorList
	g := &opGen{file: file, playbook: p, opts: opts, src: src, opKeys: newOpKeys(opts.Seed), errs: &errs}

	var ops []Op
	for si, st := range p.Steps {
		actor := actors[strings.ToLower(st.Actor)]
		info := infos[si]
		ops = append(ops, g.stepOps(stepPlan{
			index:     si,
			step:      st,
			info:      info,
			actor:     actor,
			variables: render.MergeVariables(p.Variables, actor.Variables, opts.Vars),
			multi:     info.repeat > 1 || info.batch > 1,
		}, start)...)
	}

	// Operations run in time order. Steps may overlap (a repeating step and
	// a later one interleave), and an action offset can move an action past
	// the next step. Ties keep declaration order; ${SEQ} was assigned above,
	// in declaration order, and does not change.
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].At.Before(ops[j].At) })
	return ops, errs.err()
}

// stepOps builds every operation one step contributes.
func (g *opGen) stepOps(sp stepPlan, start time.Time) []Op {
	var ops []Op
	for _, occ := range occurrences(sp.step, sp.info, start) {
		ops = append(ops, g.occurrenceOps(sp, occ)...)
	}
	return ops
}

// occurrenceOps builds the operations for one firing of a step: one per action
// whose condition admits this batch index.
func (g *opGen) occurrenceOps(sp stepPlan, occ occurrence) []Op {
	var ops []Op
	for ai, a := range sp.step.Actions {
		if !evalCondition(a.Condition, occ.batch, sp.info.batch) {
			continue
		}
		if op, ok := g.actionOp(sp, ai, a, occ); ok {
			ops = append(ops, op)
		}
	}
	return ops
}

// actionOp builds one operation from one action at one occurrence. A rejected
// action is reported and skipped rather than returned as an error, so one pass
// reports every mistake in the playbook.
func (g *opGen) actionOp(sp stepPlan, ai int, a spec.Action, occ occurrence) (Op, bool) {
	an := sp.info.actionNodes[ai]
	ref := SourceRef{File: g.file, Line: an.Line, Col: an.Column, Step: sp.index + 1, Action: ai + 1,
		Iteration: occ.iteration, Batch: occ.batch, Multi: sp.multi, Name: a.Action}
	r := reporter{errs: g.errs, src: ref}

	g.seq++
	ctx := g.context(sp, an, a, occ)
	at, err := applyActionOffset(a.Offset, occ.at, &ctx)
	if err != nil {
		r.at("offset", "%v", err)
		return Op{}, false
	}
	// Times derived from the schedule may carry a seeded fraction of a
	// second; explicit times never do.
	when := at
	if g.playbook.SubsecondJitter {
		when = at.Add(subsecondJitter(ctx.Rand))
	}

	// Each occurrence gets its own copy of the nested specs, rendered for its
	// own iteration, with pdf and email dates defaulting to the scheduled time.
	op := operationFrom(a, sp.actor)
	if ferr := defaultDates(&op, at); ferr != nil {
		r.at(ferr.field, "%s", ferr.msg)
		return Op{}, false
	}
	rebaseArchive(&op, sp.actor.Base)
	if err := applyTemplate(&op, a.Template, ctx); err != nil {
		r.at("template", "%v", err)
		return Op{}, false
	}

	prepared, err := Prepare(op, g.src, ctx)
	if err != nil {
		r.whole("%v", err)
		return Op{}, false
	}
	return Op{Operation: prepared, Src: ref, At: at, When: when, Rand: ctx.Rand, keys: sp.info.actionKeys[ai]}, true
}

// context is the render context for one action: the occurrence's time and
// indices, the variables visible to it, and its own random key. The key comes
// from the action's identity rather than its position, so inserting an
// unrelated action elsewhere does not change this one's bytes.
func (g *opGen) context(sp stepPlan, an *yaml.Node, a spec.Action, occ occurrence) render.Context {
	kind, value := identity(a.ID, an)
	return render.Context{
		Seq:       g.seq,
		BatchIdx:  occ.batch,
		Iteration: occ.iteration,
		Actor:     sp.actor.Name,
		Timestamp: occ.at,
		Variables: sp.variables,
		Rand: g.opKeys.key("playbook", kind, value, "actor", sp.actor.Name, "offset", sp.step.Offset,
			"iteration", strconv.Itoa(occ.iteration), "batch", strconv.Itoa(occ.batch)),
		Field: "offset",
	}
}

// applyActionOffset moves the occurrence time by the action's own offset. The
// offset is templated before it is parsed, so an expression like "${BATCH}s"
// resolves, and the context then moves to the result, so every field rendered
// afterwards sees the action's own time.
func applyActionOffset(offset string, base time.Time, ctx *render.Context) (time.Time, error) {
	rendered, err := render.Apply(offset, *ctx)
	if err != nil {
		return time.Time{}, err
	}
	d, err := parseDurationSafe(rendered)
	if err != nil {
		return time.Time{}, err
	}
	at := base.Add(d)
	ctx.Timestamp = at
	return at, nil
}

// subsecondJitter is a seeded fraction of a second, so a corpus does not have
// every timestamp landing on a whole second. The draw is in units of 100 ns,
// the finest resolution NTFS records.
func subsecondJitter(k prng.Key) time.Duration {
	const ticksPerSecond = 10_000_000
	return time.Duration(k.Derive("jitter").Stream().IntN(ticksPerSecond)) * 100
}

// rebaseArchive names an archive's members under the actor base, as every
// other path in the action is.
func rebaseArchive(op *spec.Operation, base string) {
	if op.Archive == nil {
		return
	}
	for i, member := range op.Archive.Members {
		op.Archive.Members[i] = joinPath(base, member)
	}
	op.Archive.Base = joinPath(base, op.Archive.Base)
}

// applyTemplate replaces the content with a named template's body. That body is
// already formatted, so it must not be templated a second time.
func applyTemplate(op *spec.Operation, name string, ctx render.Context) error {
	if name == "" {
		return nil
	}
	body, err := getTemplate(name, ctx)
	if err != nil {
		return err
	}
	op.Content = body
	op.ContentFile = ""
	op.Render = new(false)
	return nil
}

// operationFrom lowers a playbook action into the operation an executor runs,
// rooting its paths under the actor's base. An action is an operation plus its
// scheduling, so everything but the paths carries over unchanged.
func operationFrom(a spec.Action, actor spec.Actor) spec.Operation {
	op := a.Operation
	op.Path = joinPath(actor.Base, a.Path)
	op.NewPath = joinPath(actor.Base, a.NewPath)
	return op
}

// joinPath prefixes an actor's base. It keeps YAML's forward slashes; the
// result is validated and cleaned after rendering.
func joinPath(base, p string) string {
	if strings.TrimSpace(p) == "" || strings.TrimSpace(base) == "" {
		return p
	}
	return strings.TrimSuffix(base, "/") + "/" + p
}

// evalCondition applies a condition already known to be in the closed set.
func evalCondition(condition string, index, total int) bool {
	switch condition {
	case "odd":
		return index%2 == 1
	case "even":
		return index%2 == 0
	case "first":
		return index == 0
	case "last":
		return index == total-1
	default:
		return true
	}
}
