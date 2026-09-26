package compile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// compilePlaybook lowers a playbook into concrete operations with resolved
// times, paths and content. Everything that can be checked without rendering
// is checked first, so every mistake in a rejected playbook is reported.
func compilePlaybook(file string, root *yaml.Node, p *spec.Playbook, opts Options, src *sandbox.Sources) ([]Op, bool, error) {
	var errs ErrorList
	rootKeys := mappingKeys(root)
	fileRef := SourceRef{File: file, Line: root.Line, Col: root.Column}

	startTime, startNow, err := parseStart(p.Start, rootKeys.has("start"), true, fileRef, rootKeys, opts)
	if err != nil {
		errs.add(err)
	}
	if len(p.Actors) == 0 {
		errs.add(&Error{Src: fileRef, Msg: "no actors"})
	}
	if len(p.Steps) == 0 {
		errs.add(&Error{Src: fileRef, Msg: "no steps"})
	}

	actorNodes := seqItems(mappingValue(root, "actors"))
	actors := map[string]spec.Actor{}
	for i, a := range p.Actors {
		n := actorNodes[i]
		aref := SourceRef{File: file, Line: n.Line, Col: n.Column}
		key := strings.ToLower(a.Name)
		switch {
		case strings.TrimSpace(a.Name) == "":
			errs.add(&Error{Src: aref, Field: "name", Msg: "actor has no name"})
		case actors[key].Name != "":
			errs.add(&Error{Src: aref, Field: "name", Msg: fmt.Sprintf("actor %q is defined twice", a.Name)})
		case strings.HasPrefix(a.Base, "/"):
			errs.add(&Error{Src: aref, Field: "base", Msg: fmt.Sprintf("%q is absolute; actor bases are relative to the output root", a.Base)})
		}
		actors[key] = a
	}

	// Validate every step and action before generating anything.
	stepNodes := seqItems(mappingValue(root, "steps"))
	type stepInfo struct {
		offset, every time.Duration
		repeat, batch int
		keys          keys
		actionKeys    []keys
		actionNodes   []*yaml.Node
	}
	infos := make([]stepInfo, len(p.Steps))
	for si, st := range p.Steps {
		n := stepNodes[si]
		sk := mappingKeys(n)
		sref := SourceRef{File: file, Line: n.Line, Col: n.Column, Step: si + 1}
		at := func(field, format string, args ...any) {
			e := &Error{Src: sref, Field: field, Msg: fmt.Sprintf(format, args...)}
			if kn := sk[field]; kn != nil {
				e.Line, e.Col = kn.Line, kn.Column
			}
			errs.add(e)
		}
		info := stepInfo{keys: sk, repeat: 1, batch: 1}

		if _, ok := actors[strings.ToLower(st.Actor)]; !ok {
			at("actor", "unknown actor %q", st.Actor)
		}
		var err error
		if info.offset, err = parseDurationSafe(st.Offset); err != nil {
			at("offset", "%v", err)
		}
		if info.every, err = parseDurationSafe(st.Every); err != nil {
			at("every", "%v", err)
		} else if info.every < 0 {
			at("every", "%q is negative", st.Every)
		}
		if sk.has("repeat") {
			if st.Repeat < 1 {
				at("repeat", "must be at least 1")
			}
			info.repeat = max(st.Repeat, 1)
		}
		if sk.has("batch_count") {
			if st.BatchCount < 1 {
				at("batch_count", "must be at least 1")
			}
			info.batch = max(st.BatchCount, 1)
		}
		if info.repeat > 1 && !sk.has("every") {
			at("repeat", "repeat %d without every would stack every occurrence on the same instant; set every (every: 0s to do that on purpose)", st.Repeat)
		}
		if sk.has("condition") && !contains(Conditions, st.Condition) {
			at("condition", "unknown condition %q (want one of: %s; a step condition tests the iteration index)", st.Condition, strings.Join(Conditions, ", "))
		}
		if len(st.Actions) == 0 {
			at("actions", "step has no actions")
		}

		actNodes := seqItems(mappingValue(n, "actions"))
		for ai, a := range st.Actions {
			an := actNodes[ai]
			ak := mappingKeys(an)
			aref := SourceRef{File: file, Line: an.Line, Col: an.Column, Step: si + 1, Action: ai + 1, Name: a.Action}
			errs.add(checkFields(aref, ak, a.Action, true))
			aat := func(field, format string, args ...any) {
				e := &Error{Src: aref, Field: field, Msg: fmt.Sprintf(format, args...)}
				if kn := ak[field]; kn != nil {
					e.Line, e.Col = kn.Line, kn.Column
				}
				errs.add(e)
			}
			if ak.has("condition") && !contains(Conditions, a.Condition) {
				aat("condition", "unknown condition %q (want one of: %s; an action condition tests the batch index)", a.Condition, strings.Join(Conditions, ", "))
			}
			if ak.has("template") && !contains(Templates, a.Template) {
				aat("template", "unknown template %q (want one of: %s)", a.Template, strings.Join(Templates, ", "))
			}
			for _, f := range []struct{ key, val string }{{"path", a.Path}, {"new_path", a.NewPath}} {
				if strings.HasPrefix(f.val, "/") {
					aat(f.key, "%q is absolute; paths are relative to the actor base and the output root", f.val)
				}
			}
			info.actionKeys = append(info.actionKeys, ak)
			info.actionNodes = append(info.actionNodes, an)
		}
		infos[si] = info
	}
	if err := errs.err(); err != nil {
		return nil, startNow, err
	}

	var ops []Op
	opKeys := newOpKeys(opts.Seed)
	seq := 0
	for si, st := range p.Steps {
		info := infos[si]
		actor := actors[strings.ToLower(st.Actor)]
		baseTime := startTime.Add(info.offset)
		variables := render.MergeVariables(p.Variables, actor.Variables, opts.Vars)
		multi := info.repeat > 1 || info.batch > 1

		for i := 0; i < info.repeat; i++ {
			if !evalCondition(st.Condition, i, info.repeat) {
				continue
			}
			t := baseTime.Add(time.Duration(i) * info.every)

			for batchIdx := 0; batchIdx < info.batch; batchIdx++ {
				for ai, a := range st.Actions {
					if !evalCondition(a.Condition, batchIdx, info.batch) {
						continue
					}
					an := info.actionNodes[ai]
					ref := SourceRef{File: file, Line: an.Line, Col: an.Column, Step: si + 1, Action: ai + 1,
						Iteration: i, Batch: batchIdx, Multi: multi, Name: a.Action}

					seq++
					kind, value := identity(a.ID, an)
					ctx := render.Context{
						Seq:       seq,
						BatchIdx:  batchIdx,
						Iteration: i,
						Actor:     actor.Name,
						Timestamp: t,
						Variables: variables,
						Rand: opKeys.key("playbook", kind, value, "actor", actor.Name, "offset", st.Offset,
							"iteration", strconv.Itoa(i), "batch", strconv.Itoa(batchIdx)),
						Field: "offset",
					}

					// The offset is templated before parsing, so an expression
					// like "${BATCH}s" resolves.
					offset, err := render.Apply(a.Offset, ctx)
					if err != nil {
						errs.add(&Error{Src: ref, Field: "offset", Msg: err.Error()})
						continue
					}
					d, err := parseDurationSafe(offset)
					if err != nil {
						errs.add(&Error{Src: ref, Field: "offset", Msg: err.Error()})
						continue
					}
					at := t.Add(d)
					ctx.Timestamp = at
					// Times derived from the schedule may carry a seeded
					// fraction of a second; explicit times never do.
					when := at
					if p.SubsecondJitter {
						when = at.Add(time.Duration(ctx.Rand.Derive("jitter").Stream().IntN(10_000_000)) * 100)
					}

					op := spec.Operation{
						Action:      a.Action,
						Path:        joinPath(actor.Base, a.Path),
						ID:          a.ID,
						Ref:         a.Ref,
						Refs:        a.Refs,
						MissingOK:   a.MissingOK,
						NewPath:     joinPath(actor.Base, a.NewPath),
						Type:        a.Type,
						Ext:         a.Ext,
						Content:     a.Content,
						ContentLen:  a.ContentLen,
						ContentKind: a.ContentKind,
						ContentFile: a.ContentFile,
						Render:      a.Render,
						Mode:        a.Mode,
						Format:      a.Format,
						Pdf:         a.Pdf,
						Docx:        a.Docx,
						Pe:          a.Pe,
						History:     a.History,
						Email:       a.Email,
						Vault:       a.Vault,
						Archive:     a.Archive,
						Edit:        a.Edit,
						Atime:       a.Atime,
						Mtime:       a.Mtime,
						Ctime:       a.Ctime,
						Crtime:      a.Crtime,
						Stream:      a.Stream,
						ZoneID:      a.ZoneID,
						HostURL:     a.HostURL,
						ReferrerURL: a.ReferrerURL,
					}
					// Each occurrence gets its own copy of the nested specs,
					// rendered for its own iteration, with pdf and email
					// dates defaulting to the scheduled time.
					if ferr := defaultDates(&op, at); ferr != nil {
						errs.add(&Error{Src: ref, Field: ferr.field, Msg: ferr.msg})
						continue
					}
					// An archive names its members under the actor base, as
					// every other path in the action does.
					if op.Archive != nil {
						for mi, g := range op.Archive.Members {
							op.Archive.Members[mi] = joinPath(actor.Base, g)
						}
						op.Archive.Base = joinPath(actor.Base, op.Archive.Base)
					}

					// A named template supplies already-formatted content, so
					// it must not be templated a second time.
					if a.Template != "" {
						body, terr := getTemplate(a.Template, ctx)
						if terr != nil {
							errs.add(&Error{Src: ref, Field: "template", Msg: terr.Error()})
							continue
						}
						op.Content = body
						op.ContentFile = ""
						op.Render = boolPtr(false)
					}

					prepared, err := Prepare(op, src, ctx)
					if err != nil {
						errs.add(&Error{Src: ref, Msg: err.Error()})
						continue
					}
					ops = append(ops, Op{Operation: prepared, Src: ref, At: at, When: when, Rand: ctx.Rand, keys: info.actionKeys[ai]})
				}
			}
		}
	}

	// Operations run in time order. Steps may overlap (a repeating step and
	// a later one interleave), and an action offset can move an action past
	// the next step. Ties keep declaration order; ${SEQ} was assigned above,
	// in declaration order, and does not change.
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].At.Before(ops[j].At) })
	return ops, startNow, errs.err()
}

func boolPtr(b bool) *bool { return &b }

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
