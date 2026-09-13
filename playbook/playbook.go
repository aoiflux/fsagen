package playbook

import (
	"fmt"
	manifestpkg "fsagen/manifest"
	"fsagen/render"
	"fsagen/spec"
	"fsagen/util"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type Playbook = spec.Playbook
type Actor = spec.Actor
type Step = spec.Step
type Action = spec.Action

// ExecutePlaybook loads a playbook YAML and executes compiled operations under root.
func ExecutePlaybook(root string, path string, vars map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var pb Playbook
	// Strict: silently ignoring an unknown key produces artifacts that look
	// right and are not.
	if err := yaml.UnmarshalStrict(data, &pb); err != nil {
		return fmt.Errorf("parse playbook: %w", err)
	}

	baseDir := filepath.Dir(path)
	ops, err := compilePlaybook(pb, baseDir, vars)
	if err != nil {
		return err
	}
	// Execute sequentially to preserve deterministic order
	return manifestpkg.ExecuteOperations(manifestpkg.ExecContext{Root: root, BaseDir: baseDir}, ops)
}

// compilePlaybook lowers a playbook into concrete manifest operations with
// resolved times, paths and content.
func compilePlaybook(p Playbook, baseDir string, cliVars map[string]string) ([]manifestpkg.Operation, error) {
	startTime := time.Now().UTC()
	if strings.TrimSpace(p.Start) != "" && strings.ToLower(p.Start) != "now" {
		t, err := time.Parse(time.RFC3339, p.Start)
		if err != nil {
			return nil, fmt.Errorf("invalid start: %w", err)
		}
		startTime = t
	}
	actors := map[string]Actor{}
	for _, a := range p.Actors {
		actors[strings.ToLower(a.Name)] = a
	}

	var ops []manifestpkg.Operation
	seq := 0
	for _, st := range p.Steps {
		actor, ok := actors[strings.ToLower(st.Actor)]
		if !ok {
			return nil, fmt.Errorf("unknown actor: %s", st.Actor)
		}
		offsetDur, err := parseDurationSafe(st.Offset)
		if err != nil {
			return nil, fmt.Errorf("step offset: %w", err)
		}
		everyDur, err := parseDurationDefault(st.Every, 0)
		if err != nil {
			return nil, fmt.Errorf("step every: %w", err)
		}
		if st.Repeat <= 0 {
			st.Repeat = 1
		}
		baseTime := startTime.Add(offsetDur)
		variables := render.MergeVariables(p.Variables, actor.Variables, cliVars)

		for i := 0; i < st.Repeat; i++ {
			if !evalCondition(st.Condition, i, st.Repeat) {
				continue
			}

			t := baseTime.Add(time.Duration(i) * everyDur)

			batchCount := st.BatchCount
			if batchCount <= 0 {
				batchCount = 1
			}

			for batchIdx := 0; batchIdx < batchCount; batchIdx++ {
				for _, a := range st.Actions {
					if !evalCondition(a.Condition, batchIdx, batchCount) {
						continue
					}

					seq++
					ctx := render.Context{
						Seq:       seq,
						BatchIdx:  batchIdx,
						Iteration: i,
						Actor:     actor.Name,
						Timestamp: t,
						Variables: variables,
					}

					// The offset is templated before parsing, so an expression
					// like "${BATCH}s" resolves. Parsing first used to leave
					// every batched file stamped with the same time.
					at := t
					if d, err := parseDurationSafe(render.Apply(a.Offset, ctx)); err != nil {
						return nil, fmt.Errorf("action offset %q: %w", a.Offset, err)
					} else {
						at = t.Add(d)
					}
					ctx.Timestamp = at

					// A message carries its own timestamp in the Date header,
					// which is what a mail store would show. Leave the times
					// unset so the email writer can use it; an explicit atime
					// or mtime on the action still wins.
					derive := !(strings.EqualFold(strings.TrimSpace(a.Action), "email") &&
						a.Email != nil && strings.TrimSpace(a.Email.Date) != "")

					atime := a.Atime
					mtime := a.Mtime
					if derive {
						if strings.TrimSpace(atime) == "" {
							atime = at.Format(time.RFC3339)
						}
						if strings.TrimSpace(mtime) == "" {
							mtime = at.Format(time.RFC3339)
						}
					}

					op := manifestpkg.Operation{
						Action:      a.Action,
						Path:        joinPath(actor.Base, a.Path),
						NewPath:     joinPath(actor.Base, a.NewPath),
						Type:        a.Type,
						Ext:         a.Ext,
						Content:     a.Content,
						ContentLen:  a.ContentLen,
						ContentFile: a.ContentFile,
						Render:      a.Render,
						Mode:        a.Mode,
						Format:      a.Format,
						Pdf:         a.Pdf,
						Email:       a.Email,
						Vault:       a.Vault,
						Atime:       atime,
						Mtime:       mtime,
						Stream:      a.Stream,
						ZoneID:      a.ZoneID,
						HostURL:     a.HostURL,
						ReferrerURL: a.ReferrerURL,
					}

					// A named template supplies already-formatted content, so
					// it must not be templated a second time.
					if a.Template != "" {
						op.Content = getTemplate(a.Template, ctx)
						op.ContentFile = ""
						op.Render = boolPtr(false)
					}

					prepared, err := manifestpkg.PrepareOperation(op, baseDir, ctx)
					if err != nil {
						return nil, fmt.Errorf("step %q action %q: %w", st.Actor, a.Action, err)
					}
					ops = append(ops, prepared)
				}
			}
		}
	}

	return ops, nil
}

func boolPtr(b bool) *bool { return &b }

func joinPath(base, p string) string {
	if strings.TrimSpace(p) == "" {
		return p
	}
	if strings.TrimSpace(base) == "" {
		return p
	}
	// keep forward slash YAML style, convert later by manifest executor
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/")
}

func parseDurationDefault(s string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return parseDuration(s)
}

func parseDurationSafe(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return parseDuration(s)
}

var reDayWeek = regexp.MustCompile(`^(\d+)([dw])`)

// parseDuration extends time.ParseDuration with day and week units. Scenarios
// here run over days ("2d6h" for a 54-hour dwell time), and Go's parser stops
// at hours.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var total time.Duration

	for {
		m := reDayWeek.FindStringSubmatch(s)
		if m == nil {
			break
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		unit := 24 * time.Hour
		if m[2] == "w" {
			unit = 7 * 24 * time.Hour
		}
		total += time.Duration(n) * unit
		s = s[len(m[0]):]
	}

	if s == "" {
		if total == 0 {
			return 0, fmt.Errorf("invalid duration: empty")
		}
		return total, nil
	}

	rest, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return total + rest, nil
}

// evalCondition evaluates conditional logic for steps/actions
func evalCondition(condition string, index, total int) bool {
	condition = strings.ToLower(strings.TrimSpace(condition))
	if condition == "" {
		return true
	}
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

// getTemplate returns predefined content templates
func getTemplate(templateName string, ctx render.Context) string {
	switch strings.ToLower(templateName) {
	case "email":
		return fmt.Sprintf(`From: %s@example.com
To: recipient@example.com
Subject: %s
Date: %s

This is an automated message from %s.

Message ID: %d
`,
			strings.ToLower(ctx.Actor),
			util.GetRandomString(20),
			ctx.Timestamp.Format(time.RFC1123Z),
			ctx.Actor,
			ctx.Seq)

	case "log":
		return fmt.Sprintf(`%s [INFO] User=%s Action=file_access File=document_%d.txt Result=success
%s [WARN] User=%s Action=failed_login Attempts=3
%s [INFO] User=%s Action=logout SessionID=%d
`,
			ctx.Timestamp.Format(time.RFC3339),
			ctx.Actor,
			ctx.Seq,
			ctx.Timestamp.Add(1*time.Minute).Format(time.RFC3339),
			ctx.Actor,
			ctx.Timestamp.Add(2*time.Minute).Format(time.RFC3339),
			ctx.Actor,
			ctx.Seq)

	case "script":
		return fmt.Sprintf(`#!/bin/bash
# Generated by %s at %s
# Sequence: %d

echo "Running automated task"
echo "User: %s"
echo "Timestamp: %s"
`,
			ctx.Actor,
			ctx.Timestamp.Format(time.RFC3339),
			ctx.Seq,
			ctx.Actor,
			ctx.Timestamp.Format(time.RFC3339))

	case "doc":
		return fmt.Sprintf(`Document Title: Report %d
Author: %s
Date: %s

This is a generated document for testing purposes.
Document ID: %d
Generated content: %s
`,
			ctx.Seq,
			ctx.Actor,
			ctx.Timestamp.Format("2006-01-02"),
			ctx.Seq,
			util.GetRandomString(100))

	default:
		return util.GetRandomString(256)
	}
}
