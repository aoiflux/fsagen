package compile

import (
	"fmt"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// compileManifest renders a manifest's operations in declaration order.
// ${SEQ} is the 1-based operation number.
func compileManifest(file string, root *yaml.Node, m *spec.Manifest, opts Options, src *sandbox.Sources) ([]Op, error) {
	var errs ErrorList
	if len(m.Operations) == 0 {
		return nil, fmt.Errorf("%s: no operations", file)
	}
	vars := render.MergeVariables(m.Variables, opts.Vars)
	nodes := seqItems(mappingValue(root, "operations"))

	out := make([]Op, 0, len(m.Operations))
	for i, raw := range m.Operations {
		n := nodes[i]
		ref := SourceRef{File: file, Line: n.Line, Col: n.Column, Op: i + 1, Name: raw.Action}
		k := mappingKeys(n)
		if fieldErrs := checkFields(ref, k, raw.Action, false); len(fieldErrs) > 0 {
			errs.add(fieldErrs)
			continue
		}

		// ${DATE:...} in a manifest resolves against that operation's own
		// mtime, falling back to now when it has none.
		refTime := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw.Mtime)); err == nil {
			refTime = t
		}

		prepared, err := Prepare(raw, src, render.Context{Seq: i + 1, Timestamp: refTime, Variables: vars})
		if err != nil {
			errs.add(&Error{Src: ref, Msg: err.Error()})
			continue
		}
		out = append(out, Op{Operation: prepared, Src: ref, keys: k})
	}
	return out, errs.err()
}
