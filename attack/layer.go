// Package attack writes the ATT&CK Navigator layer for a run: one technique
// per ID the scenario's operations were tagged with (mitre:), scored by how
// many operations that ran exhibit it.
//
// The layer is built from the ledger, not from the input, so an operation
// that was skipped or had nothing to do contributes nothing: the layer says
// what the corpus holds evidence of, as the answer key does. It reads no
// clock and orders everything, so it is byte-stable for a given input and
// seed.
package attack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/aoiflux/fsagen/ledger"
)

// FileName is the layer's name in the metadata directory.
const FileName = "mitre-layer.json"

// LayerVersion and NavigatorVersion are the Navigator layer format this
// writes. No ATT&CK content version is claimed: fsagen checks the shape of an
// ID, not that the catalogue defines it.
const (
	LayerVersion     = "4.5"
	NavigatorVersion = "5.1.0"
)

type versions struct {
	Layer     string `json:"layer"`
	Navigator string `json:"navigator"`
}

type metadata struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type technique struct {
	TechniqueID       string     `json:"techniqueID"`
	Score             *int       `json:"score,omitempty"`
	Comment           string     `json:"comment,omitempty"`
	Enabled           bool       `json:"enabled"`
	Metadata          []metadata `json:"metadata,omitempty"`
	ShowSubtechniques bool       `json:"showSubtechniques,omitempty"`
}

type gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type layer struct {
	Name        string      `json:"name"`
	Versions    versions    `json:"versions"`
	Domain      string      `json:"domain"`
	Description string      `json:"description"`
	Techniques  []technique `json:"techniques"`
	Gradient    gradient    `json:"gradient"`
	Metadata    []metadata  `json:"metadata,omitempty"`
}

// Tagged reports whether any operation that ran carries a technique, which
// is when a run writes a layer at all.
func Tagged(entries []ledger.Entry) bool {
	return slices.ContainsFunc(entries, func(e ledger.Entry) bool {
		return e.Outcome == ledger.Done && len(e.Mitre) > 0
	})
}

// evidence is what the run left for one technique.
type evidence struct {
	ops   []int
	paths []string
}

// Layer builds the Navigator layer for the operations in entries that ran.
// name titles it, typically after the input file; meta is carried into the
// layer's metadata as given, in order.
func Layer(name string, entries []ledger.Entry, meta [][2]string) ([]byte, error) {
	byID := map[string]*evidence{}
	for _, e := range entries {
		if e.Outcome != ledger.Done {
			continue
		}
		for _, id := range e.Mitre {
			ev := byID[id]
			if ev == nil {
				ev = &evidence{}
				byID[id] = ev
			}
			ev.ops = append(ev.ops, e.N)
			ev.paths = append(ev.paths, touched(e)...)
		}
	}

	l := layer{
		Name:        name,
		Versions:    versions{Layer: LayerVersion, Navigator: NavigatorVersion},
		Domain:      "enterprise-attack",
		Description: "Techniques exhibited by an fsagen scenario; each score is the number of operations that exhibit it.",
		Techniques:  techniques(byID),
		Gradient:    gradient{Colors: []string{"#ffffff", "#ff6666"}, MinValue: 0, MaxValue: maxScore(byID)},
	}
	for _, m := range meta {
		l.Metadata = append(l.Metadata, metadata{Name: m[0], Value: m[1]})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		return nil, fmt.Errorf("encode %s: %w", FileName, err)
	}
	return buf.Bytes(), nil
}

// techniques lists every tagged technique by ID. A technique with tagged
// sub-techniques is shown unfolded, and a sub-technique whose parent is not
// tagged itself brings an unscored parent entry that unfolds it, so Navigator
// shows every tagged ID without the reader expanding anything.
func techniques(byID map[string]*evidence) []technique {
	parents := map[string]bool{}
	for id := range byID {
		if parent, _, sub := strings.Cut(id, "."); sub {
			parents[parent] = true
		}
	}
	var out []technique
	for id, ev := range byID {
		score := len(ev.ops)
		t := technique{
			TechniqueID:       id,
			Score:             &score,
			Comment:           "ledger operations " + joinInts(ev.ops),
			Enabled:           true,
			ShowSubtechniques: parents[id],
		}
		for _, p := range slices.Compact(slices.Sorted(slices.Values(ev.paths))) {
			t.Metadata = append(t.Metadata, metadata{Name: "path", Value: p})
		}
		out = append(out, t)
	}
	for parent := range parents {
		if byID[parent] == nil {
			out = append(out, technique{TechniqueID: parent, Enabled: true, ShowSubtechniques: true})
		}
	}
	slices.SortFunc(out, func(a, b technique) int { return strings.Compare(a.TechniqueID, b.TechniqueID) })
	return out
}

// touched is every path the operation acted on.
func touched(e ledger.Entry) []string {
	var out []string
	for _, p := range []string{e.Path, e.NewPath} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func maxScore(byID map[string]*evidence) int {
	m := 0
	for _, ev := range byID {
		m = max(m, len(ev.ops))
	}
	return m
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
