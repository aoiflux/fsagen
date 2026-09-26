package manifest

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/spec"
)

// applyEdit changes a file in place. The steps run in a fixed order, whatever
// order they were written in: whole lines go first, then substitutions over
// the text, then insertions. A scenario that needs another order uses two
// edits, which is also what the ledger will then show.
//
// The file's line endings survive: lines are split on "\n" alone, so a CRLF
// file keeps its carriage returns, and a file that ended without a newline
// still does.
func applyEdit(e spec.EditSpec, data []byte) ([]byte, error) {
	text := string(data)
	trailing := strings.HasSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	if trailing {
		lines = lines[:len(lines)-1]
	} else if text == "" {
		lines = nil
	}

	if s := strings.TrimSpace(e.DeleteLines); s != "" {
		from, to, err := compile.ParseLineRange(s)
		if err != nil {
			return nil, fmt.Errorf("delete_lines: %w", err)
		}
		if from > len(lines) {
			return nil, fmt.Errorf("delete_lines: %s names lines past the end of a %d line file", s, len(lines))
		}
		to = min(to, len(lines))
		lines = append(lines[:from-1], lines[to:]...)
	}

	if e.DeleteMatching != "" {
		re, err := regexp.Compile(e.DeleteMatching)
		if err != nil {
			return nil, fmt.Errorf("delete_matching: %w", err)
		}
		kept := lines[:0]
		for _, l := range lines {
			if !re.MatchString(l) {
				kept = append(kept, l)
			}
		}
		lines = kept
	}

	if len(e.Replace) > 0 {
		joined := strings.Join(lines, "\n")
		for i, r := range e.Replace {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("replace[%d].pattern: %w", i, err)
			}
			joined = replaceN(re, joined, r.With, r.Count)
		}
		lines = strings.Split(joined, "\n")
		if joined == "" {
			lines = nil
		}
	}

	for i, ins := range e.InsertAfter {
		re, err := regexp.Compile(ins.Pattern)
		if err != nil {
			return nil, fmt.Errorf("insert_after[%d].pattern: %w", i, err)
		}
		var out []string
		for _, l := range lines {
			out = append(out, l)
			if re.MatchString(l) {
				out = append(out, ins.Text)
			}
		}
		lines = out
	}

	result := strings.Join(lines, "\n")
	if trailing && len(lines) > 0 {
		result += "\n"
	}
	return []byte(result), nil
}

// replaceN substitutes the first n matches, or every one when n is not
// positive. The replacement expands $1 and ${name} against each match.
func replaceN(re *regexp.Regexp, src, repl string, n int) string {
	matches := re.FindAllStringSubmatchIndex(src, -1)
	if n > 0 && len(matches) > n {
		matches = matches[:n]
	}
	var out []byte
	last := 0
	for _, m := range matches {
		out = append(out, src[last:m[0]]...)
		out = re.ExpandString(out, repl, src, m)
		last = m[1]
	}
	return string(append(out, src[last:]...))
}
