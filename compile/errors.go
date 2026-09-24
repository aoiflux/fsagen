package compile

import (
	"fmt"
	"strings"
)

// SourceRef says where in the input an operation came from. Every error the
// compiler reports carries one, so a message names the file, the line and
// column, and the operation or step/action that caused it.
type SourceRef struct {
	File      string
	Line, Col int
	Op        int // manifest: 1-based operation number
	Step      int // playbook: 1-based step number
	Action    int // playbook: 1-based action number within its step
	Iteration int // playbook: 0-based repeat iteration
	Batch     int // playbook: 0-based batch index
	Multi     bool
	Name      string // the action as written
}

func (s SourceRef) String() string {
	var b strings.Builder
	b.WriteString(s.File)
	if s.Line > 0 {
		fmt.Fprintf(&b, ":%d:%d", s.Line, s.Col)
	}
	b.WriteString(s.where())
	return b.String()
}

// where is the position-free part, used by the dry-run listing.
func (s SourceRef) where() string {
	var b strings.Builder
	switch {
	case s.Op > 0:
		fmt.Fprintf(&b, ": operation %d", s.Op)
	case s.Step > 0:
		fmt.Fprintf(&b, ": step %d", s.Step)
		if s.Action > 0 {
			fmt.Fprintf(&b, " action %d", s.Action)
		}
		if s.Multi {
			fmt.Fprintf(&b, " (iteration %d, batch %d)", s.Iteration, s.Batch)
		}
	}
	if s.Name != "" {
		fmt.Fprintf(&b, " [%s]", s.Name)
	}
	return b.String()
}

// Error is one compile-time problem.
type Error struct {
	Src       SourceRef
	Field     string // the YAML key at fault, when there is one
	Line, Col int    // the key's own position, when known
	Msg       string
}

func (e *Error) Error() string {
	src := e.Src
	if e.Line > 0 {
		src.Line, src.Col = e.Line, e.Col
	}
	if e.Field != "" {
		return fmt.Sprintf("%s: %s: %s", src, e.Field, e.Msg)
	}
	return fmt.Sprintf("%s: %s", src, e.Msg)
}

// maxErrors caps how many problems one run reports; past that the rest are
// usually consequences of the first.
const maxErrors = 50

// ErrorList collects every problem found in one pass, so a file is fixed in
// one edit rather than one error at a time.
type ErrorList []error

func (l ErrorList) Error() string {
	parts := make([]string, 0, len(l)+1)
	for _, e := range l {
		parts = append(parts, e.Error())
	}
	if len(l) >= maxErrors {
		parts = append(parts, fmt.Sprintf("(stopped after %d errors)", maxErrors))
	}
	return strings.Join(parts, "\n")
}

func (l *ErrorList) add(err error) {
	if err == nil || len(*l) >= maxErrors {
		return
	}
	if nested, ok := err.(ErrorList); ok {
		for _, e := range nested {
			l.add(e)
		}
		return
	}
	// A repeated or batched action produces the same problem once per
	// occurrence; report it once, at its position in the file.
	if e, ok := err.(*Error); ok {
		for _, prev := range *l {
			if p, ok := prev.(*Error); ok && p.key() == e.key() {
				return
			}
		}
	}
	*l = append(*l, err)
}

// key identifies an error by its position in the file, field and message,
// ignoring which iteration or batch raised it.
func (e *Error) key() string {
	line, col := e.Src.Line, e.Src.Col
	if e.Line > 0 {
		line, col = e.Line, e.Col
	}
	return fmt.Sprintf("%s:%d:%d:%s:%s", e.Src.File, line, col, e.Field, e.Msg)
}

func (l ErrorList) err() error {
	if len(l) == 0 {
		return nil
	}
	return l
}
