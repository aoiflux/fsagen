// Package oracle is fsagen's diff-oracle subcommand: it scores what a
// forensic tool reports about a generated tree against what fsagen knows
// it made. The expected state comes from the run's sidecar directory: the
// ledger, folded operation by operation, and SHA256SUMS. The tool's report
// can be The Sleuth Kit's bodyfile (fls -m), Plaso's l2tcsv, dynamic CSV or
// JSON lines, or one of fsagen's own timelines.
//
// Six categories are scored, each with true and false positives and
// negatives: the names present, the deleted entries, the named streams, the
// times of every entry found, the digests the tool computed, and links
// (hard-linked names sharing an inode, where symlinks and junctions point).
package oracle

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// Exit codes. They follow fsagen's own, with one more for a score below
// --fail-under.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitBelow = 3
)

// ScorecardVersion is the version of the scorecard's layout.
const ScorecardVersion = 1

// Case modes.
const (
	caseAuto  = "auto"
	caseExact = "exact"
	caseFold  = "fold"
)

// listLimit is how many missing, extra or wrong findings the text report
// shows per category; the scorecard lists them all.
const listLimit = 20

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// errBelow marks a run that scored below --fail-under.
var errBelow = errors.New("below --fail-under")

type config struct {
	meta, model, format    string
	prefix                 string
	prefixSet              bool
	tolerance              time.Duration
	toleranceSet           bool
	caseMode               string
	categories             []string
	scorecard              string
	failUnder              float64
	failUnderSet           bool
	tool                   string
	stdin                  io.Reader
	stdout, stderr         io.Writer
	toleranceText, catText string
}

// Main runs "fsagen diff-oracle" with the arguments after the subcommand's
// name, and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stdout)
		return exitOK
	}
	if err == nil {
		c.stdin, c.stdout, c.stderr = stdin, stdout, stderr
		err = c.run()
	}
	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errBelow):
		return exitBelow
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "fsagen diff-oracle: %v\nRun 'fsagen diff-oracle -h' for usage.\n", err)
		return exitUsage
	default:
		fmt.Fprintf(stderr, "fsagen diff-oracle: %v\n", err)
		return exitError
	}
}

func parseFlags(args []string) (*config, error) {
	c := &config{}
	fl := flag.NewFlagSet("fsagen diff-oracle", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	fl.StringVar(&c.meta, "meta", "", "the run's sidecar directory")
	fl.StringVar(&c.format, "format", "", "the tool output's format")
	fl.StringVar(&c.model, "model", "", "a modelled timeline of the same run")
	fl.StringVar(&c.prefix, "strip-prefix", "", "the path the tool gives the output root")
	fl.StringVar(&c.toleranceText, "time-tolerance", "", "how far a time may be off")
	fl.StringVar(&c.caseMode, "case", caseAuto, "auto, exact or fold")
	fl.StringVar(&c.catText, "categories", "", "the categories to score")
	fl.StringVar(&c.scorecard, "scorecard", "", "write the scorecard as JSON")
	fl.Float64Var(&c.failUnder, "fail-under", 0, "exit 3 when the overall F1 is below this")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}
	fl.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "strip-prefix":
			c.prefixSet = true
		case "time-tolerance":
			c.toleranceSet = true
		case "fail-under":
			c.failUnderSet = true
		}
	})
	switch rest := fl.Args(); len(rest) {
	case 0:
		return nil, usagef("missing the tool's output (a file, or - for standard input)")
	case 1:
		c.tool = rest[0]
	default:
		return nil, usagef("unexpected argument %q after the tool's output (flags must come before it)", rest[1])
	}
	return c, c.check()
}

// check rejects flags that make no sense, before anything is read.
func (c *config) check() error {
	if c.meta == "" {
		return usagef("--meta is required: the sidecar directory of the run the tool examined (<output>.fsagen)")
	}
	if c.format != "" {
		if _, ok := formatNamed(c.format); !ok {
			return usagef("--format must be one of %s, not %q", strings.Join(FormatNames(), ", "), c.format)
		}
	}
	if c.toleranceSet {
		d, err := time.ParseDuration(c.toleranceText)
		if c.toleranceText == "0" {
			d, err = 0, nil
		}
		if err != nil || d < 0 {
			return usagef("--time-tolerance must be a duration such as 0, 100ns, 1us, 1s or 2s, not %q", c.toleranceText)
		}
		c.tolerance = d
	}
	if !slices.Contains([]string{caseAuto, caseExact, caseFold}, c.caseMode) {
		return usagef("--case must be auto, exact or fold, not %q", c.caseMode)
	}
	c.categories = CategoryNames
	if c.catText != "" {
		c.categories = nil
		for _, n := range strings.Split(c.catText, ",") {
			n = strings.TrimSpace(n)
			if !slices.Contains(CategoryNames, n) {
				return usagef("--categories takes %s, not %q", strings.Join(CategoryNames, ", "), n)
			}
			if !slices.Contains(c.categories, n) {
				c.categories = append(c.categories, n)
			}
		}
	}
	if c.failUnderSet && (c.failUnder < 0 || c.failUnder > 1) {
		return usagef("--fail-under must be between 0 and 1, not %v", c.failUnder)
	}
	return nil
}

func (c *config) run() error {
	x, err := LoadExpected(c.meta)
	if err != nil {
		return err
	}
	data, err := c.readTool()
	if err != nil {
		return err
	}
	f, err := c.toolFormat(data)
	if err != nil {
		return fmt.Errorf("%s: %w", c.tool, err)
	}
	rows, err := f.read(data)
	if err != nil {
		return fmt.Errorf("%s (%s): %w", c.tool, f.name, err)
	}
	if c.model != "" {
		if err := c.useModel(x); err != nil {
			return err
		}
	}
	if !c.toleranceSet {
		c.tolerance = f.resolution
	}
	fold := x.fold
	switch c.caseMode {
	case caseExact:
		fold = false
	case caseFold:
		fold = true
	}
	cats, paths, err := Score(x, rows, Options{
		Prefix: c.prefix, PrefixSet: c.prefixSet, Tolerance: c.tolerance,
		Fold: fold, Commas: f.name == "l2tcsv" || f.name == "dynamic",
	})
	if err != nil {
		return fmt.Errorf("%s: %w", c.tool, err)
	}
	sc := &Scorecard{
		Version: ScorecardVersion, ToolOutput: c.tool, Format: f.name, Meta: c.meta, Model: c.model,
		Tolerance: durationText(c.tolerance), Case: caseExact, Paths: paths,
		Ops: x.ops, SumsLines: x.sums,
	}
	if fold {
		sc.Case = caseFold
	}
	for _, cat := range cats {
		if slices.Contains(c.categories, cat.Name) {
			sc.Categories = append(sc.Categories, cat)
		}
	}
	sc.total()
	if c.scorecard != "" {
		if err := os.WriteFile(c.scorecard, sc.JSON(), 0o644); err != nil {
			return err
		}
	}
	sc.WriteText(c.stdout)
	if c.failUnderSet {
		if f1, ok := sc.Overall.F1.Value(); !ok || f1 < c.failUnder {
			fmt.Fprintf(c.stderr, "fsagen diff-oracle: overall F1 %s is below --fail-under %v\n", sc.Overall.F1, c.failUnder)
			return errBelow
		}
	}
	return nil
}

func (c *config) readTool() ([]byte, error) {
	if c.tool == "-" {
		return io.ReadAll(c.stdin)
	}
	return os.ReadFile(c.tool)
}

func (c *config) toolFormat(data []byte) (format, error) {
	if c.format != "" {
		f, _ := formatNamed(c.format)
		return f, nil
	}
	return detect(data)
}

// useModel takes directory times from a modelled timeline of the run.
func (c *config) useModel(x *Expected) error {
	data, err := os.ReadFile(c.model)
	if err != nil {
		return err
	}
	f, err := detect(data)
	if err != nil {
		return fmt.Errorf("--model %s: %w", c.model, err)
	}
	rows, err := f.read(data)
	if err != nil {
		return fmt.Errorf("--model %s (%s): %w", c.model, f.name, err)
	}
	if err := x.UseModel(rows); err != nil {
		return fmt.Errorf("--model %s: %w", c.model, err)
	}
	return nil
}

// durationText writes a tolerance as Go does, but with "us" for
// microseconds, as --time-tolerance takes it, so the report stays ASCII.
func durationText(d time.Duration) string {
	return strings.ReplaceAll(d.String(), "µ", "u")
}

// Scorecard is the full result.
type Scorecard struct {
	Version    int    `json:"scorecard_version"`
	ToolOutput string `json:"tool_output"`
	Format     string `json:"format"`
	Meta       string `json:"meta"`
	Model      string `json:"model,omitempty"`
	// Ops and SumsLines say what the expected state was built from: the
	// ledger's finished operations and SHA256SUMS's lines.
	Ops        int         `json:"operations"`
	SumsLines  int         `json:"sha256sums_lines"`
	Tolerance  string      `json:"time_tolerance"`
	Case       string      `json:"case"`
	Paths      PathReport  `json:"paths"`
	Categories []*Category `json:"categories"`
	Overall    Overall     `json:"overall"`
}

// Overall sums the categories scored.
type Overall struct {
	TP        int   `json:"tp"`
	FP        int   `json:"fp"`
	FN        int   `json:"fn"`
	Precision Ratio `json:"precision"`
	Recall    Ratio `json:"recall"`
	F1        Ratio `json:"f1"`
}

func (sc *Scorecard) total() {
	o := &sc.Overall
	for _, c := range sc.Categories {
		o.TP, o.FP, o.FN = o.TP+c.TP, o.FP+c.FP, o.FN+c.FN
	}
	o.Precision, o.Recall, o.F1 = Ratio{o.TP, o.TP + o.FP}, Ratio{o.TP, o.TP + o.FN}, Ratio{2 * o.TP, 2*o.TP + o.FP + o.FN}
}

// JSON is the scorecard, indented, with a final newline.
func (sc *Scorecard) JSON() []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(sc)
	return b.Bytes()
}

// WriteText writes the report: where everything came from, a table of the
// categories, and the first few of what each got wrong.
func (sc *Scorecard) WriteText(w io.Writer) {
	p := sc.Paths
	fmt.Fprintf(w, "tool output  %s (%s, %d entries)\n", sc.ToolOutput, sc.Format, p.Rows)
	fmt.Fprintf(w, "expected     %s (%d operations, %d SHA256SUMS lines)\n", sc.Meta, sc.Ops, sc.SumsLines)
	if sc.Model != "" {
		fmt.Fprintf(w, "model        %s\n", sc.Model)
	}
	how := "given"
	if p.PrefixDetected {
		how = "detected"
	}
	fmt.Fprintf(w, "paths        output root %s (%s); outside it %d, volume files %d, $FILE_NAME records %d (not scored), old names %d\n",
		p.Prefix, how, p.OutsidePrefix, p.VolumeFiles, p.FilenameRecords, p.OldNames)
	names := "exactly"
	if sc.Case == caseFold {
		names = "ignoring case"
	}
	fmt.Fprintf(w, "matching     times within %s, names %s\n\n", sc.Tolerance, names)

	fmt.Fprintf(w, "%-10s %8s %8s %7s %7s %7s %9s %7s %7s\n", "category", "expected", "checked", "tp", "fp", "fn", "precision", "recall", "f1")
	for _, c := range sc.Categories {
		fmt.Fprintf(w, "%-10s %8d %8d %7d %7d %7d %9s %7s %7s\n", c.Name, c.Expected, c.Checked, c.TP, c.FP, c.FN, c.Precision, c.Recall, c.F1)
	}
	o := sc.Overall
	fmt.Fprintf(w, "%-10s %8s %8s %7d %7d %7d %9s %7s %7s\n", "overall", "", "", o.TP, o.FP, o.FN, o.Precision, o.Recall, o.F1)

	for _, c := range sc.Categories {
		list(w, c.Name+" missing", c.Missing, func(s string) string { return s })
		list(w, c.Name+" extra", c.Extra, func(e Extra) string { return fmt.Sprintf("line %d: %s: %s", e.Line, e.Path, e.Reason) })
		list(w, c.Name+" wrong", c.Wrong, func(e Wrong) string {
			found := e.Found
			if found == "" {
				found = "none reported"
			}
			return fmt.Sprintf("line %d: %s %s: expected %s, found %s", e.Line, e.Path, e.Field, e.Expected, found)
		})
	}
}

// list writes up to listLimit items under a heading.
func list[T any](w io.Writer, heading string, items []T, line func(T) string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s (%d):\n", heading, len(items))
	for i, it := range items {
		if i == listLimit {
			fmt.Fprintf(w, "  ... and %d more (the scorecard lists them all)\n", len(items)-listLimit)
			break
		}
		fmt.Fprintf(w, "  %s\n", line(it))
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: fsagen diff-oracle --meta DIR [OPTIONS] <tool-output>

Score what a forensic tool reports about a generated tree against what fsagen
made: the names present, deleted entries, named streams, times, digests and
links. <tool-output> is a file, or - for standard input.

  --meta DIR             the run's sidecar directory (<output>.fsagen); required
  --format F             %s
                         (default: detected from the first line)
  --model FILE           a modelled timeline of the same run (fsagen
                         --timeline-source modelled), for directory times
  --strip-prefix P       the path the tool gives the output root (default:
                         detected, as the prefix most paths share)
  --time-tolerance D     how far a time may be off and still match, such as
                         0, 100ns, 1us, 1s or 2s (default: the format's
                         resolution: 1s for bodyfile and l2tcsv, 1us for
                         dynamic and timesketch, 0 for jsonl and csv)
  --case MODE            auto (default: as the volume the run wrote to), exact
                         or fold
  --categories LIST      score only these, comma-separated: %s
  --scorecard FILE       also write the full scorecard as JSON
  --fail-under X         exit 3 when the overall F1 is below X (0 to 1)

Exit codes: 0 scored, 1 error, 2 bad command line, 3 below --fail-under.
`, strings.Join(FormatNames(), ", "), strings.Join(CategoryNames, ", "))
}
