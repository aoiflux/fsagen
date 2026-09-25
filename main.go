package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/ledger"
	libgenpkg "github.com/aoiflux/fsagen/libgen"
	manifestpkg "github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
	schemapkg "github.com/aoiflux/fsagen/schema"
	timelinepkg "github.com/aoiflux/fsagen/timeline"
)

// Exit codes.
const (
	exitOK      = 0
	exitRuntime = 1 // the input was understood but generation failed
	exitUsage   = 2 // the command line itself is wrong
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// capsOverride replaces the detected capability set. Tests use it to exercise
// a platform without named streams on any machine.
var capsOverride *compile.Caps

func capsOf(fsys *sandbox.FS) compile.Caps {
	if capsOverride != nil {
		return *capsOverride
	}
	return manifestpkg.Caps(fsys)
}

// usageError marks a problem with the command line rather than the input.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

type config struct {
	seed           int64
	manifest       string
	playbook       string
	generateSchema bool
	schemaOut      string
	bulk           int
	depth          int
	bulkStart      string
	timeline       string
	timelineFormat string
	timelineSource string
	hashLimit      int64
	varsFile       string
	vars           varList
	clean          bool
	intoExisting   bool
	validate       bool
	dryRun         bool
	version        bool
	onUnsupported  string
	allowNonport   bool
	allowExternal  bool
	meta           string
	out            string
}

// run is the whole command, separated from main so tests can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stdout)
		return exitOK
	}
	if err == nil {
		err = execute(cfg, stdout)
	}
	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "fsagen: %v\nRun 'fsagen -h' for usage.\n", err)
		return exitUsage
	default:
		fmt.Fprintf(stderr, "fsagen: %v\n", err)
		return exitRuntime
	}
}

func parseFlags(args []string) (*config, error) {
	c := &config{}
	fl := flag.NewFlagSet("fsagen", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	fl.Int64Var(&c.seed, "seed", 1, "PRNG seed for deterministic generation")
	fl.StringVar(&c.manifest, "manifest", "", "YAML manifest of operations")
	fl.StringVar(&c.playbook, "playbook", "", "YAML playbook of actors and timed steps")
	fl.BoolVar(&c.generateSchema, "generate-schema", false, "write JSON schemas for manifests and playbooks and exit")
	fl.StringVar(&c.schemaOut, "schema-out", "schemas", "output directory for --generate-schema")
	fl.IntVar(&c.bulk, "bulk", 0, "bulk generation: items per level")
	fl.IntVar(&c.depth, "depth", 1, "bulk generation: directory depth")
	fl.StringVar(&c.bulkStart, "bulk-start", "", "bulk generation: RFC 3339 reference time for dates inside files (default 2021-01-01T00:00:00Z)")
	fl.StringVar(&c.timeline, "timeline", "", "write a timeline of the output tree to this file (outside the tree)")
	fl.StringVar(&c.timelineFormat, "timeline-format", "", "timeline format: csv, txt, bodyfile, macb or jsonl (default: from the extension)")
	fl.StringVar(&c.timelineSource, "timeline-source", "", "timeline source: observed (read back from disk, the default) or modelled (what the scenario intends, including deleted objects)")
	fl.Int64Var(&c.hashLimit, "hash-limit", 0, "observed timeline: skip the MD5 of files and streams larger than this many bytes (default: hash everything)")
	fl.StringVar(&c.varsFile, "vars-file", "", "YAML map of variables exposed as ${VAR:name}")
	fl.Var(&c.vars, "var", "set a variable as key=value (repeatable; overrides --vars-file)")
	fl.BoolVar(&c.clean, "clean", false, "empty a non-empty output directory before generating")
	fl.BoolVar(&c.intoExisting, "into-existing", false, "generate into a non-empty output directory, merging (recorded)")
	fl.BoolVar(&c.validate, "validate", false, "check the manifest or playbook and exit without writing")
	fl.BoolVar(&c.dryRun, "dry-run", false, "print the compiled operations as JSON lines and exit without writing")
	fl.BoolVar(&c.version, "version", false, "print version information and exit")
	fl.StringVar(&c.onUnsupported, "on-unsupported", "fail", "operations the platform cannot perform: fail (before writing) or skip (and record)")
	fl.BoolVar(&c.allowNonport, "allow-nonportable", false, "allow paths that only work on some platforms")
	fl.BoolVar(&c.allowExternal, "allow-external-sources", false, "allow content_file and friends outside the YAML file's directory")
	fl.StringVar(&c.meta, "meta", "", "directory for the run manifest (default: <output>.fsagen)")

	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}
	switch rest := fl.Args(); len(rest) {
	case 0:
	case 1:
		c.out = rest[0]
	default:
		return nil, usagef("unexpected argument %q after the output path (flags must come before it)", rest[1])
	}
	return c, nil
}

func execute(c *config, stdout io.Writer) error {
	if c.version {
		printVersion(stdout)
		return nil
	}
	if c.generateSchema {
		m, p, err := writeInputSchemas(c.schemaOut)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Manifest schema written to: %s\nPlaybook schema written to: %s\n", m, p)
		return nil
	}

	modes := 0
	for _, set := range []bool{c.manifest != "", c.playbook != "", c.bulk != 0} {
		if set {
			modes++
		}
	}
	switch {
	case modes > 1:
		return usagef("give only one of --manifest, --playbook and --bulk")
	case c.bulk < 0:
		return usagef("--bulk must be positive")
	case c.bulk > 0 && c.depth < 1:
		return usagef("--depth must be at least 1")
	case c.clean && c.intoExisting:
		return usagef("--clean and --into-existing contradict each other")
	case c.onUnsupported != "fail" && c.onUnsupported != "skip":
		return usagef("--on-unsupported must be fail or skip, not %q", c.onUnsupported)
	case (c.validate || c.dryRun) && c.manifest == "" && c.playbook == "":
		return usagef("--validate and --dry-run need --manifest or --playbook")
	case (c.validate || c.dryRun) && c.timeline != "":
		return usagef("--validate and --dry-run do not write a timeline")
	case c.timelineFormat != "" && c.timeline == "":
		return usagef("--timeline-format needs --timeline")
	case c.timelineSource != "" && c.timeline == "":
		return usagef("--timeline-source needs --timeline")
	case c.timelineSource != "" && c.timelineSource != timelinepkg.SourceObserved && c.timelineSource != timelinepkg.SourceModelled:
		return usagef("--timeline-source must be observed or modelled, not %q", c.timelineSource)
	case c.timelineSource == timelinepkg.SourceModelled && c.manifest == "" && c.playbook == "":
		return usagef("--timeline-source=modelled describes what a manifest or playbook intends; it needs --manifest or --playbook (bulk mode and timeline-only mode have no model)")
	case c.hashLimit < 0:
		return usagef("--hash-limit must not be negative")
	case c.hashLimit != 0 && c.timeline == "":
		return usagef("--hash-limit needs --timeline")
	case c.hashLimit != 0 && c.timelineSource == timelinepkg.SourceModelled:
		return usagef("--hash-limit applies to observed timelines; a modelled timeline takes its digests from the ledger")
	case c.bulkStart != "" && c.bulk == 0:
		return usagef("--bulk-start needs --bulk")
	}
	if c.bulkStart != "" {
		if _, err := time.Parse(time.RFC3339, c.bulkStart); err != nil {
			return usagef("--bulk-start %q is not an RFC 3339 time", c.bulkStart)
		}
	}

	var tl *timelineRequest
	if c.timeline != "" {
		format, err := timelineFormat(c.timelineFormat, c.timeline)
		if err != nil {
			return err
		}
		source := c.timelineSource
		if source == "" {
			source = timelinepkg.SourceObserved
		}
		tl = &timelineRequest{file: c.timeline, format: format, source: source, hashLimit: c.hashLimit}
	}

	vars, varsInput, err := loadVariables(c.varsFile, c.vars)
	if err != nil {
		return err
	}

	if c.validate || c.dryRun {
		return check(c, vars, stdout)
	}

	if c.out == "" {
		if modes == 0 && c.timeline == "" {
			return usagef("nothing to do: give --manifest, --playbook or --bulk and an output path (or --timeline alone for timeline-only mode)")
		}
		return usagef("missing output path")
	}
	absOut, err := filepath.Abs(c.out)
	if err != nil {
		return err
	}
	if c.timeline != "" {
		if err := outside(c.timeline, absOut, "the timeline"); err != nil {
			return err
		}
	}

	if modes == 0 {
		// Timeline-only mode describes an existing tree; it never creates one.
		info, err := os.Stat(absOut)
		if err != nil {
			return fmt.Errorf("timeline-only mode needs an existing directory: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("timeline-only mode needs a directory, and %s is a file", absOut)
		}
		fmt.Fprintf(stdout, "Scanning existing artifacts in %s...\n", absOut)
		_, err = tl.write(stdout, absOut, nil)
		return err
	}

	return generate(c, absOut, vars, varsInput, tl, stdout)
}

// check implements --validate and --dry-run: compile, simulate and
// pre-flight, then report without writing anything.
func check(c *config, vars map[string]string, stdout io.Writer) error {
	opts := compile.Options{Vars: vars, Seed: c.seed, AllowExternalSources: c.allowExternal, AllowNonportable: c.allowNonport}
	caps := compile.DefaultCaps()
	if capsOverride != nil {
		caps = *capsOverride
	}
	if c.out != "" && c.intoExisting {
		fsys, err := sandbox.Open(c.out)
		if err != nil {
			return err
		}
		defer fsys.Close()
		if opts.Existing, err = seedModel(fsys); err != nil {
			return err
		}
		caps = capsOf(fsys)
	}
	prog, err := compile.Load(inputMode(c), inputFile(c), opts)
	if err != nil {
		return err
	}
	defer prog.Close()
	if err := compile.Preflight(prog, caps, c.onUnsupported == "skip"); err != nil {
		return err
	}
	if c.dryRun {
		return compile.WriteDryRun(stdout, prog)
	}
	fmt.Fprintf(stdout, "%s: %d operations, valid\n", inputFile(c), len(prog.Ops))
	return nil
}

func inputMode(c *config) compile.Mode {
	if c.manifest != "" {
		return compile.ModeManifest
	}
	return compile.ModePlaybook
}

func inputFile(c *config) string {
	if c.manifest != "" {
		return c.manifest
	}
	return c.playbook
}

// generate prepares the output root, compiles and checks the input, and only
// then writes, recording the run beside the root.
func generate(c *config, absOut string, vars map[string]string, varsInput *sandbox.Input, tl *timelineRequest, stdout io.Writer) error {
	metaDir := c.meta
	if metaDir == "" {
		metaDir = absOut + ".fsagen"
	}
	metaDir, err := filepath.Abs(metaDir)
	if err != nil {
		return err
	}
	if err := outside(metaDir, absOut, "the run manifest directory (--meta)"); err != nil {
		return err
	}
	if err := outside(absOut, metaDir, "the output directory"); err != nil {
		return err
	}

	info, statErr := os.Stat(absOut)
	switch {
	case statErr == nil && !info.IsDir():
		return fmt.Errorf("output path %s is a file, not a directory", absOut)
	case statErr != nil && !os.IsNotExist(statErr):
		return statErr
	}
	exists := statErr == nil

	// Everything is checked before anything is written, including the output
	// directory itself. Capabilities come from the volume the output will
	// live on: the directory, or its nearest existing ancestor.
	probeDir := absOut
	if !exists {
		probeDir = nearestExisting(absOut)
	}
	probe, err := sandbox.Open(probeDir)
	if err != nil {
		return err
	}
	defer probe.Close()
	caps := capsOf(probe)

	empty := true
	var existing *model.Tree
	if exists {
		if empty, err = probe.Empty(); err != nil {
			return err
		}
		if !empty && !c.clean && !c.intoExisting {
			return fmt.Errorf("output directory %s is not empty; pass --clean to empty it first, or --into-existing to merge into it (recorded in the run manifest)", absOut)
		}
		if c.intoExisting {
			if existing, err = seedModel(probe); err != nil {
				return err
			}
		}
	}

	mode := "bulk"
	if c.manifest != "" || c.playbook != "" {
		mode = string(inputMode(c))
	}
	rm := runinfo.New(mode, c.seed)
	rm.VarsFile = varsInput
	rm.CLIVarsSHA256 = cliVarsHash(c.vars)
	rm.Options = runinfo.Options{
		Clean:                c.clean,
		IntoExisting:         c.intoExisting,
		OnUnsupported:        c.onUnsupported,
		AllowNonportable:     c.allowNonport,
		AllowExternalSources: c.allowExternal,
	}
	rm.Capabilities = runinfo.Capabilities{NamedStreams: caps.NamedStreams, BirthTime: caps.BirthTime, ChangeTime: caps.ChangeTime}
	rinfo := runinfo.NewInfo()
	rinfo.Filesystem = probe.FilesystemName()
	rinfo.LastAccess = runinfo.LastAccessPolicy()
	rinfo.Output = absOut
	rinfo.Started = time.Now().UTC().Format(time.RFC3339Nano)
	if c.intoExisting {
		rm.Reproducible = false
	}

	var prog *compile.Program
	if mode != "bulk" {
		opts := compile.Options{Vars: vars, Seed: c.seed, AllowExternalSources: c.allowExternal, AllowNonportable: c.allowNonport, Existing: existing}
		if prog, err = compile.Load(inputMode(c), inputFile(c), opts); err != nil {
			return err
		}
		defer prog.Close()
		if err := compile.Preflight(prog, caps, c.onUnsupported == "skip"); err != nil {
			return err
		}
		rm.Input = &sandbox.Input{Path: filepath.Base(prog.File), SHA256: prog.SHA256}
		if rinfo.Input, err = filepath.Abs(prog.File); err != nil {
			return err
		}
		rm.Operations = len(prog.Ops)
		if prog.StartNow {
			rm.Reproducible = false
		}
		for i, op := range prog.Ops {
			src := op.Src
			src.File = filepath.Base(src.File)
			if op.Skip != "" {
				rm.Skipped = append(rm.Skipped, runinfo.Skipped{Op: i + 1, Src: src.String(), Action: op.Action, Path: op.Path, Reason: op.Skip})
			}
			for _, f := range op.Dropped {
				rm.Skipped = append(rm.Skipped, runinfo.Skipped{Op: i + 1, Src: src.String(), Action: op.Action, Path: op.Path, Field: f, Reason: f + " cannot be set on this platform or volume"})
			}
		}
	} else {
		rm.Options.Bulk, rm.Options.Depth = c.bulk, c.depth
		rm.Options.BulkStart = libgenpkg.DefaultStart.Format(time.RFC3339)
		if c.bulkStart != "" {
			rm.Options.BulkStart = c.bulkStart
		}
	}

	fsys := probe
	if !exists {
		if err := os.MkdirAll(absOut, sandbox.DirMode); err != nil {
			return err
		}
		if fsys, err = sandbox.Open(absOut); err != nil {
			return err
		}
		defer fsys.Close()
	}
	if c.clean && !empty {
		if err := fsys.RemoveContents(); err != nil {
			return fmt.Errorf("clean %s: %w", absOut, err)
		}
	}
	if err := rm.Write(metaDir); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	if err := rinfo.Write(metaDir); err != nil {
		return fmt.Errorf("write run info: %w", err)
	}

	fmt.Fprintln(stdout, "Generating artifacts...")
	var (
		ectx      manifestpkg.ExecContext
		ledgerSum string
		entries   []ledger.Entry
	)
	if mode == "bulk" {
		start, _ := time.Parse(time.RFC3339, rm.Options.BulkStart)
		err = libgenpkg.Generate(fsys, c.bulk, c.depth, libgenpkg.Options{Seed: c.seed, Start: start})
	} else {
		ectx = manifestpkg.ExecContext{FS: fsys, Sources: prog.Sources, Caps: caps}
		entries, err = manifestpkg.Execute(ectx, prog.Ops)
		rm.Sources = prog.Sources.Inputs()
		// The ledger is written even when the run fails: it says how far the
		// run got.
		sum, lerr := runinfo.WriteLedger(metaDir, entries)
		if lerr != nil && err == nil {
			err = fmt.Errorf("write %s: %w", ledger.FileName, lerr)
		}
		ledgerSum = sum
	}
	// Digests are read before the settle pass, which puts back any access
	// time the reads moved.
	if err == nil {
		var out runinfo.Outputs
		if out, err = runinfo.WriteSums(metaDir, fsys); err == nil {
			out.Ledger = ledgerSum
			rm.Outputs = &out
		} else {
			err = fmt.Errorf("write %s: %w", runinfo.SumsFileName, err)
		}
	}
	if err == nil && mode != "bulk" {
		err = manifestpkg.SettleAndVerify(ectx, prog.Model)
	}
	// The answer key describes a finished scenario, so a failed run has
	// none; the ledger says how far it got.
	if err == nil && mode != "bulk" {
		sum, kerr := runinfo.WriteAnswerKey(metaDir, manifestpkg.AnswerKey(prog.Model, entries, caps))
		if kerr != nil {
			err = fmt.Errorf("write %s: %w", ledger.AnswerKeyFileName, kerr)
		}
		rm.Outputs.AnswerKey = sum
	}
	rinfo.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	if ierr := rinfo.Write(metaDir); ierr != nil && err == nil {
		err = fmt.Errorf("write run info: %w", ierr)
	}
	if err != nil {
		rm.Status, rm.Failure = runinfo.StatusFailed, err.Error()
		if werr := rm.Write(metaDir); werr != nil {
			return fmt.Errorf("%w (and the run manifest could not be updated: %v)", err, werr)
		}
		return fmt.Errorf("%w\nthe output in %s is incomplete; its run manifest says so", err, absOut)
	}
	rm.Status = runinfo.StatusComplete
	if err := rm.Write(metaDir); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	if len(rm.Skipped) > 0 {
		fmt.Fprintf(stdout, "Skipped %d unsupported operation(s); see %s\n", len(rm.Skipped), filepath.Join(metaDir, runinfo.FileName))
	}
	fmt.Fprintln(stdout, "Done!")

	if tl == nil {
		return nil
	}
	// The timeline comes after the run is recorded complete: the output is
	// finished whether or not the timeline can be written.
	var modelled *timelinepkg.Timeline
	if tl.source == timelinepkg.SourceModelled {
		modelled = manifestpkg.ModelledTimeline(prog.Model, entries, caps)
	}
	rec, err := tl.write(stdout, absOut, modelled)
	if err != nil {
		return fmt.Errorf("%w (the output in %s is complete; only the timeline is missing)", err, absOut)
	}
	rm.Timeline = rec
	if err := rm.Write(metaDir); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	return nil
}

// nearestExisting returns the closest ancestor of p that exists.
func nearestExisting(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

// seedModel loads an existing tree into a model for --into-existing.
func seedModel(fsys *sandbox.FS) (*model.Tree, error) {
	t := model.New()
	err := fsys.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		kind := model.File
		if d.IsDir() {
			kind = model.Dir
		}
		t.Add(path.Clean(name), kind)
		if streams, err := fsys.Streams(name); err == nil {
			for _, s := range streams {
				_ = t.AddStream(name, s.Name)
			}
		}
		return nil
	})
	return t, err
}

// outside refuses a path that lies inside (or is) root.
func outside(p, root, what string) error {
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, abs)
	if err == nil && (rel == "." || filepath.IsLocal(rel)) {
		return usagef("%s (%s) must be outside the output directory %s, or it would become part of the evidence it describes", what, abs, root)
	}
	return nil
}

var timelineExtensions = map[string]string{
	".csv":      "csv",
	".txt":      "txt",
	".bodyfile": "bodyfile",
	".body":     "bodyfile",
	".macb":     "macb",
	".jsonl":    "jsonl",
}

// timelineFormat picks the timeline format from the flag, or else from the
// file extension. An extension it does not know is an error, never a silent
// fall-back to CSV.
func timelineFormat(flagValue, file string) (string, error) {
	if flagValue != "" {
		if slices.Contains(timelinepkg.Formats, flagValue) {
			return flagValue, nil
		}
		return "", usagef("unknown --timeline-format %q (want csv, txt, bodyfile, macb or jsonl)", flagValue)
	}
	ext := strings.ToLower(filepath.Ext(file))
	if f, ok := timelineExtensions[ext]; ok {
		return f, nil
	}
	return "", usagef("cannot tell the timeline format from %q; use .csv, .txt, .bodyfile, .body, .macb or .jsonl, or pass --timeline-format", file)
}

// timelineRequest is a --timeline and the flags that shape it.
type timelineRequest struct {
	file, format, source string
	hashLimit            int64
}

// write writes the timeline: modelled when one is given, else observed
// from root. The whole timeline is built before the file is created, so a
// failure leaves no partial timeline behind.
func (r *timelineRequest) write(stdout io.Writer, root string, modelled *timelinepkg.Timeline) (*runinfo.Timeline, error) {
	fmt.Fprintf(stdout, "\nGenerating %s timeline...\n", r.source)
	tl := modelled
	if tl == nil {
		var err error
		if tl, err = timelinepkg.Generate(root, timelinepkg.Options{HashLimit: r.hashLimit}); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := tl.Write(&buf, r.format); err != nil {
		return nil, fmt.Errorf("write timeline: %w", err)
	}
	if err := os.WriteFile(r.file, buf.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("write timeline: %w", err)
	}
	fmt.Fprintf(stdout, "Timeline written to: %s\n", r.file)
	rec := &runinfo.Timeline{Source: r.source, Format: r.format, File: filepath.Base(r.file), HashLimit: r.hashLimit}
	if r.source == timelinepkg.SourceModelled {
		rec.SHA256 = runinfo.Digest(buf.Bytes())
	}
	return rec, nil
}

func printVersion(w io.Writer) {
	module, rev, modified := runinfo.Build()
	extra := ""
	if rev != "" {
		extra = ", " + rev
		if modified {
			extra += "+modified"
		}
	}
	fmt.Fprintf(w, "fsagen %s (generator version %d%s) %s %s/%s\n", module, constant.GeneratorVersion, extra, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: fsagen [OPTIONS] <output-path>

Generate deterministic filesystem artifacts for forensic testing.

Input (give one):
  --manifest FILE           YAML manifest of operations
  --playbook FILE           YAML playbook of actors and timed steps
  --bulk N --depth D        bulk generation: N items per level, D levels deep
  --bulk-start T            bulk generation: RFC 3339 time the dates inside
                            files count from (default 2021-01-01T00:00:00Z)

Generation:
  --seed N                  PRNG seed (default 1)
  --vars-file FILE          YAML map of variables exposed as ${VAR:name}
  --var k=v                 set one variable (repeatable; overrides --vars-file)
  --clean                   empty a non-empty output directory first
  --into-existing           merge into a non-empty output directory (recorded)
  --on-unsupported MODE     fail (default: refuse before writing) or skip
                            (generate the rest and record each skipped operation)
  --allow-nonportable       allow paths that only work on some platforms
  --allow-external-sources  allow content_file etc. outside the YAML's directory
  --meta DIR                where to write run-manifest.json, SHA256SUMS,
                            ledger.jsonl, answer-key.jsonl and run-info.json
                            (default: <output-path>.fsagen, beside the output)

Checking without writing:
  --validate                check the input and exit
  --dry-run                 print the compiled operations as JSON lines

Timeline:
  --timeline FILE           write a timeline of the output (FILE must be
                            outside the output directory)
  --timeline-format F       csv, txt, bodyfile, macb or jsonl (default: from
                            the extension: .csv .txt .bodyfile .body .macb
                            .jsonl)
  --timeline-source S       observed (default): read back from the output;
                            modelled: what the scenario intends, including
                            deleted objects, the same bytes on every run
                            (needs --manifest or --playbook)
  --hash-limit N            observed timeline: no MD5 for files and streams
                            over N bytes (default: hash everything)
  If --timeline is given without an input, fsagen only scans the existing
  directory and writes an observed timeline (timeline-only mode).

Other:
  --generate-schema         write JSON schemas and exit (--schema-out DIR,
                            default schemas)
  --version                 print version information

Exit status: 0 success, 1 generation failed, 2 command-line error.

Examples:
  fsagen --seed 42 --manifest basic.yaml ./output
  fsagen --seed 100 --playbook adversary.yaml --timeline case.bodyfile ./scene
  fsagen --playbook adversary.yaml --dry-run
  fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk
  fsagen --timeline existing.csv ./existing-artifacts
`)
}

func writeInputSchemas(outputDir string) (string, string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", "", fmt.Errorf("schema output directory cannot be empty")
	}
	if strings.EqualFold(filepath.Ext(outputDir), ".json") {
		outputDir = filepath.Dir(outputDir)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", "", fmt.Errorf("prepare schema output directory: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "manifest-schema.json")
	playbookPath := filepath.Join(outputDir, "playbook-schema.json")

	manifestSchema, err := schemapkg.BuildManifestSchema()
	if err != nil {
		return "", "", fmt.Errorf("build manifest schema: %w", err)
	}
	playbookSchema, err := schemapkg.BuildPlaybookSchema()
	if err != nil {
		return "", "", fmt.Errorf("build playbook schema: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestSchema, 0o644); err != nil {
		return "", "", fmt.Errorf("write manifest schema: %w", err)
	}
	if err := os.WriteFile(playbookPath, playbookSchema, 0o644); err != nil {
		return "", "", fmt.Errorf("write playbook schema: %w", err)
	}
	return manifestPath, playbookPath, nil
}

// varList collects repeated --var key=value flags.
type varList []string

func (v *varList) String() string { return strings.Join(*v, ",") }

func (v *varList) Set(s string) error {
	if _, _, err := render.ParseVarAssignment(s); err != nil {
		return err
	}
	*v = append(*v, s)
	return nil
}

// loadVariables merges a --vars-file with any --var overrides. Command-line
// values win, so one persona file can drive every scenario while a single value
// is overridden per run.
func loadVariables(varsFile string, overrides varList) (map[string]string, *sandbox.Input, error) {
	vars := map[string]string{}
	var input *sandbox.Input

	if strings.TrimSpace(varsFile) != "" {
		data, err := os.ReadFile(varsFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read vars file: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&vars); err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, fmt.Errorf("parse vars file %s (expected a flat map of key: value): %w", varsFile, err)
		}
		sum := sha256.Sum256(data)
		input = &sandbox.Input{Path: filepath.Base(varsFile), SHA256: hex.EncodeToString(sum[:])}
	}

	for _, assignment := range overrides {
		k, val, err := render.ParseVarAssignment(assignment)
		if err != nil {
			return nil, nil, err
		}
		vars[k] = val
	}
	return vars, input, nil
}

// cliVarsHash identifies the --var values without recording them: they can
// hold secrets such as a vault password.
func cliVarsHash(vars varList) string {
	if len(vars) == 0 {
		return ""
	}
	sorted := append([]string(nil), vars...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return hex.EncodeToString(sum[:])
}
