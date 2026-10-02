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

// The values --on-unsupported takes: refuse the run before writing anything, or
// generate what this platform can and record each operation left out.
const (
	onUnsupportedFail = "fail"
	onUnsupportedSkip = "skip"
)

// modeBulk names bulk generation in the run record. It is not a compile mode:
// a bulk corpus is generated directly, with no input file to compile.
const modeBulk = "bulk"

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
	// capsFor reports what the volume under a root can do. The command uses the
	// real detection; a test injects a fixed set to exercise a platform it is
	// not running on.
	capsFor func(*sandbox.FS) compile.Caps
}

// run is the whole command, separated from main so tests can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	return runWithCaps(args, stdout, stderr, manifestpkg.Caps)
}

// runWithCaps is run with capability detection injected, so a test can exercise
// a platform it is not running on without a package-level switch.
func runWithCaps(args []string, stdout, stderr io.Writer, capsFor func(*sandbox.FS) compile.Caps) int {
	cfg, err := parseFlags(args)
	if cfg != nil {
		cfg.capsFor = capsFor
	}
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
	fl.StringVar(&c.onUnsupported, "on-unsupported", onUnsupportedFail, "operations the platform cannot perform: fail (before writing) or skip (and record)")
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
	if err := validateFlags(c); err != nil {
		return err
	}

	tl, err := timelineRequestFrom(c)
	if err != nil {
		return err
	}
	vars, varsInput, err := loadVariables(c.varsFile, c.vars)
	if err != nil {
		return err
	}
	if c.checkOnly() {
		return check(c, vars, stdout)
	}
	return writeOutput(c, tl, vars, varsInput, stdout)
}

// checkOnly reports whether the run only inspects its input and writes nothing.
func (c *config) checkOnly() bool { return c.validate || c.dryRun }

// bulkMode reports whether the run generates a bulk corpus rather than
// compiling an input file.
func (c *config) bulkMode() bool { return c.manifest == "" && c.playbook == "" }

// inputModes counts the ways of describing the work that were given. Exactly
// one is needed, except in timeline-only mode, which gives none.
func inputModes(c *config) int {
	n := 0
	for _, given := range []bool{c.manifest != "", c.playbook != "", c.bulk != 0} {
		if given {
			n++
		}
	}
	return n
}

// validateFlags rejects a command line whose flags contradict each other, before
// anything is read or written.
func validateFlags(c *config) error {
	switch {
	case inputModes(c) > 1:
		return usagef("give only one of --manifest, --playbook and --bulk")
	case c.bulk < 0:
		return usagef("--bulk must be positive")
	case c.bulk > 0 && c.depth < 1:
		return usagef("--depth must be at least 1")
	case c.clean && c.intoExisting:
		return usagef("--clean and --into-existing contradict each other")
	case c.onUnsupported != onUnsupportedFail && c.onUnsupported != onUnsupportedSkip:
		return usagef("--on-unsupported must be fail or skip, not %q", c.onUnsupported)
	case c.checkOnly() && c.manifest == "" && c.playbook == "":
		return usagef("--validate and --dry-run need --manifest or --playbook")
	case c.checkOnly() && c.timeline != "":
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
	return nil
}

// timelineRequestFrom settles which timeline to write, if any.
func timelineRequestFrom(c *config) (*timelineRequest, error) {
	if c.timeline == "" {
		return nil, nil
	}
	format, err := timelineFormat(c.timelineFormat, c.timeline)
	if err != nil {
		return nil, err
	}
	source := c.timelineSource
	if source == "" {
		source = timelinepkg.SourceObserved
	}
	return &timelineRequest{file: c.timeline, format: format, source: source, hashLimit: c.hashLimit}, nil
}

// writeOutput generates a tree, or, when no input was given, describes one that
// is already there.
func writeOutput(c *config, tl *timelineRequest, vars map[string]string, varsInput *sandbox.Input, stdout io.Writer) error {
	if c.out == "" {
		if inputModes(c) == 0 && c.timeline == "" {
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
	if inputModes(c) == 0 {
		return scanExisting(absOut, tl, stdout)
	}
	return generate(c, absOut, vars, varsInput, tl, stdout)
}

// scanExisting is timeline-only mode: it describes a tree that already exists
// and never creates one.
func scanExisting(absOut string, tl *timelineRequest, stdout io.Writer) error {
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

// check implements --validate and --dry-run: compile, simulate and
// pre-flight, then report without writing anything.
func check(c *config, vars map[string]string, stdout io.Writer) error {
	opts := compile.Options{Vars: vars, Seed: c.seed, AllowExternalSources: c.allowExternal, AllowNonportable: c.allowNonport}
	caps := compile.DefaultCaps()
	if c.out != "" && c.intoExisting {
		fsys, err := sandbox.Open(c.out)
		if err != nil {
			return err
		}
		defer fsys.Close()
		if opts.Existing, err = seedModel(fsys); err != nil {
			return err
		}
		caps = c.capsFor(fsys)
	}
	prog, err := compile.Load(inputMode(c), inputFile(c), opts)
	if err != nil {
		return err
	}
	defer prog.Close()
	if err := compile.Preflight(prog, caps, c.onUnsupported == onUnsupportedSkip); err != nil {
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
	metaDir, err := resolveMetaDir(c.meta, absOut)
	if err != nil {
		return err
	}
	exists, err := outputExists(absOut)
	if err != nil {
		return err
	}

	// Everything is checked before anything is written, including the output
	// directory itself. Capabilities come from the volume the output will
	// live on: the directory, or its nearest existing ancestor.
	probe, err := openProbe(absOut, exists)
	if err != nil {
		return err
	}
	defer probe.Close()
	caps := c.capsFor(probe)

	empty, existing, err := inspectExisting(c, probe, exists, absOut)
	if err != nil {
		return err
	}
	rm, rinfo := newRecords(c, varsInput, caps, probe, absOut)

	var prog *compile.Program
	if c.bulkMode() {
		recordBulkOptions(rm, c)
	} else {
		if prog, err = compileInput(c, vars, existing, caps); err != nil {
			return err
		}
		defer prog.Close()
		if err := recordProgram(rm, rinfo, prog); err != nil {
			return err
		}
	}

	fsys, err := openOutput(absOut, exists, probe)
	if err != nil {
		return err
	}
	if fsys != probe {
		defer fsys.Close()
	}
	if c.clean && !empty {
		if err := fsys.RemoveContents(); err != nil {
			return fmt.Errorf("clean %s: %w", absOut, err)
		}
	}
	if err := writeRecords(metaDir, rm, rinfo); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Generating artifacts...")
	g := runGeneration(c, fsys, prog, caps, rm, metaDir)

	rinfo.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	if ierr := rinfo.Write(metaDir); ierr != nil && g.err == nil {
		g.err = fmt.Errorf("write run info: %w", ierr)
	}
	if g.err != nil {
		return recordFailure(metaDir, rm, g.err, absOut)
	}
	if err := recordSuccess(metaDir, rm, stdout); err != nil {
		return err
	}

	var modelled *timelinepkg.Timeline
	if tl != nil && tl.source == timelinepkg.SourceModelled {
		modelled = manifestpkg.ModelledTimeline(prog.Model, g.entries, caps)
	}
	return writeTimeline(tl, modelled, rm, metaDir, absOut, stdout)
}

// metaDirSuffix names the default run-record directory, beside the output.
const metaDirSuffix = ".fsagen"

// resolveMetaDir settles where the run's records go. The records and the output
// must not contain one another, or the evidence would describe itself.
func resolveMetaDir(meta, absOut string) (string, error) {
	if meta == "" {
		meta = absOut + metaDirSuffix
	}
	metaDir, err := filepath.Abs(meta)
	if err != nil {
		return "", err
	}
	if err := outside(metaDir, absOut, "the run manifest directory (--meta)"); err != nil {
		return "", err
	}
	if err := outside(absOut, metaDir, "the output directory"); err != nil {
		return "", err
	}
	return metaDir, nil
}

// outputExists reports whether the output directory is already there, refusing
// a path that names a file.
func outputExists(absOut string) (bool, error) {
	info, err := os.Stat(absOut)
	switch {
	case err == nil && !info.IsDir():
		return false, fmt.Errorf("output path %s is a file, not a directory", absOut)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	return err == nil, nil
}

// openProbe opens the volume the output will live on, so what it can do is known
// before anything is written.
func openProbe(absOut string, exists bool) (*sandbox.FS, error) {
	dir := absOut
	if !exists {
		dir = nearestExisting(absOut)
	}
	return sandbox.Open(dir)
}

// inspectExisting reports whether the output directory is empty and, for
// --into-existing, models what is already in it.
func inspectExisting(c *config, probe *sandbox.FS, exists bool, absOut string) (bool, *model.Tree, error) {
	if !exists {
		return true, nil, nil
	}
	empty, err := probe.Empty()
	if err != nil {
		return false, nil, err
	}
	if !empty && !c.clean && !c.intoExisting {
		return false, nil, fmt.Errorf("output directory %s is not empty; pass --clean to empty it first, or --into-existing to merge into it (recorded in the run manifest)", absOut)
	}
	if !c.intoExisting {
		return empty, nil, nil
	}
	existing, err := seedModel(probe)
	return empty, existing, err
}

// runMode names what this run generates from, for its record.
func runMode(c *config) string {
	if c.bulkMode() {
		return modeBulk
	}
	return string(inputMode(c))
}

// newRecords starts the two records kept beside the output: what the run was
// asked to do, and the environment it ran in.
func newRecords(c *config, varsInput *sandbox.Input, caps compile.Caps, probe *sandbox.FS, absOut string) (*runinfo.Manifest, *runinfo.Info) {
	rm := runinfo.New(runMode(c), c.seed)
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
	// Merging into a tree this run did not create cannot be reproduced from the
	// input alone.
	rm.Reproducible = !c.intoExisting

	rinfo := runinfo.NewInfo()
	rinfo.Filesystem = probe.FilesystemName()
	rinfo.LastAccess = runinfo.LastAccessPolicy()
	rinfo.Output = absOut
	rinfo.Started = time.Now().UTC().Format(time.RFC3339Nano)
	return rm, rinfo
}

// compileInput loads the input and checks it against this platform, so a run
// that cannot be performed here fails before it writes anything.
func compileInput(c *config, vars map[string]string, existing *model.Tree, caps compile.Caps) (*compile.Program, error) {
	opts := compile.Options{Vars: vars, Seed: c.seed, AllowExternalSources: c.allowExternal, AllowNonportable: c.allowNonport, Existing: existing}
	prog, err := compile.Load(inputMode(c), inputFile(c), opts)
	if err != nil {
		return nil, err
	}
	if err := compile.Preflight(prog, caps, c.onUnsupported == onUnsupportedSkip); err != nil {
		prog.Close()
		return nil, err
	}
	return prog, nil
}

// recordProgram notes which input the run compiled and what it left out.
func recordProgram(rm *runinfo.Manifest, rinfo *runinfo.Info, prog *compile.Program) error {
	rm.Input = &sandbox.Input{Path: filepath.Base(prog.File), SHA256: prog.SHA256}
	abs, err := filepath.Abs(prog.File)
	if err != nil {
		return err
	}
	rinfo.Input = abs
	rm.Operations = len(prog.Ops)
	if prog.StartNow {
		// A start of "now" cannot be reproduced.
		rm.Reproducible = false
	}
	rm.Skipped = skippedOps(prog.Ops)
	return nil
}

// skippedOps lists the operations, and the single fields, that this platform
// cannot carry out and the run was told to skip rather than fail on.
func skippedOps(ops []compile.Op) []runinfo.Skipped {
	var out []runinfo.Skipped
	for i, op := range ops {
		src := op.Src
		src.File = filepath.Base(src.File)
		if op.Skip != "" {
			out = append(out, runinfo.Skipped{Op: i + 1, Src: src.String(), Action: op.Action, Path: op.Path, Reason: op.Skip})
		}
		for _, f := range op.Dropped {
			out = append(out, runinfo.Skipped{Op: i + 1, Src: src.String(), Action: op.Action, Path: op.Path, Field: f, Reason: f + " cannot be set on this platform or volume"})
		}
	}
	return out
}

// recordBulkOptions notes the shape of a bulk corpus and the time its dates
// count from.
func recordBulkOptions(rm *runinfo.Manifest, c *config) {
	rm.Options.Bulk, rm.Options.Depth = c.bulk, c.depth
	rm.Options.BulkStart = libgenpkg.DefaultStart.Format(time.RFC3339)
	if c.bulkStart != "" {
		rm.Options.BulkStart = c.bulkStart
	}
}

// openOutput creates the output directory when it is not there yet and opens it
// for confined writes. A directory that already exists is open as the probe.
func openOutput(absOut string, exists bool, probe *sandbox.FS) (*sandbox.FS, error) {
	if exists {
		return probe, nil
	}
	if err := os.MkdirAll(absOut, sandbox.DirMode); err != nil {
		return nil, err
	}
	return sandbox.Open(absOut)
}

// writeRecords puts both records on disk before generating, so output that is
// interrupted still carries a record saying the run was under way.
func writeRecords(metaDir string, rm *runinfo.Manifest, rinfo *runinfo.Info) error {
	if err := rm.Write(metaDir); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	if err := rinfo.Write(metaDir); err != nil {
		return fmt.Errorf("write run info: %w", err)
	}
	return nil
}

// generated is what one generating pass produced: its ledger, the context it
// ran in, and the first failure if there was one.
type generated struct {
	entries []ledger.Entry
	ectx    manifestpkg.ExecContext
	err     error
}

// runGeneration writes the artifacts and the records describing them. Each step
// runs only if the ones before it succeeded, but the ledger is written either
// way: it says how far the run got.
func runGeneration(c *config, fsys *sandbox.FS, prog *compile.Program, caps compile.Caps, rm *runinfo.Manifest, metaDir string) generated {
	var g generated
	var ledgerSum string
	if c.bulkMode() {
		start, _ := time.Parse(time.RFC3339, rm.Options.BulkStart)
		g.err = libgenpkg.Generate(fsys, c.bulk, c.depth, libgenpkg.Options{Seed: c.seed, Start: start})
	} else {
		g.ectx = manifestpkg.ExecContext{FS: fsys, Sources: prog.Sources, Caps: caps}
		g.entries, g.err = manifestpkg.Execute(g.ectx, prog.Ops)
		rm.Sources = prog.Sources.Inputs()
		sum, lerr := runinfo.WriteLedger(metaDir, g.entries)
		if lerr != nil && g.err == nil {
			g.err = fmt.Errorf("write %s: %w", ledger.FileName, lerr)
		}
		ledgerSum = sum
	}
	// Digests are read before the settle pass, which puts back any access
	// time the reads moved.
	if g.err == nil {
		g.err = writeSums(metaDir, fsys, rm, ledgerSum)
	}
	if g.err == nil && !c.bulkMode() {
		g.err = manifestpkg.SettleAndVerify(g.ectx, prog.Model)
	}
	// The answer key describes a finished scenario, so a failed run has
	// none; the ledger says how far it got.
	if g.err == nil && !c.bulkMode() {
		g.err = writeAnswerKey(metaDir, prog, g.entries, caps, rm)
	}
	return g
}

// writeSums records the digest of every file in the output, and the ledger's.
func writeSums(metaDir string, fsys *sandbox.FS, rm *runinfo.Manifest, ledgerSum string) error {
	out, err := runinfo.WriteSums(metaDir, fsys)
	if err != nil {
		return fmt.Errorf("write %s: %w", runinfo.SumsFileName, err)
	}
	out.Ledger = ledgerSum
	rm.Outputs = &out
	return nil
}

// writeAnswerKey records what a tool reading the finished output should find.
func writeAnswerKey(metaDir string, prog *compile.Program, entries []ledger.Entry, caps compile.Caps, rm *runinfo.Manifest) error {
	sum, err := runinfo.WriteAnswerKey(metaDir, manifestpkg.AnswerKey(prog.Model, entries, caps))
	if err != nil {
		return fmt.Errorf("write %s: %w", ledger.AnswerKeyFileName, err)
	}
	rm.Outputs.AnswerKey = sum
	return nil
}

// recordFailure marks the run failed in its own record, so output that stopped
// part way cannot pass for finished.
func recordFailure(metaDir string, rm *runinfo.Manifest, cause error, absOut string) error {
	rm.Status, rm.Failure = runinfo.StatusFailed, cause.Error()
	if werr := rm.Write(metaDir); werr != nil {
		return fmt.Errorf("%w (and the run manifest could not be updated: %v)", cause, werr)
	}
	return fmt.Errorf("%w\nthe output in %s is incomplete; its run manifest says so", cause, absOut)
}

// recordSuccess marks the run complete and reports anything it left out.
func recordSuccess(metaDir string, rm *runinfo.Manifest, stdout io.Writer) error {
	rm.Status = runinfo.StatusComplete
	if err := rm.Write(metaDir); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	if len(rm.Skipped) > 0 {
		fmt.Fprintf(stdout, "Skipped %d unsupported operation(s); see %s\n", len(rm.Skipped), filepath.Join(metaDir, runinfo.FileName))
	}
	fmt.Fprintln(stdout, "Done!")
	return nil
}

// writeTimeline writes the timeline, if one was asked for. It comes after the
// run is recorded complete: the output is finished whether or not the timeline
// can be written.
func writeTimeline(tl *timelineRequest, modelled *timelinepkg.Timeline, rm *runinfo.Manifest, metaDir, absOut string, stdout io.Writer) error {
	if tl == nil {
		return nil
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

// seedModel loads an existing tree into a model for --into-existing. Anything
// it cannot read is an error that names the path: a model with holes in it would
// let a later operation collide with something the model does not know is there.
func seedModel(fsys *sandbox.FS) (*model.Tree, error) {
	t := model.New()
	err := fsys.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		t.Add(path.Clean(name), kindOf(d))
		return seedStreams(t, fsys, name)
	})
	return t, err
}

// kindOf is the model kind of a directory entry.
func kindOf(d fs.DirEntry) model.Kind {
	if d.IsDir() {
		return model.Dir
	}
	return model.File
}

// seedStreams adds the named streams a path already carries to the model.
func seedStreams(t *model.Tree, fsys *sandbox.FS, name string) error {
	streams, err := fsys.Streams(name)
	if err != nil {
		return fmt.Errorf("%s: read streams: %w", name, err)
	}
	for _, s := range streams {
		if err := t.AddStream(name, s.Name); err != nil {
			return fmt.Errorf("%s:%s: %w", name, s.Name, err)
		}
	}
	return nil
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

// timelineFormat picks the timeline format from the flag, or else from the file
// extension. An extension it does not know is an error, never a silent
// fall-back to CSV.
func timelineFormat(flagValue, file string) (string, error) {
	if flagValue != "" {
		if slices.Contains(timelinepkg.Formats, flagValue) {
			return flagValue, nil
		}
		return "", usagef("unknown --timeline-format %q (want csv, txt, bodyfile, macb or jsonl)", flagValue)
	}
	if f, ok := timelinepkg.FormatForExtension(strings.ToLower(filepath.Ext(file))); ok {
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
	if err := os.WriteFile(r.file, buf.Bytes(), sandbox.FileMode); err != nil {
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
	if err := os.MkdirAll(outputDir, sandbox.DirMode); err != nil {
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

	if err := os.WriteFile(manifestPath, manifestSchema, sandbox.FileMode); err != nil {
		return "", "", fmt.Errorf("write manifest schema: %w", err)
	}
	if err := os.WriteFile(playbookPath, playbookSchema, sandbox.FileMode); err != nil {
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
