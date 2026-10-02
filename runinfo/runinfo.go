// Package runinfo writes the records kept beside the output root, never
// inside it, in the sidecar directory (<out>.fsagen by default):
//
//   - run-manifest.json: what produced the corpus. Its status is "running"
//     before the first file and "complete" or "failed" at the end, so a
//     half-built tree cannot pass for a finished one. It is deterministic:
//     the same generator version, toolchain, seed, inputs and capability set
//     give the same bytes on any machine.
//   - SHA256SUMS: the digest of every file and named stream in the output.
//   - ledger.jsonl: what each operation did (see package ledger).
//   - answer-key.jsonl: what a tool examining the output should find,
//     derived from the ledger and the model.
//   - run-info.json: everything about the run that is not deterministic
//     (build revision, host, platform, absolute paths, wall-clock times).
package runinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

// File names inside the sidecar directory.
const (
	FileName     = "run-manifest.json"
	InfoFileName = "run-info.json"
	SumsFileName = "SHA256SUMS"
)

// Status values.
const (
	statusRunning  = "running"
	StatusComplete = "complete"
	StatusFailed   = "failed"
)

// Manifest is the run manifest.
type Manifest struct {
	Generator        string          `json:"generator"`
	GeneratorVersion int             `json:"generator_version"`
	GoVersion        string          `json:"go_version"`
	Status           string          `json:"status"`
	Mode             string          `json:"mode"`
	Seed             int64           `json:"seed"`
	Reproducible     bool            `json:"reproducible"`
	Input            *sandbox.Input  `json:"input,omitempty"`
	Sources          []sandbox.Input `json:"sources,omitempty"`
	VarsFile         *sandbox.Input  `json:"vars_file,omitempty"`
	CLIVarsSHA256    string          `json:"cli_vars_sha256,omitempty"`
	Options          Options         `json:"options"`
	Capabilities     Capabilities    `json:"capabilities"`
	Operations       int             `json:"operations"`
	Skipped          []Skipped       `json:"skipped,omitempty"`
	Outputs          *Outputs        `json:"outputs,omitempty"`
	Timeline         *Timeline       `json:"timeline,omitempty"`
	Failure          string          `json:"failure,omitempty"`
}

// Timeline records the timeline written after a complete run. Its digest
// is recorded only for a modelled timeline: an observed one is read back
// from the file system and differs from run to run.
type Timeline struct {
	Source    string `json:"source"`
	Format    string `json:"format"`
	File      string `json:"file"`
	HashLimit int64  `json:"hash_limit,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// Options are the flags that change what is generated.
type Options struct {
	Clean                bool   `json:"clean,omitempty"`
	IntoExisting         bool   `json:"into_existing,omitempty"`
	OnUnsupported        string `json:"on_unsupported"`
	AllowNonportable     bool   `json:"allow_nonportable,omitempty"`
	AllowExternalSources bool   `json:"allow_external_sources,omitempty"`
	Bulk                 int    `json:"bulk,omitempty"`
	Depth                int    `json:"depth,omitempty"`
	BulkStart            string `json:"bulk_start,omitempty"`
}

// Capabilities is the capability set the run was compiled against. Which
// operations were skipped follows from it.
type Capabilities struct {
	NamedStreams bool `json:"named_streams"`
	// BirthTime and ChangeTime: the creation and metadata change times can
	// be set. Access and modification times always can.
	BirthTime  bool `json:"birth_time"`
	ChangeTime bool `json:"change_time"`
	// FilenameTimesControlled is always false: NTFS keeps a second set of
	// times in each $FILE_NAME attribute, which no user-mode call sets.
	FilenameTimesControlled bool `json:"filename_times_controlled"`
	// RootTimesControlled is always false: the output directory itself is
	// the caller's, and its times are never stamped.
	RootTimesControlled bool `json:"root_times_controlled"`
}

// Skipped is one operation the platform could not perform, left out because
// the run was told to skip rather than fail.
type Skipped struct {
	Op     int             `json:"op"`
	Src    string          `json:"src"`
	Action spec.ActionName `json:"action"`
	Path   string          `json:"path"`
	// Field is set when only one field was dropped (an explicit time the
	// platform cannot set) and the operation itself was performed.
	Field  string `json:"field,omitempty"`
	Reason string `json:"reason"`
}

// Outputs summarises SHA256SUMS.
type Outputs struct {
	SHA256SUMS string `json:"sha256sums"` // SHA-256 of the SHA256SUMS file
	Files      int    `json:"files"`
	Streams    int    `json:"streams"`
	Ledger     string `json:"ledger_sha256,omitempty"`     // SHA-256 of ledger.jsonl
	AnswerKey  string `json:"answer_key_sha256,omitempty"` // SHA-256 of answer-key.jsonl
}

// New starts a run manifest.
func New(mode string, seed int64) *Manifest {
	return &Manifest{
		Generator:        "fsagen",
		GeneratorVersion: constant.GeneratorVersion,
		GoVersion:        runtime.Version(),
		Status:           statusRunning,
		Mode:             mode,
		Seed:             seed,
		Reproducible:     true,
	}
}

// Write replaces dir/run-manifest.json atomically.
func (m *Manifest) Write(dir string) error { return writeJSON(dir, FileName, m) }

// Info is the non-deterministic record of a run.
type Info struct {
	ModuleVersion string `json:"module_version"`
	Revision      string `json:"vcs_revision,omitempty"`
	Modified      bool   `json:"vcs_modified,omitempty"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Filesystem    string `json:"filesystem,omitempty"`
	// LastAccess is the host's last-access-time policy (Windows'
	// NtfsDisableLastAccessUpdate), which decides whether reading a file
	// after the run moves its access time.
	LastAccess string `json:"last_access_policy,omitempty"`
	Host       string `json:"host,omitempty"`
	Output     string `json:"output"`
	Input      string `json:"input,omitempty"`
	Started    string `json:"started"`
	Finished   string `json:"finished,omitempty"`
}

// NewInfo fills in the build and platform.
func NewInfo() *Info {
	module, rev, modified := Build()
	host, _ := os.Hostname()
	return &Info{ModuleVersion: module, Revision: rev, Modified: modified, OS: runtime.GOOS, Arch: runtime.GOARCH, Host: host}
}

// Write replaces dir/run-info.json atomically.
func (i *Info) Write(dir string) error { return writeJSON(dir, InfoFileName, i) }

// version is the release version, stamped at link time by build.sh and
// build.ps1 (-ldflags -X). Go stamps Main.Version itself, but only ever with a
// tag it can see: built from an untagged commit it records a pseudo-version,
// which is how the v0.1.0 assets shipped reporting
// v0.0.0-20260927132346-6b5b91ad4367. The release scripts pass the version
// they name the files after, so the name and the binary cannot disagree.
//
// This is only a claim about the version. The revision below always comes from
// the toolchain, so the commit a binary was built from stays checkable against
// the tag whatever this says.
var version string

// Build reports the version and VCS revision this binary was built from. The
// version is the one a release script stamped, if one did, and the module
// version the toolchain recorded otherwise.
func Build() (module, revision string, modified bool) {
	module, revision, modified = recorded()
	if version != "" {
		module = version
	}
	return
}

// recorded reports what the toolchain wrote into the binary, as far as it
// recorded anything at all.
func recorded() (module, revision string, modified bool) {
	module = "(unknown)"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	module = info.Main.Version
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return
}

func writeJSON(dir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(dir, name, append(data, '\n'))
}

func writeAtomic(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, sandbox.DirMode); err != nil {
		return err
	}
	// The temporary name carries the process id, so two runs sharing one --meta
	// directory cannot overwrite each other's half-written file.
	tmp := filepath.Join(dir, fmt.Sprintf("%s.%d.tmp", name, os.Getpid()))
	if err := writeAndSync(tmp, data); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// writeAndSync writes the file and flushes it to the disk, so the rename that
// follows cannot publish a name whose contents have not landed yet.
func writeAndSync(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, sandbox.FileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteLedger writes ledger.jsonl into dir and returns its SHA-256.
func WriteLedger(dir string, entries []ledger.Entry) (string, error) {
	data := ledger.Bytes(entries)
	return Digest(data), writeAtomic(dir, ledger.FileName, data)
}

// WriteAnswerKey writes answer-key.jsonl into dir and returns its SHA-256.
func WriteAnswerKey(dir string, facts []ledger.Fact) (string, error) {
	data := ledger.FactBytes(facts)
	return Digest(data), writeAtomic(dir, ledger.AnswerKeyFileName, data)
}

// buildSums lists the SHA-256 of every file and named stream under fsys in
// sha256sum's format ("<hex>  <path>"), with slash paths, a stream written
// as path:stream, sorted by path.
func buildSums(fsys *sandbox.FS) ([]byte, Outputs, error) {
	s := &sums{fsys: fsys}
	if err := fsys.WalkDir(s.visit); err != nil {
		return nil, s.out, err
	}
	return s.render()
}

// sumLine is one line of SHA256SUMS: a path, or a path and stream name, and the
// digest of its bytes.
type sumLine struct{ path, sum string }

// sums collects a digest for everything in the output: every file, and every
// named stream of a file or directory.
type sums struct {
	fsys  *sandbox.FS
	lines []sumLine
	out   Outputs
}

// visit digests one entry of the tree. A directory has no content of its own,
// but it can still carry named streams.
func (s *sums) visit(name string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if name == "." {
		return nil
	}
	if !d.IsDir() {
		if err := s.addFile(name); err != nil {
			return err
		}
	}
	return s.addStreams(name)
}

func (s *sums) addFile(name string) error {
	sum, err := fileDigest(s.fsys, name)
	if err != nil {
		return err
	}
	s.lines = append(s.lines, sumLine{name, sum})
	s.out.Files++
	return nil
}

func (s *sums) addStreams(name string) error {
	streams, err := s.fsys.Streams(name)
	if err != nil {
		return err
	}
	for _, st := range streams {
		if err := s.addStream(name, st.Name); err != nil {
			return err
		}
	}
	return nil
}

func (s *sums) addStream(name, stream string) error {
	b, err := s.fsys.ReadStream(name, stream)
	if err != nil {
		return err
	}
	s.lines = append(s.lines, sumLine{name + ":" + stream, Digest(b)})
	s.out.Streams++
	return nil
}

// render writes the lines in path order, so the file is the same whatever order
// the tree was walked in, and digests the result.
func (s *sums) render() ([]byte, Outputs, error) {
	sort.Slice(s.lines, func(i, j int) bool { return s.lines[i].path < s.lines[j].path })
	var b strings.Builder
	for _, l := range s.lines {
		fmt.Fprintf(&b, "%s  %s\n", l.sum, l.path)
	}
	data := []byte(b.String())
	s.out.SHA256SUMS = Digest(data)
	return data, s.out, nil
}

// WriteSums writes SHA256SUMS for fsys into dir and returns its summary.
func WriteSums(dir string, fsys *sandbox.FS) (Outputs, error) {
	data, out, err := buildSums(fsys)
	if err != nil {
		return out, err
	}
	return out, writeAtomic(dir, SumsFileName, data)
}

// Digest is the SHA-256 of data, in hex.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fileDigest is the SHA-256 of a file in the output, read as a stream so a
// large artefact is never held in memory.
func fileDigest(fsys *sandbox.FS, name string) (string, error) {
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
