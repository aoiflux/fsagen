// Package runinfo writes the records kept beside the output root, never
// inside it, in the sidecar directory (<out>.fsagen by default):
//
//   - run-manifest.json: what produced the corpus. Its status is "running"
//     before the first file and "complete" or "failed" at the end, so a
//     half-built tree cannot pass for a finished one. It is deterministic:
//     the same generator version, toolchain, seed, inputs and capability set
//     give the same bytes on any machine.
//   - SHA256SUMS: the digest of every file and named stream in the output.
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
	"github.com/aoiflux/fsagen/sandbox"
)

// File names inside the sidecar directory.
const (
	FileName     = "run-manifest.json"
	InfoFileName = "run-info.json"
	SumsFileName = "SHA256SUMS"
)

// Status values.
const (
	StatusRunning  = "running"
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
	Failure          string          `json:"failure,omitempty"`
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
}

// Skipped is one operation the platform could not perform, left out because
// the run was told to skip rather than fail.
type Skipped struct {
	Op     int    `json:"op"`
	Src    string `json:"src"`
	Action string `json:"action"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Outputs summarises SHA256SUMS.
type Outputs struct {
	SHA256SUMS string `json:"sha256sums"` // SHA-256 of the SHA256SUMS file
	Files      int    `json:"files"`
	Streams    int    `json:"streams"`
}

// New starts a run manifest.
func New(mode string, seed int64) *Manifest {
	return &Manifest{
		Generator:        "fsagen",
		GeneratorVersion: constant.GeneratorVersion,
		GoVersion:        runtime.Version(),
		Status:           StatusRunning,
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
	Host          string `json:"host,omitempty"`
	Output        string `json:"output"`
	Input         string `json:"input,omitempty"`
	Started       string `json:"started"`
	Finished      string `json:"finished,omitempty"`
}

// NewInfo fills in the build and platform.
func NewInfo() *Info {
	module, rev, modified := Build()
	host, _ := os.Hostname()
	return &Info{ModuleVersion: module, Revision: rev, Modified: modified, OS: runtime.GOOS, Arch: runtime.GOARCH, Host: host}
}

// Write replaces dir/run-info.json atomically.
func (i *Info) Write(dir string) error { return writeJSON(dir, InfoFileName, i) }

// Build reports the module version and VCS revision this binary was built
// from, as far as the toolchain recorded them.
func Build() (module, revision string, modified bool) {
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// Sums lists the SHA-256 of every file and named stream under fsys in
// sha256sum's format ("<hex>  <path>"), with slash paths, a stream written
// as path:stream, sorted by path.
func Sums(fsys *sandbox.FS) (data []byte, out Outputs, err error) {
	type line struct{ path, sum string }
	var lines []line
	addStreams := func(name string) error {
		streams, err := fsys.Streams(name)
		if err != nil {
			return err
		}
		for _, s := range streams {
			b, err := fsys.ReadStream(name, s.Name)
			if err != nil {
				return err
			}
			lines = append(lines, line{name + ":" + s.Name, digest(b)})
			out.Streams++
		}
		return nil
	}
	err = fsys.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if !d.IsDir() {
			f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			lines = append(lines, line{name, hex.EncodeToString(h.Sum(nil))})
			out.Files++
		}
		return addStreams(name)
	})
	if err != nil {
		return nil, out, err
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].path < lines[j].path })
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%s  %s\n", l.sum, l.path)
	}
	data = []byte(b.String())
	out.SHA256SUMS = digest(data)
	return data, out, nil
}

// WriteSums writes SHA256SUMS for fsys into dir and returns its summary.
func WriteSums(dir string, fsys *sandbox.FS) (Outputs, error) {
	data, out, err := Sums(fsys)
	if err != nil {
		return out, err
	}
	return out, writeAtomic(dir, SumsFileName, data)
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
