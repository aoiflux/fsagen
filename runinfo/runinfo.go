// Package runinfo writes the run manifest: the record, kept beside the output
// root and never inside it, of what produced a corpus. Its status is written
// as "running" before the first file and replaced by "complete" or "failed"
// at the end, so a half-built tree can never pass for a finished one.
//
// Everything in it is deterministic for a given build, seed, input and
// platform: no wall-clock times, host names or absolute paths.
package runinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/sandbox"
)

// FileName is the run manifest's name inside the sidecar directory.
const FileName = "run-manifest.json"

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
	ModuleVersion    string          `json:"module_version"`
	Revision         string          `json:"vcs_revision,omitempty"`
	Modified         bool            `json:"vcs_modified,omitempty"`
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
	Platform         Platform        `json:"platform"`
	Operations       int             `json:"operations"`
	Skipped          []Skipped       `json:"skipped,omitempty"`
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
}

// Platform describes where the corpus was generated.
type Platform struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Filesystem   string `json:"filesystem,omitempty"`
	NamedStreams bool   `json:"named_streams"`
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

// New fills in the fields that describe this build and platform.
func New(mode string, seed int64) *Manifest {
	module, rev, modified := Build()
	return &Manifest{
		Generator:        "fsagen",
		GeneratorVersion: constant.GeneratorVersion,
		ModuleVersion:    module,
		Revision:         rev,
		Modified:         modified,
		GoVersion:        runtime.Version(),
		Status:           StatusRunning,
		Mode:             mode,
		Seed:             seed,
		Reproducible:     true,
		Platform:         Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
	}
}

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

// Write replaces dir/run-manifest.json atomically.
func (m *Manifest) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := filepath.Join(dir, FileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FileName))
}
