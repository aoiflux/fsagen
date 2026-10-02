// Package sandbox is the only way fsagen touches the file system while
// generating. Every write goes through an *os.Root opened on the output
// directory, so a path that slipped past pathpolicy, or a symlink planted
// inside the tree, still cannot reach outside it. Source reads (content_file,
// email bodies, attachments) go through a second root on the YAML file's
// directory.
//
// Names passed in are slash-separated and relative, as produced by pathpolicy.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/aoiflux/fsagen/pathpolicy"
)

// ErrStreamsUnsupported is returned by stream operations on a platform or
// volume without named streams.
var ErrStreamsUnsupported = errors.New("alternate data streams are not supported on this platform or volume")

// Default permissions. Files are not executable and directories are not
// world-writable; an operation's own mode overrides these.
const (
	FileMode = os.FileMode(0o644)
	DirMode  = os.FileMode(0o755)
)

// FS confines file-system writes to one directory.
type FS struct {
	root    *os.Root
	dir     string
	streams bool
	fsName  string
	gran    Granularity
}

// Open opens dir, which must already exist, as a confined output root.
func Open(dir string) (*FS, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	f := &FS{root: r, dir: abs}
	f.streams, f.fsName = probeVolume(r)
	f.gran = volumeGranularity(r, f.fsName)
	return f, nil
}

// Close releases the root.
func (f *FS) Close() error { return f.root.Close() }

// Dir is the absolute path of the root, for messages only.
func (f *FS) Dir() string { return f.dir }

// SupportsStreams reports whether the volume stores named data streams.
func (f *FS) SupportsStreams() bool { return f.streams }

// FilesystemName is the volume's file-system name (NTFS, ReFS, ext4,
// btrfs, ...), or "" where the platform does not report one.
func (f *FS) FilesystemName() string { return f.fsName }

func native(name string) string { return filepath.FromSlash(name) }

// MkdirAll creates name and any missing parents.
func (f *FS) MkdirAll(name string, perm os.FileMode) error {
	return f.root.MkdirAll(native(name), perm)
}

// MkdirParent creates the directory that will hold name.
func (f *FS) MkdirParent(name string) error {
	if dir := path.Dir(name); dir != "." {
		return f.root.MkdirAll(native(dir), DirMode)
	}
	return nil
}

// WriteFile creates or truncates name and writes data to it.
func (f *FS) WriteFile(name string, data []byte, perm os.FileMode) error {
	if err := f.MkdirParent(name); err != nil {
		return err
	}
	return f.root.WriteFile(native(name), data, perm)
}

// OpenFile opens name within the root.
func (f *FS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return f.root.OpenFile(native(name), flag, perm)
}

// ReadFile reads name from within the root.
func (f *FS) ReadFile(name string) ([]byte, error) { return f.root.ReadFile(native(name)) }

// Remove deletes a file or an empty directory.
func (f *FS) Remove(name string) error { return f.root.Remove(native(name)) }

// Rename moves oldname to newname, both inside the root.
func (f *FS) Rename(oldname, newname string) error {
	return f.root.Rename(native(oldname), native(newname))
}

// Chmod changes name's permission bits.
func (f *FS) Chmod(name string, mode os.FileMode) error {
	return f.root.Chmod(native(name), mode)
}

// Empty reports whether the root holds no entries at all.
func (f *FS) Empty() (bool, error) {
	entries, err := fs.ReadDir(f.root.FS(), ".")
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// RemoveContents deletes everything inside the root but not the root itself.
// It is how --clean empties a previous run's output without ever operating on
// a path outside it.
func (f *FS) RemoveContents() error {
	entries, err := fs.ReadDir(f.root.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := f.root.RemoveAll(e.Name()); err != nil {
			return err
		}
	}
	return nil
}

// WalkDir walks the tree in lexical order with slash-separated names.
func (f *FS) WalkDir(fn fs.WalkDirFunc) error { return fs.WalkDir(f.root.FS(), ".", fn) }

// Stream describes one named data stream.
type Stream struct {
	Name string
	Size int64
}

// WriteStream creates or replaces a named stream on an existing file or
// directory. The base is opened through the root first, which proves it lies
// inside; the stream is then opened relative to that handle, so no path to
// the stream is ever resolved from outside.
func (f *FS) WriteStream(name, stream string, data []byte) error {
	if err := pathpolicy.Stream(stream); err != nil {
		return err
	}
	if !f.streams {
		return ErrStreamsUnsupported
	}
	return writeStream(f.root, native(name), stream, data)
}

// ReadStream reads a named stream.
func (f *FS) ReadStream(name, stream string) ([]byte, error) {
	if err := pathpolicy.Stream(stream); err != nil {
		return nil, err
	}
	if !f.streams {
		return nil, ErrStreamsUnsupported
	}
	return readStream(f.root, native(name), stream)
}

// Streams lists name's named data streams, sorted by name. The default
// (unnamed) stream is not included. Platforms without streams return none.
func (f *FS) Streams(name string) ([]Stream, error) {
	if !f.streams {
		return nil, nil
	}
	s, err := listStreams(f.root, native(name))
	if err != nil {
		return nil, err
	}
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	return s, nil
}

// Sources reads the input files a manifest or playbook refers to, confined to
// the directory holding the YAML unless external reads were allowed. Every
// file read is remembered with its SHA-256 so the run manifest can name every
// input the output depends on.
type Sources struct {
	root          *os.Root
	dir           string
	allowExternal bool
	inputs        map[string]string
}

// OpenSources opens dir (the YAML file's directory) for confined reads.
func OpenSources(dir string, allowExternal bool) (*Sources, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return &Sources{root: r, dir: abs, allowExternal: allowExternal, inputs: map[string]string{}}, nil
}

// Close releases the source root.
func (s *Sources) Close() error { return s.root.Close() }

// resolve decides what a source path as written in the YAML refers to: the
// policy's verdict on the path first, then whether reading outside the YAML's
// directory is allowed at all. It returns a path to open, and whether that
// path is on the host rather than inside the source root. Both ReadFile and
// Check go through it, so a path one of them accepts the other cannot refuse.
func (s *Sources) resolve(p string) (name string, external bool, err error) {
	clean, external, err := pathpolicy.Source(p)
	if err != nil {
		return "", false, err
	}
	if external {
		if !s.allowExternal {
			return "", false, fmt.Errorf("source %q is outside the directory holding the YAML file; copy it there or pass --allow-external-sources", p)
		}
		return resolveExternal(s.dir, p), true, nil
	}
	return native(clean), false, nil
}

// ReadFile reads a source path exactly as written in the YAML.
func (s *Sources) ReadFile(p string) ([]byte, error) {
	name, external, err := s.resolve(p)
	if err != nil {
		return nil, err
	}
	var data []byte
	if external {
		data, err = os.ReadFile(name)
	} else {
		data, err = s.root.ReadFile(name)
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	s.inputs[p] = hex.EncodeToString(sum[:])
	return data, nil
}

// Check verifies that a source path is acceptable and exists, without
// recording it as read.
func (s *Sources) Check(p string) error {
	name, external, err := s.resolve(p)
	if err != nil {
		return err
	}
	if external {
		_, err = os.Stat(name)
	} else {
		_, err = s.root.Stat(name)
	}
	return err
}

func resolveExternal(dir, p string) string {
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// Input is one file read while compiling or executing.
type Input struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Inputs lists every source read so far, sorted by path.
func (s *Sources) Inputs() []Input {
	out := make([]Input, 0, len(s.inputs))
	for p, h := range s.inputs {
		out = append(out, Input{Path: p, SHA256: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
