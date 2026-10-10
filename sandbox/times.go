package sandbox

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/target"
)

// Times are an object's four timestamps (see target.Times).
type Times = target.Times

// TimeCaps says which times this platform and volume let fsagen set. Access
// and modification times can always be set.
type TimeCaps struct {
	// Birth: the creation time can be set (Windows, any volume).
	Birth bool
	// Change: the metadata change time can be set and is stored (Windows on
	// NTFS or ReFS; FAT volumes do not keep one).
	Change bool
}

// TimeCaps reports which times can be set on this root's volume.
func (f *FS) TimeCaps() TimeCaps { return timeCaps(f.fsName) }

// tick is the unit a Windows FILETIME counts, and so the resolution of the
// file systems that store one per time. It is spelled out because the
// Granularity fields below are durations, where a bare 100 reads as 100
// nanoseconds only if you already know that.
const tick = 100 * time.Nanosecond

// Granularity is how finely the volume stores each time (see
// target.Granularity).
type Granularity = target.Granularity

// Granularity reports the time resolution of this root's volume.
func (f *FS) Granularity() Granularity { return f.gran }

// namedGranularity is the resolution of the file systems whose name says
// it.
func namedGranularity(fsName string) (Granularity, bool) {
	switch strings.ToUpper(fsName) {
	case "NTFS", "REFS":
		return uniform(tick), true
	case "FAT", "FAT12", "FAT16", "FAT32", "VFAT":
		return Granularity{Atime: 24 * time.Hour, Mtime: 2 * time.Second, Ctime: 2 * time.Second, Btime: 10 * time.Millisecond}, true
	case "EXFAT":
		return Granularity{Atime: 2 * time.Second, Mtime: 10 * time.Millisecond, Ctime: 10 * time.Millisecond, Btime: 10 * time.Millisecond}, true
	}
	return Granularity{}, false
}

// uniform is the resolution of a volume that keeps every time alike.
func uniform(d time.Duration) Granularity {
	return Granularity{Atime: d, Mtime: d, Ctime: d, Btime: d}
}

// wholeSeconds is the resolution of a volume that keeps whole seconds.
var wholeSeconds = uniform(time.Second)

// SetTimes sets name's times in one step. Zero times are left alone, and so
// are the times TimeCaps says this platform cannot set. The root itself is
// never stamped: it is the caller's directory, not part of the scenario.
func (f *FS) SetTimes(name string, t Times) error {
	if name == "." || name == "" {
		return fmt.Errorf("the output root's own times are not set")
	}
	if t.IsZero() {
		return nil
	}
	if err := setTimes(f.root, native(name), t, f.TimeCaps()); err != nil {
		return &os.PathError{Op: "set times", Path: name, Err: err}
	}
	return nil
}

// Times reads name's times without following a final symlink. Times this
// platform does not report are zero.
func (f *FS) Times(name string) (Times, error) {
	m, err := f.Meta(name)
	return m.Times, err
}

// Meta is what a timeline records about an object besides its content
// (see target.Meta). Linux reports a birth time only where statx has one.
type Meta = target.Meta

// Meta reads name's times, identity and owner without following a final
// symlink, reading only metadata (no access time moves).
func (f *FS) Meta(name string) (Meta, error) {
	m, err := getMeta(f.root, native(name), f.fsName)
	if err != nil {
		return Meta{}, &os.PathError{Op: "read metadata", Path: name, Err: err}
	}
	switch m.Link {
	case LinkSymlink:
		m.Target = filepath.ToSlash(m.Target)
	case LinkJunction:
		m.Target = f.relativeTarget(m.Target)
	}
	return m, nil
}

// OpenQuiet opens name for reading in a way that does not move its access
// time where the platform allows that: on Windows the handle's access-time
// updates are suspended, on Linux the file is opened with O_NOATIME when the
// caller owns it. Elsewhere it is an ordinary read.
func (f *FS) OpenQuiet(name string) (io.ReadCloser, error) {
	return readCloser(openQuiet(f.root, native(name)))
}

// OpenStreamQuiet opens a named stream for reading without moving its
// file's access time (see OpenQuiet).
func (f *FS) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	if err := pathpolicy.Stream(stream); err != nil {
		return nil, err
	}
	if !f.streams {
		return nil, ErrStreamsUnsupported
	}
	return readCloser(openStreamQuiet(f.root, native(name), stream))
}

// readCloser hands on an opened file, or the error, never a nil *os.File
// in a non-nil interface.
func readCloser(f *os.File, err error) (io.ReadCloser, error) {
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ReadDirQuiet lists a directory, sorted by name, through a handle that
// does not move the directory's access time where the platform allows (see
// OpenQuiet). The root itself is listed normally: its times are never part
// of the scenario.
func (f *FS) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	var (
		d   *os.File
		err error
	)
	if name == "." || name == "" {
		d, err = f.root.Open(".")
	} else {
		d, err = openQuiet(f.root, native(name))
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}
