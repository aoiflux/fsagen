package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// Times are an object's four timestamps: last access, last modification,
// metadata change, and birth (creation). A zero value means "not set":
// SetTimes leaves that time as the file system has it, and Times reports it
// as unknown.
type Times struct {
	Atime, Mtime, Ctime, Btime time.Time
}

// IsZero reports whether no time is set.
func (t Times) IsZero() bool {
	return t.Atime.IsZero() && t.Mtime.IsZero() && t.Ctime.IsZero() && t.Btime.IsZero()
}

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

// Granularity is how finely the volume stores each time, which is how far a
// time read back may differ from the one that was set.
type Granularity struct {
	Atime, Mtime, Ctime, Btime time.Duration
}

// Granularity reports the time resolution of this root's volume.
func (f *FS) Granularity() Granularity { return granularity(f.fsName) }

func granularity(fsName string) Granularity {
	switch strings.ToUpper(fsName) {
	case "NTFS", "REFS":
		return Granularity{100, 100, 100, 100}
	case "FAT", "FAT12", "FAT16", "FAT32", "VFAT":
		return Granularity{Atime: 24 * time.Hour, Mtime: 2 * time.Second, Ctime: 2 * time.Second, Btime: 10 * time.Millisecond}
	case "EXFAT":
		return Granularity{Atime: 2 * time.Second, Mtime: 10 * time.Millisecond, Ctime: 10 * time.Millisecond, Btime: 10 * time.Millisecond}
	}
	return defaultGranularity
}

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
	t, err := getTimes(f.root, native(name))
	if err != nil {
		return Times{}, &os.PathError{Op: "read times", Path: name, Err: err}
	}
	return t, nil
}

// OpenQuiet opens name for reading in a way that does not move its access
// time where the platform allows that: on Windows the handle's access-time
// updates are suspended, on Linux the file is opened with O_NOATIME when the
// caller owns it. Elsewhere it is an ordinary read.
func (f *FS) OpenQuiet(name string) (*os.File, error) { return openQuiet(f.root, native(name)) }

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

// CopyStreams copies every named stream of src onto dst, as the Windows
// CopyFile call does. It does nothing where streams are unsupported.
func (f *FS) CopyStreams(src, dst string) error {
	streams, err := f.Streams(src)
	if err != nil {
		return err
	}
	for _, s := range streams {
		data, err := f.ReadStream(src, s.Name)
		if err != nil {
			return err
		}
		if err := f.WriteStream(dst, s.Name, data); err != nil {
			return err
		}
	}
	return nil
}
