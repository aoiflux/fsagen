// Package target says what fsagen writes a scenario into and reads it back
// from. A live directory (package sandbox) is one target; a file-system
// image built byte by byte is another. Executing, settling, verifying,
// digesting and the observed timeline all go through these interfaces, so
// none of them knows which kind it has.
//
// A target does only what it is told. Every time it keeps is stamped from
// the model, every name it holds was proved valid by compile, and what it
// cannot do is in its Caps, which pre-flight checked the program against
// before anything was written.
//
// Names are slash-separated and relative to the target's root, as produced
// by pathpolicy. The root itself is "." and is never part of the scenario.
package target

import (
	"io"
	"io/fs"
	"path"
	"time"
)

// Default permissions. Files are not executable and directories are not
// world-writable; an operation's own mode overrides these.
const (
	FileMode = fs.FileMode(0o644)
	DirMode  = fs.FileMode(0o755)
)

// Times are an object's four timestamps: last access, last modification,
// metadata change, and birth (creation). A zero value means "not set":
// SetTimes leaves that time as the target has it, and a read reports it as
// unknown.
type Times struct {
	Atime, Mtime, Ctime, Btime time.Time
}

// IsZero reports whether no time is set.
func (t Times) IsZero() bool {
	return t.Atime.IsZero() && t.Mtime.IsZero() && t.Ctime.IsZero() && t.Btime.IsZero()
}

// Granularity is how finely a target stores each time, which is how far a
// time read back may differ from the one that was set.
type Granularity struct {
	Atime, Mtime, Ctime, Btime time.Duration
}

// The kinds of link Meta reports.
const (
	LinkSymlink  = "symlink"
	LinkJunction = "junction"
)

// Meta is what a timeline records about an object besides its content.
type Meta struct {
	// Times are the four times; one the target does not report is zero.
	Times
	// ID identifies the object on its volume: the MFT record number on
	// NTFS, the file ID elsewhere on Windows, the inode number on Unix.
	ID string
	// UID and GID own the object on Unix. Windows has no numeric owner, and
	// they are 0 there, as The Sleuth Kit writes them for NTFS.
	UID, GID int
	// Links is the number of names the object has (0 where the target does
	// not say).
	Links int
	// FileName are the times NTFS keeps in the $FILE_NAME attribute of this
	// name, nil where the target does not report them.
	FileName *Times
	// Link is LinkSymlink or LinkJunction for a link, and Target what it
	// points at: for a symlink as stored, with '/' between names; for a
	// junction a path in the output when it points into it.
	Link, Target string
}

// Stream describes one named data stream.
type Stream struct {
	Name string
	Size int64
}

// SlackSupport is how far a target can be trusted to keep slack bytes.
type SlackSupport string

const (
	// SlackNone: the target cannot be made to keep them at all.
	SlackNone SlackSupport = "none"
	// SlackBestEffort: they are written where the file system leaves them,
	// but nothing short of reading the raw volume can confirm they stayed.
	SlackBestEffort SlackSupport = "best_effort"
	// SlackExact: fsagen writes the cluster itself.
	SlackExact SlackSupport = "exact"
)

// Caps is what a target can do.
type Caps struct {
	// NamedStreams: the volume stores alternate data streams (NTFS, ReFS).
	NamedStreams bool
	// BirthTime: a file's creation time can be set (Windows).
	BirthTime bool
	// ChangeTime: a file's metadata change time can be set and is stored
	// (Windows on NTFS or ReFS).
	ChangeTime bool
	// FilenameTimes: the times NTFS keeps in each $FILE_NAME attribute can
	// be set. No live volume allows it: Windows sets them itself, and no
	// call a program can make changes them.
	FilenameTimes bool
	// Hardlinks, Symlinks and Junctions: the volume stores them, and this
	// process may make them (a Windows symlink needs Developer Mode or the
	// privilege).
	Hardlinks, Symlinks, Junctions bool
	// Slack is how far the target keeps bytes written past the end of a
	// file, and ClusterSize the size of its clusters (0 when not known, as
	// for --validate with no output volume).
	Slack       SlackSupport
	ClusterSize int
	// ResidentData: a small file's content may be kept in its MFT record,
	// with no cluster and so no slack (NTFS).
	ResidentData bool
	// MinTime and MaxTime bound the times the volume can store; zero is no
	// bound. FAT keeps none before 1980 or after 2107.
	MinTime, MaxTime time.Time
	// FoldsCase: names differing only in case are one name, whatever
	// --allow-nonportable says (FAT and NTFS images).
	FoldsCase bool
	// ValidName refuses a name the volume cannot store; nil accepts any
	// name pathpolicy does.
	ValidName func(name string) error
	// Reserved are names the file system keeps for itself at the root of
	// the volume, such as ext4's lost+found, which the scenario cannot use
	// there.
	Reserved []string
}

// File is an open file in a target: read, written, or both, as it was
// opened.
type File interface {
	io.Reader
	io.Writer
	io.Closer
}

// Reader reads a target's tree. Reads are quiet: where the target can, they
// leave access times alone, so reading the output does not change the times
// being read.
type Reader interface {
	// WalkDir walks the tree in lexical order, the root first, as
	// fs.WalkDir does. It never descends through a link.
	WalkDir(fn fs.WalkDirFunc) error
	// ReadDirQuiet lists a directory, sorted by name.
	ReadDirQuiet(name string) ([]fs.DirEntry, error)
	// Meta reads an object's times, identity and owner without following a
	// final link.
	Meta(name string) (Meta, error)
	// Times reads an object's times without following a final link. Times
	// the target does not report are zero.
	Times(name string) (Times, error)
	// Granularity is how finely the target stores each time.
	Granularity() Granularity
	// ReadFile reads a file whole.
	ReadFile(name string) ([]byte, error)
	// OpenQuiet opens a file for reading.
	OpenQuiet(name string) (io.ReadCloser, error)
	// Streams lists an object's named streams, sorted by name. The default
	// (unnamed) stream is not included; a target without streams has none.
	Streams(name string) ([]Stream, error)
	// ReadStream reads a named stream whole.
	ReadStream(name, stream string) ([]byte, error)
	// OpenStreamQuiet opens a named stream for reading.
	OpenStreamQuiet(name, stream string) (io.ReadCloser, error)
}

// Writer changes a target's tree.
type Writer interface {
	// MkdirAll creates a directory and any missing parents.
	MkdirAll(name string, perm fs.FileMode) error
	// WriteFile creates or truncates a file, creating its parents, and
	// writes data to it.
	WriteFile(name string, data []byte, perm fs.FileMode) error
	// OpenFile opens a file with os.OpenFile's flags.
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	// Remove deletes a file, a link or an empty directory. A file with
	// another name keeps it.
	Remove(name string) error
	// Rename moves a file or a directory and everything in it.
	Rename(oldname, newname string) error
	// Chmod changes an object's permission bits.
	Chmod(name string, mode fs.FileMode) error
	// WriteStream creates or replaces a named stream on an existing file or
	// directory.
	WriteStream(name, stream string, data []byte) error
	// SetTimes sets an object's times in one step. Zero times are left
	// alone. The root's own times are never set.
	SetTimes(name string, t Times) error
}

// Target is somewhere a scenario is written: read and written through one
// root, with the capabilities pre-flight checks the program against.
type Target interface {
	Reader
	Writer
	Caps() Caps
}

// Linker is a target that makes links. One whose Caps claim a kind of link
// must implement it.
type Linker interface {
	// Link gives the file oldname a second name, newname.
	Link(oldname, newname string) error
	// Symlink makes name a symlink to target, written as given and never
	// followed. dir says whether it points at a directory.
	Symlink(name, target string, dir bool) error
	// Junction makes name a junction to target, a directory in the output.
	Junction(name, target string) error
}

// Slacker is a target that keeps bytes past the end of a file. One whose
// Caps claim slack must implement it.
type Slacker interface {
	// WriteSlack writes data just past byte at of name, which must be where
	// its content ends, and leaves the file ending at at.
	WriteSlack(name string, at int64, data []byte) error
}

// FilenameTimer is a target that sets the times NTFS keeps in a name's
// $FILE_NAME attribute. One whose Caps claim FilenameTimes must implement
// it.
type FilenameTimer interface {
	// SetFileNameTimes sets the non-zero times of name's $FILE_NAME.
	SetFileNameTimes(name string, t Times) error
}

// Finisher is a target that is built in one go, such as an image: what it
// holds is final only once Finish has run. Finish returns the reader of the
// finished target, and nothing may be written to the target after it.
//
// A target that is not a Finisher is final as it is written, and is read
// back through itself.
type Finisher interface {
	Finish() (Reader, error)
}

// OpObserver is a target told which operation is running, so what it
// records itself, such as residue, can name the ledger entry that left it,
// and what it stamps itself, such as ext4's deletion time, carries the
// operation's time.
type OpObserver interface {
	// BeginOp is called before operation n (the ledger's n) runs, and with 0
	// once the operations are done. when is the time the operation happens,
	// zero when the scenario does not say.
	BeginOp(n int, when time.Time)
}

// Forensic is a target that knows what its writes left behind beyond the
// tree: deleted entries and the bytes they pointed at. Residue is complete
// once Finish has run.
type Forensic interface {
	Residue() []Residue
}

// The causes of residue.
const (
	ResidueDelete    = "delete"
	ResidueRename    = "rename"
	ResidueOverwrite = "overwrite"
)

// How much of residue's content is still on the volume.
const (
	RecoverableFull    = "full"
	RecoverablePartial = "partial"
	RecoverableNone    = "none"
)

// Residue is something a write left on the volume that no name reaches any
// more: the entry a delete or rename left behind, and the clusters a delete
// or overwrite freed with their bytes still in them.
type Residue struct {
	// N is the ledger entry of the operation that left it, and Path the
	// name it was under.
	N    int    `json:"-"`
	Path string `json:"-"`
	// Cause is ResidueDelete, ResidueRename or ResidueOverwrite.
	Cause string `json:"cause"`
	// Entry is the directory entry or record left behind, if any.
	Entry *ResidueEntry `json:"entry,omitempty"`
	// Extents are where the freed content was, as byte ranges of the image
	// file, in the content's order, and SHA256 its digest then.
	Extents []Extent `json:"extents,omitempty"`
	Size    int64    `json:"size,omitempty"`
	SHA256  string   `json:"sha256,omitempty"`
	// Recoverable says how much of that content the finished image still
	// holds, and Overwritten which ranges of it later writes changed.
	Recoverable string   `json:"recoverable,omitempty"`
	Overwritten []Extent `json:"overwritten,omitempty"`
}

// ResidueEntry is a deleted directory entry or record.
type ResidueEntry struct {
	// Type names the structure, such as "fat_dirent".
	Type string `json:"type"`
	// Number is its address as The Sleuth Kit numbers it, and Seq its
	// sequence number where the file system keeps one.
	Number int64 `json:"number"`
	Seq    int   `json:"seq,omitempty"`
	// Offset and Length are where it lies in the image file.
	Offset int64 `json:"offset"`
	Length int   `json:"length"`
	// Deleted is when the entry itself says it was deleted, where the file
	// system records that (ext4's dtime, to the second), in RFC 3339.
	Deleted string `json:"deleted,omitempty"`
	// Overwritten: a later write reused it, so no tool will find it.
	Overwritten bool `json:"overwritten,omitempty"`
}

// Extent is a byte range of the image file.
type Extent struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// MkdirParent creates the directory that will hold name.
func MkdirParent(w Writer, name string) error {
	if dir := path.Dir(name); dir != "." {
		return w.MkdirAll(dir, DirMode)
	}
	return nil
}

// CopyStreams copies every named stream of src onto dst, as the Windows
// CopyFile call does. It does nothing where the target has no streams.
func CopyStreams(t Target, src, dst string) error {
	streams, err := t.Streams(src)
	if err != nil {
		return err
	}
	for _, s := range streams {
		data, err := t.ReadStream(src, s.Name)
		if err != nil {
			return err
		}
		if err := t.WriteStream(dst, s.Name, data); err != nil {
			return err
		}
	}
	return nil
}
