// Package timeline describes a tree as a forensic timeline, in five formats:
// CSV, text, The Sleuth Kit's bodyfile, a mactime-style MACB listing and
// JSON lines.
//
// A timeline has one of two sources. An observed timeline (Generate) is read
// back from the file system after the run; it is what a tool examining the
// output would see, and it is not covered by the determinism contract. A
// modelled timeline (Modelled) is built from the run's model and ledger: the
// times, sizes and digests the scenario intends, including the objects it
// deleted, which the observed timeline can never show. It is the same bytes
// on every run with the same inputs and capability set.
//
// Every entry carries four times, each of which may be unknown: access,
// modification, metadata change and birth (creation). An unknown time is
// never filled in from another one; the bodyfile writes it as 0, as The
// Sleuth Kit does.
package timeline

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"time"

	"github.com/aoiflux/fsagen/sandbox"
)

// Sources.
const (
	SourceObserved = "observed"
	SourceModelled = "modelled"
)

// Formats lists the formats Write accepts, in the order they are documented.
// It is built from the writers table rather than written out beside it, so a
// format cannot be offered that nothing writes, or written that nothing
// offers.
var Formats = formatNames()

// Type is what an entry describes.
type Type string

const (
	TypeFile   Type = "file"
	TypeDir    Type = "dir"
	TypeLink   Type = "link"
	TypeStream Type = "stream" // a named data stream of Path
	TypeOther  Type = "other"
)

// Entry is one timeline record: a file, directory or link, or one named
// stream of a file or directory (with its object's times, as NTFS keeps
// them per file).
type Entry struct {
	// Path is slash-separated and relative to the root.
	Path string
	// Stream names the stream when Type is TypeStream.
	Stream string
	Type   Type
	// Mode holds the permission bits (and, for directories, fs.ModeDir).
	Mode fs.FileMode
	Size int64
	// UID and GID are the owner on Unix; 0 elsewhere.
	UID, GID int
	// Inode identifies the object: its MFT record number or inode number
	// when observed, its ledger object number when modelled. "" is unknown.
	Inode string
	// Object is the ledger's object number (modelled timelines only).
	Object int
	// The four times; zero is unknown.
	Atime, Mtime, Ctime, Btime time.Time
	// MD5 of the content; "" when not computed (directories, links, files
	// over the hash limit).
	MD5 string
	// Deleted marks an object the scenario deleted (modelled timelines only).
	Deleted bool
}

// Timeline holds all entries, sorted.
type Timeline struct {
	// Source is SourceObserved or SourceModelled.
	Source string
	// Root is the directory an observed timeline was read from; empty for a
	// modelled one, which does not depend on where the output went.
	Root    string
	Entries []Entry
}

// Options tune an observed timeline.
type Options struct {
	// HashLimit skips the MD5 of files and streams larger than this many
	// bytes; 0 hashes everything.
	HashLimit int64
}

// Generate walks the tree under root and records every file, directory,
// link and named stream in it (the root itself is not an entry).
//
// It reads the tree through the sandbox, so it cannot leave root, and every
// directory listing and digest goes through a handle that leaves access
// times alone where the platform allows (Windows always; Linux when the
// caller owns the file). Reading the corpus therefore does not change the
// times it is reading. Anything it cannot read is an error that names the
// path: a timeline with holes in it would pass for a complete one.
func Generate(root string, opts Options) (*Timeline, error) {
	fsys, err := sandbox.Open(root)
	if err != nil {
		return nil, err
	}
	defer fsys.Close()

	w := &walker{fsys: fsys, opts: opts}
	if err := w.walk("."); err != nil {
		return nil, fmt.Errorf("timeline of %s: %w", root, err)
	}
	tl := &Timeline{Source: SourceObserved, Root: fsys.Dir(), Entries: w.entries}
	sortEntries(tl.Entries)
	return tl, nil
}

// walker reads a tree into timeline entries, depth first.
type walker struct {
	fsys    *sandbox.FS
	opts    Options
	entries []Entry
}

// walk records every entry in dir and then descends into its directories.
func (w *walker) walk(dir string) error {
	names, err := w.fsys.ReadDirQuiet(dir)
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	for _, d := range names {
		name := path.Join(dir, d.Name())
		e, err := w.record(name, d)
		if err != nil {
			return err
		}
		if e.Type != TypeDir {
			continue
		}
		if err := w.walk(name); err != nil {
			return err
		}
	}
	return nil
}

// record adds the entry for one object, and one more for each of its named
// streams. It returns the object's own entry so the caller knows to descend.
func (w *walker) record(name string, d fs.DirEntry) (Entry, error) {
	e, err := w.entryFor(name, d)
	if err != nil {
		return Entry{}, err
	}
	w.entries = append(w.entries, e)
	if e.Type != TypeFile && e.Type != TypeDir {
		return e, nil
	}
	streams, err := w.streamEntries(name, e)
	if err != nil {
		return Entry{}, err
	}
	w.entries = append(w.entries, streams...)
	return e, nil
}

// entryFor reads one object into an entry, hashing its content when the
// options allow.
func (w *walker) entryFor(name string, d fs.DirEntry) (Entry, error) {
	info, err := d.Info()
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", name, err)
	}
	meta, err := w.fsys.Meta(name)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Path:  name,
		Type:  typeOf(info.Mode()),
		Mode:  reportedMode(info.Mode()),
		Size:  info.Size(),
		UID:   meta.UID,
		GID:   meta.GID,
		Inode: meta.ID,
		Atime: meta.Atime, Mtime: meta.Mtime, Ctime: meta.Ctime, Btime: meta.Btime,
	}
	if e.Type != TypeFile || !hashable(e.Size, w.opts) {
		return e, nil
	}
	if e.MD5, err = digest(func() (io.ReadCloser, error) { return w.fsys.OpenQuiet(name) }); err != nil {
		return Entry{}, fmt.Errorf("%s: %w", name, err)
	}
	return e, nil
}

// streamEntries is one entry per named stream of an object. A stream carries
// its object's times, as NTFS keeps them per file.
func (w *walker) streamEntries(name string, obj Entry) ([]Entry, error) {
	streams, err := w.fsys.Streams(name)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(streams))
	for _, s := range streams {
		e, err := w.streamEntry(name, obj, s)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// streamEntry is the entry for one named stream: its object's times, with the
// stream's own name, size and digest.
func (w *walker) streamEntry(name string, obj Entry, s sandbox.Stream) (Entry, error) {
	e := obj
	e.Type, e.Stream, e.Size, e.MD5 = TypeStream, s.Name, s.Size, ""
	if !hashable(s.Size, w.opts) {
		return e, nil
	}
	md5, err := digest(func() (io.ReadCloser, error) { return w.fsys.OpenStreamQuiet(name, s.Name) })
	if err != nil {
		return Entry{}, fmt.Errorf("%s:%s: %w", name, s.Name, err)
	}
	e.MD5 = md5
	return e, nil
}

// tskReadableBits are the bits The Sleuth Kit reports for an NTFS object:
// readable and executable by everyone, with write left to the read-only flag.
const tskReadableBits = 0o555

// reportedMode is the permission bits a timeline records. Where the platform
// has none of its own, the bits are written as The Sleuth Kit writes them for
// NTFS. Which platforms those are is sandbox's to know; what to write instead
// is this package's, because it is a statement about the timeline format.
func reportedMode(m fs.FileMode) fs.FileMode {
	mode := m & (fs.ModePerm | fs.ModeDir)
	if !sandbox.ModeHasPermissions {
		mode |= tskReadableBits
	}
	return mode
}

func hashable(size int64, opts Options) bool { return opts.HashLimit <= 0 || size <= opts.HashLimit }

func typeOf(m fs.FileMode) Type {
	switch {
	case m.IsRegular():
		return TypeFile
	case m.IsDir():
		return TypeDir
	case m&fs.ModeSymlink != 0:
		return TypeLink
	}
	return TypeOther
}

// digest is the MD5 of what open returns, read as a stream.
func digest(open func() (io.ReadCloser, error)) (string, error) {
	f, err := open()
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sortEntries orders entries by modification time (unknown first), then by
// path and stream, so equal times never come out in a varying order. The
// sort is stable, and both sources build their entries in a fixed order.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if !a.Mtime.Equal(b.Mtime) {
			return a.Mtime.Before(b.Mtime)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Stream < b.Stream
	})
}

// Name is the entry's name as The Sleuth Kit writes it: a leading slash,
// ":stream" for a stream, and " (deleted)" for a deleted object.
func (e Entry) Name() string {
	n := "/" + e.Path
	if e.Type == TypeStream {
		n += ":" + e.Stream
	}
	if e.Deleted {
		n += " (deleted)"
	}
	return n
}

// TSKMode is the mode as The Sleuth Kit writes it: the type from the
// directory entry, a slash, then the type and permissions from the metadata
// ("r/rrw-r--r--", "d/drwxr-xr-x").
func (e Entry) TSKMode() string {
	c := "-"
	switch e.Type {
	case TypeFile, TypeStream:
		c = "r"
	case TypeDir:
		c = "d"
	case TypeLink:
		c = "l"
	}
	return c + "/" + c + e.Mode.Perm().String()[1:]
}

func (e Entry) inode() string {
	if e.Inode == "" {
		return "0"
	}
	return e.Inode
}

// octal is the permission bits as four octal digits.
func (e Entry) octal() string {
	return fmt.Sprintf("%04s", strconv.FormatUint(uint64(e.Mode.Perm()), 8))
}
