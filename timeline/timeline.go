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
	"runtime"
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

// Formats lists the formats Write accepts.
var Formats = []string{"csv", "txt", "bodyfile", "macb", "jsonl"}

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

	tl := &Timeline{Source: SourceObserved, Root: fsys.Dir()}
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := fsys.ReadDirQuiet(dir)
		if err != nil {
			return fmt.Errorf("list %s: %w", dir, err)
		}
		for _, d := range entries {
			name := path.Join(dir, d.Name())
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			meta, err := fsys.Meta(name)
			if err != nil {
				return err
			}
			mode := info.Mode() & (fs.ModePerm | fs.ModeDir)
			if runtime.GOOS == "windows" {
				// Windows has no permission bits, only a read-only flag.
				// Write them as The Sleuth Kit does for NTFS: everything,
				// less the write bits of a read-only file.
				mode |= 0o555
			}
			e := Entry{
				Path:  name,
				Type:  typeOf(info.Mode()),
				Mode:  mode,
				Size:  info.Size(),
				UID:   meta.UID,
				GID:   meta.GID,
				Inode: meta.ID,
				Atime: meta.Atime, Mtime: meta.Mtime, Ctime: meta.Ctime, Btime: meta.Btime,
			}
			if e.Type == TypeFile && hashable(e.Size, opts) {
				if e.MD5, err = digest(func() (io.ReadCloser, error) { return fsys.OpenQuiet(name) }); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
			tl.Entries = append(tl.Entries, e)

			if e.Type == TypeFile || e.Type == TypeDir {
				streams, err := fsys.Streams(name)
				if err != nil {
					return err
				}
				for _, s := range streams {
					se := e
					se.Type, se.Stream, se.Size, se.MD5 = TypeStream, s.Name, s.Size, ""
					if hashable(s.Size, opts) {
						if se.MD5, err = digest(func() (io.ReadCloser, error) { return fsys.OpenStreamQuiet(name, s.Name) }); err != nil {
							return fmt.Errorf("%s:%s: %w", name, s.Name, err)
						}
					}
					tl.Entries = append(tl.Entries, se)
				}
			}
			if e.Type == TypeDir {
				if err := walk(name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, fmt.Errorf("timeline of %s: %w", root, err)
	}
	sortEntries(tl.Entries)
	return tl, nil
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
