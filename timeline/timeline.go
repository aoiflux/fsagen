package timeline

import (
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/sandbox"
)

// Entry represents a single timeline entry for a file or directory
type Entry struct {
	Path     string
	Size     int64
	Mode     os.FileMode
	Atime    time.Time
	Mtime    time.Time
	Ctime    time.Time // Change time (on Windows, this is creation time)
	MD5      string
	IsDir    bool
	ADSNames []string // Alternate Data Stream names (Windows only)
}

// Timeline holds all timeline entries
type Timeline struct {
	Root    string
	Entries []Entry
}

// Generate walks the tree under root and records every file and directory.
//
// It reads the tree through the sandbox, so it cannot leave root, and every
// directory listing and file digest goes through a handle that leaves access
// times alone where the platform allows (Windows always; Linux when the
// caller owns the file). Reading the corpus therefore does not change the
// times it is reading.
func Generate(root string) (*Timeline, error) {
	tl := &Timeline{
		Root:    root,
		Entries: make([]Entry, 0),
	}

	fsys, err := sandbox.Open(root)
	if err != nil {
		return nil, err
	}
	defer fsys.Close()

	// The root itself, described as the file system reports it: its times
	// belong to whoever created it.
	if info, err := os.Lstat(root); err == nil {
		e := Entry{Path: ".", Size: info.Size(), Mode: info.Mode(), IsDir: info.IsDir()}
		if stat, ok := getFileTimes(info); ok {
			e.Atime, e.Mtime, e.Ctime = utc(stat.Atime), utc(stat.Mtime), utc(stat.Ctime)
		} else {
			e.Mtime = utc(info.ModTime())
		}
		tl.Entries = append(tl.Entries, e)
	}

	var walk func(dir string)
	walk = func(dir string) {
		entries, err := fsys.ReadDirQuiet(dir)
		if err != nil {
			return // skip what cannot be read
		}
		for _, d := range entries {
			name := path.Join(dir, d.Name())
			info, err := d.Info()
			if err != nil {
				continue
			}
			entry := Entry{
				Path:  filepath.FromSlash(name),
				Size:  info.Size(),
				Mode:  info.Mode(),
				IsDir: info.IsDir(),
			}
			// Times in UTC, so the output does not depend on the machine's
			// time zone. The Ctime column holds the creation time on
			// Windows and the change time elsewhere, as it always has.
			if t, err := fsys.Times(name); err == nil {
				entry.Atime, entry.Mtime = utc(t.Atime), utc(t.Mtime)
				if runtime.GOOS == "windows" {
					entry.Ctime = utc(t.Btime)
				} else {
					entry.Ctime = utc(t.Ctime)
				}
			} else {
				entry.Mtime = utc(info.ModTime())
			}

			if !info.IsDir() && info.Size() > 0 && info.Size() < 100*1024*1024 { // Skip files > 100MB
				if hash, err := calculateMD5(fsys, name); err == nil {
					entry.MD5 = hash
				}
			}
			if !info.IsDir() {
				if streams, err := fsys.Streams(name); err == nil {
					for _, s := range streams {
						entry.ADSNames = append(entry.ADSNames, s.Name)
					}
				}
			}

			tl.Entries = append(tl.Entries, entry)
			if info.IsDir() {
				walk(name)
			}
		}
	}
	walk(".")

	sortEntries(tl.Entries)
	return tl, nil
}

// sortEntries orders entries by modification time, and entries with the
// same time by path, so equal times never come out in a varying order.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if !a.Mtime.Equal(b.Mtime) {
			return a.Mtime.Before(b.Mtime)
		}
		return a.Path < b.Path
	})
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

// WriteCSV writes timeline to CSV format
func (tl *Timeline) WriteCSV(w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	if err := writer.Write([]string{
		"Path",
		"Size",
		"Mode",
		"Accessed",
		"Modified",
		"Changed/Created",
		"MD5",
		"Type",
		"ADS",
	}); err != nil {
		return err
	}

	for _, e := range tl.Entries {
		fileType := "file"
		if e.IsDir {
			fileType = "dir"
		}

		adsStr := ""
		if len(e.ADSNames) > 0 {
			adsStr = strings.Join(e.ADSNames, ";")
		}

		if err := writer.Write([]string{
			e.Path,
			fmt.Sprintf("%d", e.Size),
			e.Mode.String(),
			e.Atime.Format(time.RFC3339),
			e.Mtime.Format(time.RFC3339),
			e.Ctime.Format(time.RFC3339),
			e.MD5,
			fileType,
			adsStr,
		}); err != nil {
			return err
		}
	}

	return nil
}

// WriteTXT writes a human-readable timeline
func (tl *Timeline) WriteTXT(w io.Writer) error {
	fmt.Fprintf(w, "Forensic Timeline for: %s\n", tl.Root)
	fmt.Fprintln(w, "Times are UTC.")
	fmt.Fprintf(w, "Total entries: %d\n", len(tl.Entries))
	fmt.Fprintln(w, strings.Repeat("=", 120))
	fmt.Fprintln(w)

	for _, e := range tl.Entries {
		typeStr := "[FILE]"
		if e.IsDir {
			typeStr = "[DIR ]"
		}

		if e.IsDir {
			fmt.Fprintf(w, "%s %s %s\n", e.Mtime.Format("2006-01-02 15:04:05"), typeStr, e.Path)
		} else {
			fmt.Fprintf(w, "%s %s %s\n", e.Mtime.Format("2006-01-02 15:04:05"), typeStr, e.Path)
			fmt.Fprintf(w, "         Size: %d bytes | Mode: %s | MD5: %s\n", e.Size, e.Mode.String(), e.MD5)
			fmt.Fprintf(w, "         Access: %s | Modified: %s | Changed: %s\n",
				e.Atime.Format("2006-01-02 15:04:05"),
				e.Mtime.Format("2006-01-02 15:04:05"),
				e.Ctime.Format("2006-01-02 15:04:05"))
			if len(e.ADSNames) > 0 {
				fmt.Fprintf(w, "         ADS: %s\n", strings.Join(e.ADSNames, ", "))
			}
		}
		fmt.Fprintln(w)
	}

	return nil
}

// WriteBodyfile writes timeline in bodyfile format (compatible with mactime from The Sleuth Kit)
// Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
func (tl *Timeline) WriteBodyfile(w io.Writer) error {
	for _, e := range tl.Entries {
		// For simplicity, use 0 for inode, UID, GID (not meaningful in our context)
		inode := 0
		uid := 0
		gid := 0

		// Mode as octal string
		modeStr := fmt.Sprintf("%o", e.Mode.Perm())

		// Times as Unix timestamps
		atime := e.Atime.Unix()
		mtime := e.Mtime.Unix()
		ctime := e.Ctime.Unix()
		crtime := e.Ctime.Unix() // Use ctime as creation time

		if atime == 0 {
			atime = mtime
		}
		if ctime == 0 {
			ctime = mtime
		}

		fmt.Fprintf(w, "%s|%s|%d|%s|%d|%d|%d|%d|%d|%d|%d\n",
			e.MD5,
			e.Path,
			inode,
			modeStr,
			uid,
			gid,
			e.Size,
			atime,
			mtime,
			ctime,
			crtime)
	}

	return nil
}

// WriteMACB writes a MACB (Modified, Accessed, Changed, Birth) timeline format
func (tl *Timeline) WriteMACB(w io.Writer) error {
	type macbEntry struct {
		timestamp time.Time
		macbType  string
		path      string
		size      int64
		md5       string
	}

	var entries []macbEntry

	for _, e := range tl.Entries {
		if !e.Mtime.IsZero() {
			entries = append(entries, macbEntry{e.Mtime, "M...", e.Path, e.Size, e.MD5})
		}
		if !e.Atime.IsZero() && !e.Atime.Equal(e.Mtime) {
			entries = append(entries, macbEntry{e.Atime, ".A..", e.Path, e.Size, e.MD5})
		}
		if !e.Ctime.IsZero() && !e.Ctime.Equal(e.Mtime) && !e.Ctime.Equal(e.Atime) {
			entries = append(entries, macbEntry{e.Ctime, "..C.", e.Path, e.Size, e.MD5})
		}
	}

	// Sort by timestamp; the same instant keeps path order.
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if !a.timestamp.Equal(b.timestamp) {
			return a.timestamp.Before(b.timestamp)
		}
		return a.path < b.path
	})

	fmt.Fprintf(w, "MACB Timeline for: %s\n", tl.Root)
	fmt.Fprintln(w, "Times are UTC.")
	fmt.Fprintln(w, strings.Repeat("=", 120))
	fmt.Fprintf(w, "%-20s %-6s %-60s %12s %s\n", "Timestamp", "Type", "Path", "Size", "MD5")
	fmt.Fprintln(w, strings.Repeat("-", 120))

	for _, e := range entries {
		fmt.Fprintf(w, "%-20s %-6s %-60s %12d %s\n",
			e.timestamp.Format("2006-01-02 15:04:05"),
			e.macbType,
			e.path,
			e.size,
			e.md5)
	}

	return nil
}

// calculateMD5 computes the MD5 hash of a file without moving its access
// time where the platform allows.
func calculateMD5(fsys *sandbox.FS, name string) (string, error) {
	f, err := fsys.OpenQuiet(name)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
