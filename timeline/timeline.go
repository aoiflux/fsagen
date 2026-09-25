package timeline

import (
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
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

// Generate walks the filesystem and creates a complete timeline
func Generate(root string) (*Timeline, error) {
	tl := &Timeline{
		Root:    root,
		Entries: make([]Entry, 0),
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files we can't access
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}

		entry := Entry{
			Path:  relPath,
			Size:  info.Size(),
			Mode:  info.Mode(),
			IsDir: info.IsDir(),
		}

		// Get timestamps, in UTC so the output does not depend on the
		// machine's time zone.
		if stat, ok := getFileTimes(info); ok {
			entry.Atime = utc(stat.Atime)
			entry.Mtime = utc(stat.Mtime)
			entry.Ctime = utc(stat.Ctime)
		} else {
			// Fallback to ModTime
			entry.Mtime = utc(info.ModTime())
		}

		// Calculate MD5 for files only
		if !info.IsDir() && info.Size() > 0 && info.Size() < 100*1024*1024 { // Skip files > 100MB
			if hash, err := calculateMD5(path); err == nil {
				entry.MD5 = hash
			}
		}

		// Check for Alternate Data Streams on Windows
		if runtime.GOOS == "windows" && !info.IsDir() {
			if streams, err := findADS(path); err == nil {
				entry.ADSNames = streams
			}
		}

		tl.Entries = append(tl.Entries, entry)
		return nil
	})

	if err != nil {
		return nil, err
	}

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

// calculateMD5 computes the MD5 hash of a file
func calculateMD5(path string) (string, error) {
	f, err := os.Open(path)
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

// findADS finds alternate data streams on Windows
func findADS(path string) ([]string, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}

	// Check common stream names
	commonStreams := []string{"Zone.Identifier", "metadata", "content"}
	var found []string

	for _, stream := range commonStreams {
		adsPath := path + ":" + stream
		if _, err := os.Stat(adsPath); err == nil {
			found = append(found, stream)
		}
	}

	return found, nil
}
