package timeline

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// writers is every format a timeline can be written in, each with the
// extensions that imply it. Write, FormatForExtension and Formats all read it,
// so what a caller may ask for and what can actually be written cannot drift
// apart. It is a slice, not a map, because Formats is this order and that
// order is published.
var writers = []struct {
	name       string
	write      func(*Timeline, io.Writer) error
	extensions []string
}{
	{"csv", (*Timeline).WriteCSV, []string{".csv"}},
	{"txt", (*Timeline).WriteTXT, []string{".txt"}},
	{"bodyfile", (*Timeline).WriteBodyfile, []string{".bodyfile", ".body"}},
	{"macb", (*Timeline).WriteMACB, []string{".macb"}},
	{"jsonl", (*Timeline).WriteJSONL, []string{".jsonl"}},
}

// formatNames is the name of every writer, in the table's order. It is what
// Formats is built from.
func formatNames() []string {
	out := make([]string, len(writers))
	for i, w := range writers {
		out[i] = w.name
	}
	return out
}

// Write writes the timeline in format, one of Formats.
func (tl *Timeline) Write(w io.Writer, format string) error {
	for _, f := range writers {
		if f.name == format {
			return f.write(tl, w)
		}
	}
	return fmt.Errorf("unknown timeline format %q (want %s)", format, strings.Join(Formats, ", "))
}

// FormatForExtension is the format a file extension implies, if any. It is how
// --timeline picks a format when none is given.
func FormatForExtension(ext string) (string, bool) {
	for _, f := range writers {
		if slices.Contains(f.extensions, ext) {
			return f.name, true
		}
	}
	return "", false
}

// title is the first header line of the text formats: which source, and for
// an observed timeline, of which directory.
func (tl *Timeline) title() string {
	if tl.Source == SourceModelled {
		return "Modelled timeline: the times, sizes and digests the scenario intends, including what it deleted"
	}
	return "Observed timeline of " + tl.Root
}

func (tl *Timeline) unknownIs() string {
	if tl.Source == SourceModelled {
		return "a time the scenario does not control"
	}
	return "a time the file system does not report"
}

const textTime = "2006-01-02 15:04:05.000000000"

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func text(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(textTime)
}

// unix is a time as whole seconds since 1970, or 0 when it is unknown.
func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// lineSafe refuses a name that would break a line-based format.
func lineSafe(e Entry, format, forbidden string) error {
	if strings.ContainsAny(e.Name(), forbidden) {
		return fmt.Errorf("%q cannot be written in a %s timeline, whose lines it would break; use csv or jsonl", e.Name(), format)
	}
	return nil
}

// WriteCSV writes one row per entry. Times are RFC 3339 in UTC with their
// fraction of a second; an unknown time is empty.
func (tl *Timeline) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"Path", "Stream", "Type", "Size", "Mode", "UID", "GID", "Inode", "Accessed", "Modified", "Changed", "Born", "MD5", "Deleted"}); err != nil {
		return err
	}
	for _, e := range tl.Entries {
		deleted := ""
		if e.Deleted {
			deleted = "true"
		}
		if err := cw.Write([]string{
			e.Path, e.Stream, string(e.Type), strconv.FormatInt(e.Size, 10), e.TSKMode(),
			strconv.Itoa(e.UID), strconv.Itoa(e.GID), e.Inode,
			rfc(e.Atime), rfc(e.Mtime), rfc(e.Ctime), rfc(e.Btime), e.MD5, deleted,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteTXT writes a readable listing, one block per entry, led by its
// modification time.
func (tl *Timeline) WriteTXT(w io.Writer) error {
	for _, e := range tl.Entries {
		if err := lineSafe(e, "txt", "\r\n"); err != nil {
			return err
		}
	}
	b := bufio.NewWriter(w)
	fmt.Fprintln(b, tl.title())
	fmt.Fprintf(b, "Times are UTC; - is %s.\n", tl.unknownIs())
	fmt.Fprintf(b, "Entries: %d\n", len(tl.Entries))
	fmt.Fprintln(b, strings.Repeat("=", 100))
	for _, e := range tl.Entries {
		fmt.Fprintf(b, "\n%-29s [%-6s] %s\n", text(e.Mtime), e.Type, e.Name())
		md5 := e.MD5
		if md5 == "" {
			md5 = "-"
		}
		fmt.Fprintf(b, "    size %d | mode %s | uid %d | gid %d | inode %s | md5 %s\n", e.Size, e.TSKMode(), e.UID, e.GID, e.inode(), md5)
		fmt.Fprintf(b, "    accessed %s | modified %s | changed %s | born %s\n", text(e.Atime), text(e.Mtime), text(e.Ctime), text(e.Btime))
	}
	return b.Flush()
}

// WriteBodyfile writes The Sleuth Kit's bodyfile (version 3), which mactime
// reads:
//
//	MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
//
// Names are absolute from the root with forward slashes; a stream is
// "name:stream", a deleted object "name (deleted)". Times are whole seconds
// since 1970, 0 when unknown; an MD5 that was not computed is 0.
func (tl *Timeline) WriteBodyfile(w io.Writer) error {
	// Every entry is checked before anything is written, as the other text
	// formats do: a bodyfile holding only some of the entries would pass for a
	// complete one, and a buffered writer may already have flushed part of it by
	// the time a name it cannot carry is reached.
	for _, e := range tl.Entries {
		if err := lineSafe(e, "bodyfile", "|\r\n"); err != nil {
			return err
		}
	}
	b := bufio.NewWriter(w)
	for _, e := range tl.Entries {
		md5 := e.MD5
		if md5 == "" {
			md5 = "0"
		}
		fmt.Fprintf(b, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d\n",
			md5, e.Name(), e.inode(), e.TSKMode(), e.UID, e.GID, e.Size,
			unix(e.Atime), unix(e.Mtime), unix(e.Ctime), unix(e.Btime))
	}
	return b.Flush()
}

// WriteMACB writes one line per entry and distinct time, in time order, as
// mactime does: the flags say which of the entry's times fall at that
// instant (M modified, A accessed, C changed, B born), so an entry whose
// four times are equal has a single MACB line and one with four different
// times has four. Unknown times have no line.
func (tl *Timeline) WriteMACB(w io.Writer) error {
	var lines []macbLine
	for i := range tl.Entries {
		e := &tl.Entries[i]
		if err := lineSafe(*e, "macb", "\r\n"); err != nil {
			return err
		}
		lines = append(lines, macbRows(e)...)
	}
	sort.SliceStable(lines, func(i, j int) bool {
		a, b := lines[i], lines[j]
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		return a.e.Name() < b.e.Name()
	})

	b := bufio.NewWriter(w)
	fmt.Fprintln(b, tl.title())
	fmt.Fprintln(b, "MACB: M modified, A accessed, C changed (metadata), B born (created). Times are UTC.")
	fmt.Fprintf(b, "%-29s %12s %-4s %-12s %-6s %-6s %-10s %s\n", "Date", "Size", "MACB", "Mode", "UID", "GID", "Inode", "Name")
	for _, l := range lines {
		fmt.Fprintf(b, "%-29s %12d %-4s %-12s %-6d %-6d %-10s %s\n",
			l.at.UTC().Format(textTime), l.e.Size, l.flags, l.e.TSKMode(), l.e.UID, l.e.GID, l.e.inode(), l.e.Name())
	}
	return b.Flush()
}

type jsonEntry struct {
	Path    string `json:"path"`
	Stream  string `json:"stream,omitempty"`
	Type    Type   `json:"type"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Inode   string `json:"inode,omitempty"`
	Atime   string `json:"atime,omitempty"`
	Mtime   string `json:"mtime,omitempty"`
	Ctime   string `json:"ctime,omitempty"`
	Crtime  string `json:"crtime,omitempty"`
	MD5     string `json:"md5,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// WriteJSONL writes one JSON object per entry. The mode is octal; an
// unknown time, and an MD5 that was not computed, are left out.
func (tl *Timeline) WriteJSONL(w io.Writer) error {
	b := bufio.NewWriter(w)
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false)
	for _, e := range tl.Entries {
		if err := enc.Encode(jsonEntry{
			Path: e.Path, Stream: e.Stream, Type: e.Type, Size: e.Size, Mode: e.octal(),
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			Atime: rfc(e.Atime), Mtime: rfc(e.Mtime), Ctime: rfc(e.Ctime), Crtime: rfc(e.Btime),
			MD5: e.MD5, Deleted: e.Deleted,
		}); err != nil {
			return err
		}
	}
	return b.Flush()
}

// macbFields names the four times in the order the MACB view shows them:
// modified, accessed, changed, born.
const macbFields = "MACB"

// macbFlags is the MACB column for one instant: every field sharing it, from i
// onwards, marked with its letter and recorded in done. Fields are marked once,
// so an instant several of them share produces one row rather than four.
func macbFlags(times [4]time.Time, t time.Time, i int, done *[4]bool) string {
	flags := []byte("....")
	for j := i; j < len(times); j++ {
		if times[j].IsZero() || !times[j].Equal(t) {
			continue
		}
		flags[j] = macbFields[j]
		done[j] = true
	}
	return string(flags)
}

// macbLine is one row of the MACB view: an instant, the fields that share it,
// and the entry it belongs to.
type macbLine struct {
	at    time.Time
	flags string
	e     *Entry
}

// macbRows is one row per distinct instant among an entry's four times, so a
// file whose times all match appears once rather than four times.
func macbRows(e *Entry) []macbLine {
	times := [4]time.Time{e.Mtime, e.Atime, e.Ctime, e.Btime}
	var done [4]bool
	var out []macbLine
	for i, t := range times {
		if t.IsZero() || done[i] {
			continue
		}
		out = append(out, macbLine{t, macbFlags(times, t, i, &done), e})
	}
	return out
}
