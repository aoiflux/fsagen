package oracle

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// maxLine is the longest line a tool's output may hold. Plaso's extra field
// can run long; a line past this is an error, never silently cut.
const maxLine = 16 << 20

// Row is one entry a tool reported: a name, or a stream of one, with what
// the tool said about it.
type Row struct {
	// Line is where it starts in the tool's output.
	Line int
	// Path is the name as reported, with its slashes made forward.
	Path string
	// Stream names a stream when the format keeps it apart from the path.
	// Formats that append it to the path with a colon set Whole instead, and
	// the stream is separated once the path is known.
	Stream string
	Whole  bool
	// Kind is file, dir or link; "" when the tool did not say.
	Kind    string
	Deleted bool
	// FileName marks an NTFS $FILE_NAME record of the entry, not the entry.
	FileName bool
	Target   string
	Inode    string
	// Links is the number of names the tool says the object has; 0 when it
	// did not say.
	Links       int
	MD5, SHA256 string
	Times       times
}

// format is one kind of tool output this package reads.
type format struct {
	name string
	read func([]byte) ([]Row, error)
	// resolution is the finest time the format carries, which is the
	// tolerance a time is scored with unless one is given.
	resolution time.Duration
}

// formats is every format, in the order they are documented.
var formats = []format{
	{"bodyfile", readBodyfile, time.Second},
	{"l2tcsv", readL2TCSV, time.Second},
	{"dynamic", readDynamic, time.Microsecond},
	{"timesketch", readTimesketch, time.Microsecond},
	{"jsonl", readJSONL, 0},
	{"csv", readCSV, 0},
}

// FormatNames lists the formats, in their documented order.
func FormatNames() []string {
	out := make([]string, len(formats))
	for i, f := range formats {
		out[i] = f.name
	}
	return out
}

func formatNamed(name string) (format, bool) {
	for _, f := range formats {
		if f.name == name {
			return f, true
		}
	}
	return format{}, false
}

// l2tFields is the header of Plaso's l2tcsv output, which never changes.
var l2tFields = []string{"date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short", "desc", "version", "filename", "inode", "notes", "format", "extra"}

// fsagenCSVFields is the header of fsagen's own CSV timeline.
var fsagenCSVFields = []string{"Path", "Stream", "Type", "Size", "Mode", "UID", "GID", "Inode", "Accessed", "Modified", "Changed", "Born", "MD5", "Deleted"}

// detect names the format of a tool's output from its first line.
func detect(data []byte) (format, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxLine)
	for sc.Scan() {
		line := strings.TrimSuffix(strings.TrimPrefix(sc.Text(), "\ufeff"), "\r")
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "{"):
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				return format{}, fmt.Errorf("the first line looks like JSON but is not: %w", err)
			}
			if _, ok := obj["timestamp_desc"]; ok {
				return mustFormat("timesketch"), nil
			}
			if _, ok := obj["path"]; ok {
				return mustFormat("jsonl"), nil
			}
			return format{}, errors.New("the first line is JSON, but neither a Timesketch event (no timestamp_desc) nor an fsagen timeline entry (no path)")
		case line == strings.Join(l2tFields, ","):
			return mustFormat("l2tcsv"), nil
		case line == strings.Join(fsagenCSVFields, ","):
			return mustFormat("csv"), nil
		}
		header := strings.Split(line, ",")
		if slices.Contains(header, "datetime") && slices.Contains(header, "timestamp_desc") {
			return mustFormat("dynamic"), nil
		}
		if strings.Count(line, "|") >= 10 {
			return mustFormat("bodyfile"), nil
		}
		return format{}, errors.New("cannot tell the format from the first line; give --format")
	}
	if err := sc.Err(); err != nil {
		return format{}, err
	}
	return format{}, errors.New("the tool's output is empty")
}

// lines calls fn with each line and its number, without the line ending.
func lines(data []byte, fn func(n int, line string) error) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxLine)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if err := fn(n, line); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w (a line is longer than %d bytes?)", err, maxLine)
	}
	return nil
}

// readBodyfile reads The Sleuth Kit's bodyfile, version 3, as fls -m and
// fsagen write it:
//
//	MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
//
// The name can hold "|", so the fields are counted from both ends. TSK marks
// what it says about a name by appending, in this order: ":stream" for a
// stream, " ($FILE_NAME)" for an NTFS $FILE_NAME record, " -> target" for a
// link, and " (deleted)" or " (deleted-realloc)" for a deleted entry.
// Lines starting with # are comments.
func readBodyfile(data []byte) ([]Row, error) {
	var out []Row
	err := lines(data, func(n int, line string) error {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			return nil
		}
		f := strings.Split(line, "|")
		k := len(f)
		if k < 11 {
			return fmt.Errorf("a bodyfile line has 11 |-separated fields, and this one has %d", k)
		}
		r := Row{Line: n, Whole: true, Inode: f[k-9]}
		setDigest(&r, f[0])
		r.Kind = tskKind(f[k-8])
		for i, s := range f[k-4:] {
			t, err := unixTime(s)
			if err != nil {
				return fmt.Errorf("%s %q: %w", timeNames[i], s, err)
			}
			r.Times[i] = t
		}
		name := strings.Join(f[1:k-9], "|")
		for {
			if s, ok := strings.CutSuffix(name, " (deleted)"); ok {
				name, r.Deleted = s, true
			} else if s, ok := strings.CutSuffix(name, " (deleted-realloc)"); ok {
				name, r.Deleted = s, true
			} else {
				break
			}
		}
		if r.Kind == "link" {
			if i := strings.Index(name, " -> "); i >= 0 {
				name, r.Target = name[:i], name[i+len(" -> "):]
			}
		}
		if s, ok := strings.CutSuffix(name, " ($FILE_NAME)"); ok {
			name, r.FileName = s, true
		}
		r.Path = name
		out = append(out, r)
		return nil
	})
	return out, err
}

// tskKind is the kind a TSK mode string gives: its first letter is the
// type from the directory entry, and after the slash comes the type from
// the metadata, which is used when the first is unknown.
func tskKind(mode string) string {
	for _, c := range []byte(strings.Replace(mode, "/", "", 1)) {
		switch c {
		case 'r':
			return "file"
		case 'd':
			return "dir"
		case 'l':
			return "link"
		case '-':
			continue
		}
		return ""
	}
	return ""
}

// setDigest records a bodyfile's digest column, which TSK fills with an MD5
// (0 when it computed none); some tools put a SHA-256 there instead.
func setDigest(r *Row, s string) {
	switch {
	case len(s) == 32 && isHex(s):
		r.MD5 = strings.ToLower(s)
	case len(s) == 64 && isHex(s):
		r.SHA256 = strings.ToLower(s)
	}
}

func isHex(s string) bool {
	for _, c := range []byte(s) {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// unixTime reads seconds since 1970, with any fraction, exactly. 0 is
// unknown, as in a bodyfile.
func unixTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	whole, frac, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("not a number of seconds")
	}
	var nsec int64
	if frac != "" {
		if len(frac) > 9 || !isDigits(frac) {
			return time.Time{}, errors.New("the fraction is not up to nine digits")
		}
		nsec, _ = strconv.ParseInt(frac+strings.Repeat("0", 9-len(frac)), 10, 64)
		if strings.HasPrefix(whole, "-") {
			nsec = -nsec
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}, nil
	}
	return time.Unix(sec, nsec).UTC(), nil
}

func isDigits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// plasoDescs map Plaso's timestamp descriptions to the four times. Plaso
// gives a file-stat event one of these, or a time fsagen does not keep
// (Added Time, Backup Time, Content Deletion Time), which is not scored.
var plasoDescs = map[string]int{
	"Last Access Time":           atime,
	"Content Modification Time":  mtime,
	"Metadata Modification Time": ctime,
	"Creation Time":              crtime,
}

// macbLetters map the letters of Plaso's MACB column to the four times.
var macbLetters = map[byte]int{'M': mtime, 'A': atime, 'C': ctime, 'B': crtime}

// Plaso writes what it knows about a file-stat event into its message (the
// l2tcsv desc column): "Type: file", "Number of links: 2", "(unallocated)"
// for a deleted entry, and for an NTFS MFT entry the attribute the times
// came from.
var (
	plasoType     = regexp.MustCompile(`\bType: (\w+)`)
	plasoLinks    = regexp.MustCompile(`\bNumber of links: (\d+)`)
	plasoFileName = regexp.MustCompile(`\bAttribute name: \$FILE_NAME\b`)
	// plasoSource is the path-spec type Plaso puts before a display name:
	// OS, TSK, NTFS and so on, after a shadow copy's VSSn: if there is one.
	// A drive letter is one letter, so is never taken for one.
	plasoSource = regexp.MustCompile(`^(VSS\d+:)?[A-Z][A-Z0-9_]+:`)
)

// fromMessage records what a Plaso message says about the entry.
func fromMessage(r *Row, msg string) {
	if m := plasoType.FindStringSubmatch(msg); m != nil {
		r.Kind = dfvfsKind(m[1])
	}
	if m := plasoLinks.FindStringSubmatch(msg); m != nil {
		r.Links, _ = strconv.Atoi(m[1])
	}
	if strings.Contains(msg, "(unallocated)") {
		r.Deleted = true
	}
	if plasoFileName.MatchString(msg) {
		r.FileName = true
	}
}

// dfvfsKind maps a dfVFS file entry type, and fsagen's own type names, to a
// kind.
func dfvfsKind(s string) string {
	switch s {
	case "file", "stream":
		return "file"
	case "directory", "dir":
		return "dir"
	case "link":
		return "link"
	}
	return ""
}

// displayPath is the path in a Plaso display name, without the path-spec
// type before it.
func displayPath(s string) string {
	return plasoSource.ReplaceAllString(s, "")
}

// plasoField is a value from a Plaso CSV, where "-" is a missing one.
func plasoField(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// readL2TCSV reads Plaso's l2tcsv output. Plaso neither quotes nor escapes
// it: a comma in a value is written as a space, so every line splits into
// the header's 17 fields. One line is one instant of one entry, its MACB
// column saying which of the entry's times fall then; the lines of an
// entry are folded back into one row. Only file-stat lines (source FILE)
// are read, and only lines in UTC.
func readL2TCSV(data []byte) ([]Row, error) {
	var events []Row
	err := lines(data, func(n int, line string) error {
		if n == 1 {
			if line != strings.Join(l2tFields, ",") {
				return errors.New("this is not Plaso's l2tcsv header")
			}
			return nil
		}
		if line == "" {
			return nil
		}
		f := strings.Split(line, ",")
		if len(f) != len(l2tFields) {
			return fmt.Errorf("an l2tcsv line has %d fields, and this one has %d", len(l2tFields), len(f))
		}
		if f[4] != "FILE" || f[0] == "00/00/0000" {
			return nil
		}
		if f[2] != "UTC" {
			return fmt.Errorf("the time zone is %q; write the timeline in UTC (psort --output_time_zone UTC)", f[2])
		}
		at, err := time.Parse("01/02/2006 15:04:05", f[0]+" "+f[1])
		if err != nil {
			return fmt.Errorf("date and time %q %q: %w", f[0], f[1], err)
		}
		r := Row{Line: n, Whole: true, Inode: plasoField(f[13])}
		r.Path = plasoField(f[12])
		if r.Path == "" {
			name, _, _ := strings.Cut(f[10], " Type: ")
			r.Path = displayPath(name)
		}
		fromMessage(&r, f[10])
		extra := plasoExtra(f[16])
		r.MD5, r.SHA256 = strings.ToLower(extra["md5_hash"]), strings.ToLower(extra["sha256_hash"])
		if extra["is_allocated"] == "False" {
			r.Deleted = true
		}
		set := false
		for _, d := range strings.Split(f[6], "; ") {
			if i, ok := plasoDescs[d]; ok {
				r.Times[i], set = at, true
			}
		}
		if !set {
			for i := range len(f[3]) {
				if t, ok := macbLetters[f[3][i]]; ok {
					r.Times[t] = at
				}
			}
		}
		events = append(events, r)
		return nil
	})
	return foldEvents(events), err
}

// plasoExtra splits l2tcsv's extra column, "name: value; name: value".
func plasoExtra(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, "; ") {
		if k, v, ok := strings.Cut(kv, ": "); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// readDynamic reads Plaso's dynamic CSV, psort's default output: a header
// naming the fields, then one line per event, unquoted, as l2tcsv is. Its
// default fields are datetime, timestamp_desc, source, source_long,
// message, parser, display_name and tag; filename, inode, is_allocated,
// md5_hash, sha256_hash and number_of_links are read too when they were
// asked for (psort --fields or --additional_fields). Only file-stat events
// are read: source FILE, or failing that the filestat or mft parser.
func readDynamic(data []byte) ([]Row, error) {
	var events []Row
	col := map[string]int{}
	get := func(f []string, name string) string {
		if i, ok := col[name]; ok {
			return plasoField(f[i])
		}
		return ""
	}
	err := lines(data, func(n int, line string) error {
		if n == 1 {
			for i, name := range strings.Split(line, ",") {
				col[name] = i
			}
			for _, need := range []string{"datetime", "timestamp_desc"} {
				if _, ok := col[need]; !ok {
					return fmt.Errorf("the header has no %s field", need)
				}
			}
			_, fn := col["filename"]
			_, dn := col["display_name"]
			if !fn && !dn {
				return errors.New("the header has neither a filename nor a display_name field")
			}
			return nil
		}
		if line == "" {
			return nil
		}
		f := strings.Split(line, ",")
		if len(f) != len(col) {
			return fmt.Errorf("the header has %d fields, and this line has %d", len(col), len(f))
		}
		if !fileStat(get(f, "source"), get(f, "parser")) {
			return nil
		}
		dt := get(f, "datetime")
		if dt == "" || dt == "Invalid" || strings.HasPrefix(dt, "0000-00-00") {
			return nil
		}
		at, err := time.Parse(time.RFC3339Nano, dt)
		if err != nil {
			return fmt.Errorf("datetime %q: %w", dt, err)
		}
		r := Row{Line: n, Whole: true, Inode: get(f, "inode")}
		if r.Path = get(f, "filename"); r.Path == "" {
			r.Path = displayPath(get(f, "display_name"))
		}
		fromMessage(&r, get(f, "message"))
		if k := dfvfsKind(get(f, "file_entry_type")); k != "" {
			r.Kind = k
		}
		if s := get(f, "number_of_links"); s != "" {
			r.Links, _ = strconv.Atoi(s)
		}
		if strings.EqualFold(get(f, "is_allocated"), "false") {
			r.Deleted = true
		}
		r.MD5, r.SHA256 = strings.ToLower(get(f, "md5_hash")), strings.ToLower(get(f, "sha256_hash"))
		if i, ok := plasoDescs[get(f, "timestamp_desc")]; ok {
			r.Times[i] = at.UTC()
		}
		events = append(events, r)
		return nil
	})
	return foldEvents(events), err
}

// fileStat says whether a Plaso event describes a file-system entry. Its
// short source says so when the output has one (FILE); otherwise the
// parser that made it does.
func fileStat(source, parser string) bool {
	if source != "" {
		return source == "FILE"
	}
	if parser != "" {
		last := parser[strings.LastIndex(parser, "/")+1:]
		return last == "filestat" || last == "mft"
	}
	return true
}

// readTimesketch reads JSON lines with one event per entry and time: what
// fsagen's timesketch timeline holds, and what Plaso's json_line output and
// a Timesketch export hold. Only file-stat events are read (data_type
// fs:stat or one of its variants, when the event has one).
func readTimesketch(data []byte) ([]Row, error) {
	var events []Row
	err := lines(data, func(n int, line string) error {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		var ev map[string]any
		if err := dec.Decode(&ev); err != nil {
			return err
		}
		if dt, ok := ev["data_type"].(string); ok && !strings.HasPrefix(dt, "fs:stat") {
			return nil
		}
		at, err := eventTime(ev)
		if err != nil {
			return err
		}
		r := Row{Line: n, Inode: jsonString(ev["inode"])}
		r.Path = jsonString(ev["filename"])
		if s, ok := ev["stream"]; ok {
			r.Stream = jsonString(s)
		} else {
			r.Whole = true
		}
		if r.Path == "" {
			r.Path, r.Whole = displayPath(jsonString(ev["display_name"])), true
		}
		r.Kind = dfvfsKind(jsonString(ev["file_entry_type"]))
		if a, ok := ev["is_allocated"].(bool); ok && !a {
			r.Deleted = true
		}
		r.MD5 = strings.ToLower(firstOf(ev, "md5", "md5_hash"))
		r.SHA256 = strings.ToLower(firstOf(ev, "sha256", "sha256_hash"))
		if s := jsonString(ev["number_of_links"]); s != "" {
			r.Links, _ = strconv.Atoi(s)
		}
		if jsonString(ev["attribute_type"]) == "48" || jsonString(ev["attribute_name"]) == "$FILE_NAME" {
			r.FileName = true
		}
		if i, ok := plasoDescs[jsonString(ev["timestamp_desc"])]; ok && !at.IsZero() {
			r.Times[i] = at
		}
		events = append(events, r)
		return nil
	})
	return foldEvents(events), err
}

// eventTime is an event's time: its integer microseconds when it has them,
// which Plaso and Timesketch both write, else its datetime.
func eventTime(ev map[string]any) (time.Time, error) {
	if n, ok := ev["timestamp"].(json.Number); ok {
		us, err := n.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("timestamp %s is not a whole number of microseconds", n)
		}
		if us == 0 {
			return time.Time{}, nil
		}
		return time.UnixMicro(us).UTC(), nil
	}
	s := jsonString(ev["datetime"])
	if s == "" {
		return time.Time{}, errors.New("the event has neither a timestamp nor a datetime")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("datetime %q: %w", s, err)
	}
	return t.UTC(), nil
}

// jsonString is a JSON value as text: a string as it is, a number as
// written, anything else empty.
func jsonString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func firstOf(ev map[string]any, names ...string) string {
	for _, n := range names {
		if s := jsonString(ev[n]); s != "" {
			return s
		}
	}
	return ""
}

// foldEvents folds the events of formats that give one line per time back
// into one row per entry: per path, stream, deletion, record and inode, so
// two deleted entries a tool tells apart stay apart.
func foldEvents(events []Row) []Row {
	var out []Row
	index := map[string]int{}
	for _, ev := range events {
		key := strings.Join([]string{ev.Path, ev.Stream, strconv.FormatBool(ev.Deleted), strconv.FormatBool(ev.FileName), ev.Inode}, "\x00")
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, ev)
			continue
		}
		r := &out[i]
		for t := range r.Times {
			if r.Times[t].IsZero() {
				r.Times[t] = ev.Times[t]
			}
		}
		for _, f := range [][2]*string{{&r.Kind, &ev.Kind}, {&r.Target, &ev.Target}, {&r.MD5, &ev.MD5}, {&r.SHA256, &ev.SHA256}} {
			if *f[0] == "" {
				*f[0] = *f[1]
			}
		}
		if r.Links == 0 {
			r.Links = ev.Links
		}
	}
	return out
}

// jsonlEntry is one line of fsagen's jsonl timeline.
type jsonlEntry struct {
	Path       string `json:"path"`
	Stream     string `json:"stream"`
	Type       string `json:"type"`
	Inode      string `json:"inode"`
	Atime      string `json:"atime"`
	Mtime      string `json:"mtime"`
	Ctime      string `json:"ctime"`
	Crtime     string `json:"crtime"`
	MD5        string `json:"md5"`
	Deleted    bool   `json:"deleted"`
	LinkTarget string `json:"link_target"`
	Links      int    `json:"links"`
	FileName   bool   `json:"file_name"`
}

// readJSONL reads fsagen's jsonl timeline: one entry per line, its path
// relative to the root it describes.
func readJSONL(data []byte) ([]Row, error) {
	var out []Row
	err := lines(data, func(n int, line string) error {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		var e jsonlEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return err
		}
		r := Row{Line: n, Path: e.Path, Stream: e.Stream, Kind: dfvfsKind(e.Type), Deleted: e.Deleted, Target: e.LinkTarget, Inode: e.Inode, Links: e.Links, MD5: e.MD5, FileName: e.FileName}
		for i, s := range [4]string{e.Atime, e.Mtime, e.Ctime, e.Crtime} {
			t, err := rfcTime(s)
			if err != nil {
				return fmt.Errorf("%s: %w", timeNames[i], err)
			}
			r.Times[i] = t
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

// readCSV reads fsagen's CSV timeline.
func readCSV(data []byte) ([]Row, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = len(fsagenCSVFields)
	head, err := cr.Read()
	if err != nil {
		return nil, err
	}
	if strings.Join(head, ",") != strings.Join(fsagenCSVFields, ",") {
		return nil, errors.New("this is not fsagen's CSV timeline header")
	}
	var out []Row
	for {
		f, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		r := Row{Line: line, Path: f[0], Stream: f[1], Kind: dfvfsKind(f[2]), Inode: f[7], MD5: f[12], Deleted: f[13] == "true", FileName: f[2] == "filename"}
		for i, s := range f[8:12] {
			t, err := rfcTime(s)
			if err != nil {
				return nil, fmt.Errorf("line %d: %s: %w", line, timeNames[i], err)
			}
			r.Times[i] = t
		}
		out = append(out, r)
	}
}

// rfcTime reads an RFC 3339 time; empty is unknown.
func rfcTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// mustFormat is the format named name, which is one of the table's.
func mustFormat(name string) format {
	f, ok := formatNamed(name)
	if !ok {
		panic("oracle: no format " + name)
	}
	return f
}
