package oracle

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Categories, in the order they are reported.
const (
	catFiles   = "files"
	catDeleted = "deleted"
	catStreams = "streams"
	catTimes   = "times"
	catHashes  = "hashes"
	catLinks   = "links"
	// catFileNames are the times of each name's NTFS $FILE_NAME.
	catFileNames = "filenames"
)

// CategoryNames lists the categories in the order they are reported.
var CategoryNames = []string{catFiles, catDeleted, catStreams, catTimes, catHashes, catLinks, catFileNames}

// Category is how a tool did at one kind of finding. Expected counts what
// there was to find; Checked counts what the tool's output could be judged
// on (a time of an entry it did not list cannot be, nor a digest it did not
// compute). TP, FP and FN count the findings it got right, the ones it got
// wrong or made up, and the ones it missed or got wrong.
type Category struct {
	Name      string `json:"name"`
	Expected  int    `json:"expected"`
	Checked   int    `json:"checked"`
	TP        int    `json:"tp"`
	FP        int    `json:"fp"`
	FN        int    `json:"fn"`
	Precision Ratio  `json:"precision"`
	Recall    Ratio  `json:"recall"`
	F1        Ratio  `json:"f1"`
	// Missing are what the tool did not find; Extra the rows it reported
	// that are not in the run; Wrong the values it got wrong.
	Missing []string `json:"missing,omitempty"`
	Extra   []Extra  `json:"extra,omitempty"`
	Wrong   []Wrong  `json:"wrong,omitempty"`
}

// Extra is a row of the tool's output that names nothing the run made.
type Extra struct {
	Line   int    `json:"line"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Wrong is a value the tool reported for something it found, and the value
// it should have been. Found is empty when the tool reported none.
type Wrong struct {
	Line     int    `json:"line"`
	Path     string `json:"path"`
	Field    string `json:"field"`
	Expected string `json:"expected"`
	Found    string `json:"found"`
}

// Ratio is a score from 0 to 1, or null when there was nothing to score.
type Ratio struct{ num, den int }

// Value is the ratio, and whether it is defined.
func (r Ratio) Value() (float64, bool) {
	if r.den == 0 {
		return 0, false
	}
	return float64(r.num) / float64(r.den), true
}

// String is the ratio to four places, or "-".
func (r Ratio) String() string {
	v, ok := r.Value()
	if !ok {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', 4, 64)
}

func (r Ratio) MarshalJSON() ([]byte, error) {
	if r.den == 0 {
		return []byte("null"), nil
	}
	return []byte(r.String()), nil
}

// finish works out the ratios and puts the lists in a fixed order.
func (c *Category) finish() {
	c.Precision = Ratio{c.TP, c.TP + c.FP}
	c.Recall = Ratio{c.TP, c.TP + c.FN}
	c.F1 = Ratio{2 * c.TP, 2*c.TP + c.FP + c.FN}
	slices.Sort(c.Missing)
	sort.SliceStable(c.Extra, func(i, j int) bool { return c.Extra[i].Line < c.Extra[j].Line })
	sort.SliceStable(c.Wrong, func(i, j int) bool {
		a, b := c.Wrong[i], c.Wrong[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Field < b.Field
	})
}

func (c *Category) wrong(r *Row, path, field, expected, found string) {
	c.FP++
	c.FN++
	c.Wrong = append(c.Wrong, Wrong{Line: r.Line, Path: path, Field: field, Expected: expected, Found: found})
}

// Options steer how a tool's output is scored.
type Options struct {
	// Prefix is the path the tool gives the output root; when PrefixSet is
	// false it is detected.
	Prefix    string
	PrefixSet bool
	// Tolerance is how far a reported time may be from the expected one and
	// still count.
	Tolerance time.Duration
	// Fold compares names without regard to case.
	Fold bool
	// Commas says the format writes a comma in a name as a space, as
	// Plaso's CSVs do.
	Commas bool
}

// PathReport says how the tool's paths were read.
type PathReport struct {
	Prefix         string `json:"prefix"`
	PrefixDetected bool   `json:"prefix_detected"`
	// Rows are the entries the tool reported, once per-time events are
	// folded into one row per entry.
	Rows int `json:"rows"`
	// OutsidePrefix rows are not under the output root.
	OutsidePrefix int `json:"outside_prefix"`
	// VolumeFiles are entries the file system keeps for itself.
	VolumeFiles int `json:"volume_files"`
	// FilenameRecords are NTFS $FILE_NAME records that are not scored: a
	// deleted entry's, or one of a name the run did not leave.
	FilenameRecords int `json:"filename_records"`
	// OldNames are deleted entries under a name the run once used: real
	// traces, though not of a deletion.
	OldNames int `json:"old_names"`
	// Reused are deleted objects whose entries a later write to the image
	// reused, so that no tool could find them; they are not scored.
	Reused int `json:"reused_entries,omitempty"`
	// DeletedStreams are rows for a named stream of a deleted entry found
	// by its address; the entry is scored, and its streams are not.
	DeletedStreams int `json:"deleted_streams,omitempty"`
}

// scorer scores one tool's rows against one run.
type scorer struct {
	x    *Expected
	ix   *pathIndex
	tol  time.Duration
	cats map[string]*Category
	// files and streams record the row that found each name and stream.
	files   map[string]*Row
	streams map[streamKey]*Row
	// fileNames record the row that gave each name's $FILE_NAME.
	fileNames map[string]*Row
	// deletedRows are the rows reporting a deleted entry at each path the
	// run deleted something from, and gone the row that found each object
	// deleted.
	deletedRows map[string][]*Row
	gone        map[*object]*Row
}

type streamKey struct{ path, stream string }

// Score scores a tool's rows against the expected state.
func Score(x *Expected, rows []Row, opts Options) ([]*Category, PathReport, error) {
	backslashes := !x.hasBackslash()
	s := &scorer{
		x: x, ix: newPathIndex(x, opts.Fold, opts.Commas), tol: opts.Tolerance,
		cats:  map[string]*Category{},
		files: map[string]*Row{}, streams: map[streamKey]*Row{}, fileNames: map[string]*Row{},
		deletedRows: map[string][]*Row{}, gone: map[*object]*Row{},
	}
	for _, n := range CategoryNames {
		s.cats[n] = &Category{Name: n}
	}
	rep := PathReport{Rows: len(rows), Reused: x.reused}
	var pre prefix
	if opts.PrefixSet {
		pre = parsePrefix(opts.Prefix, backslashes)
	} else {
		var err error
		if pre, err = detectPrefix(rows, s.ix, backslashes); err != nil {
			return nil, rep, err
		}
	}
	rep.Prefix, rep.PrefixDetected = pre.String(), !opts.PrefixSet

	for i := range rows {
		r := &rows[i]
		rel, ok := pre.strip(s.ix, components(reportedPath(r.Path, backslashes)))
		switch {
		case !ok:
			rep.OutsidePrefix++
		case rel == "":
			// The output root itself, whose times are not the run's.
		case selfEntry(rel):
			// A directory's own "." or ".." entry, which The Sleuth Kit
			// lists with the directory's streams.
			rep.VolumeFiles++
		case r.FileName:
			s.placeFileName(r, rel, &rep)
		default:
			s.place(r, rel, &rep)
		}
	}
	s.assignDeleted(&rep)
	s.missing()
	s.scoreTimes()
	s.scoreHashes()
	s.scoreLinks()
	s.scoreFileNames()
	out := make([]*Category, len(CategoryNames))
	for i, n := range CategoryNames {
		s.cats[n].finish()
		out[i] = s.cats[n]
	}
	return out, rep, nil
}

// hasBackslash says whether any name in the run holds a backslash, when a
// reported backslash cannot be taken for a separator.
func (x *Expected) hasBackslash() bool {
	for p := range x.history {
		if strings.Contains(p, `\`) {
			return true
		}
	}
	return false
}

// place decides what one row in the output root found.
func (s *scorer) place(r *Row, rel string, rep *PathReport) {
	path, stream, known := s.resolve(r, rel)
	shown := rel
	if r.Stream != "" {
		shown += ":" + r.Stream
	}
	if r.Deleted {
		s.placeDeleted(r, path, stream, known, shown, rep)
		return
	}
	if stream != "" {
		s.placeStream(r, path, stream, known, shown, rep)
		return
	}
	files := s.cats[catFiles]
	switch {
	case known && s.x.present[path] != nil && s.files[path] == nil:
		s.files[path] = r
		files.TP++
	case known && s.x.present[path] != nil:
		files.FP++
		files.Extra = append(files.Extra, Extra{r.Line, shown, fmt.Sprintf("listed again (first on line %d)", s.files[path].Line)})
	case volumeFurniture(rel):
		rep.VolumeFiles++
	case known:
		files.FP++
		files.Extra = append(files.Extra, Extra{r.Line, shown, "the run left nothing there (the name was moved or deleted)"})
	default:
		files.FP++
		files.Extra = append(files.Extra, Extra{r.Line, shown, "the run made nothing there"})
	}
}

// resolve finds the path and stream a row names: its stream as the format
// gave it, or, for a format that appends streams to paths, what follows
// the last element's colon when the whole is not a name of the run and the
// volume keeps streams (elsewhere a colon is just part of a name).
func (s *scorer) resolve(r *Row, rel string) (path, stream string, known bool) {
	if r.Stream != "" {
		path, known = s.ix.lookup(rel)
		return path, r.Stream, known
	}
	if path, known = s.ix.lookup(rel); known || !r.Whole || !s.x.namedStreams {
		return path, "", known
	}
	base, stream := splitStream(rel)
	if stream == "" {
		return "", "", false
	}
	path, known = s.ix.lookup(base)
	return path, stream, known
}

// placeFileName takes a row giving a $FILE_NAME of a name the run left as
// that name's, and sets the others aside.
func (s *scorer) placeFileName(r *Row, rel string, rep *PathReport) {
	path, stream, known := s.resolve(r, rel)
	switch {
	case r.Deleted || !known || stream != "" || s.x.present[path] == nil:
		rep.FilenameRecords++
	case s.fileNames[path] == nil:
		s.fileNames[path] = r
	default:
		c := s.cats[catFileNames]
		c.FP++
		c.Extra = append(c.Extra, Extra{r.Line, rel + " ($FILE_NAME)", fmt.Sprintf("listed again (first on line %d)", s.fileNames[path].Line)})
	}
}

func (s *scorer) placeDeleted(r *Row, path, stream string, known bool, shown string, rep *PathReport) {
	deleted := s.cats[catDeleted]
	if _, ok := s.x.entries[inodeKey(r.Inode)]; ok && r.Inode != "" && stream != "" {
		rep.DeletedStreams++
		return
	}
	if s.byEntry(r, shown, rep) {
		return
	}
	switch {
	case known && stream == "" && s.x.deleted[path] != nil:
		s.deletedRows[path] = append(s.deletedRows[path], r)
	case known:
		rep.OldNames++
	case volumeFurniture(shown) || streamFurniture(stream):
		rep.VolumeFiles++
	default:
		deleted.FP++
		deleted.Extra = append(deleted.Extra, Extra{r.Line, shown, "the run deleted nothing there"})
	}
}

func (s *scorer) placeStream(r *Row, path, stream string, known bool, shown string, rep *PathReport) {
	streams := s.cats[catStreams]
	key, ok := s.expectedStream(path, stream)
	switch {
	case known && ok && s.streams[key] == nil:
		s.streams[key] = r
		streams.TP++
	case known && ok:
		streams.FP++
		streams.Extra = append(streams.Extra, Extra{r.Line, shown, fmt.Sprintf("listed again (first on line %d)", s.streams[key].Line)})
	case streamFurniture(stream) || volumeFurniture(shown):
		rep.VolumeFiles++
	default:
		streams.FP++
		streams.Extra = append(streams.Extra, Extra{r.Line, shown, "the run wrote no such stream"})
	}
}

// expectedStream is the key of the stream of the object at path that stream
// names, if the run left one.
func (s *scorer) expectedStream(path, stream string) (streamKey, bool) {
	o := s.x.present[path]
	if o == nil {
		return streamKey{}, false
	}
	for _, st := range o.streams {
		if s.ix.sameName(st.Name, stream) {
			return streamKey{path, st.Name}, true
		}
	}
	return streamKey{}, false
}

// byEntry places a deleted entry by the address the tool gives it, where
// the run was written into an image and the answer key says what entry is
// there. A tool reading a deleted entry often shows its name damaged, as
// FAT's 0xE5 over the first character leaves it, but the address is exact.
func (s *scorer) byEntry(r *Row, shown string, rep *PathReport) bool {
	ref, ok := s.x.entries[inodeKey(r.Inode)]
	if !ok || r.Inode == "" {
		return false
	}
	g := s.x.deletedBy(ref.path, ref.op)
	switch {
	case ref.cause != "delete" || g == nil:
		rep.OldNames++
	case s.gone[g] == nil:
		s.gone[g] = r
		s.cats[catDeleted].TP++
	default:
		deleted := s.cats[catDeleted]
		deleted.FP++
		deleted.Extra = append(deleted.Extra, Extra{r.Line, shown, fmt.Sprintf("listed again (first on line %d)", s.gone[g].Line)})
	}
	return true
}

// assignDeleted pairs the deleted entries the tool found with the objects
// the run deleted. Several objects can have been deleted from one path, and
// a tool can find any of them: each row goes to the one, not yet found,
// whose times it matches best (the earliest on a tie). A row left over has
// found an old name, not a deletion.
func (s *scorer) assignDeleted(rep *PathReport) {
	for _, p := range slices.Sorted(maps.Keys(s.deletedRows)) {
		gens := s.x.deleted[p]
		for _, r := range s.deletedRows[p] {
			best, bestScore := -1, -1
			for i, g := range gens {
				if s.gone[g] != nil {
					continue
				}
				if n := s.agreeing(r, g); n > bestScore {
					best, bestScore = i, n
				}
			}
			if best < 0 {
				rep.OldNames++
				continue
			}
			s.gone[gens[best]] = r
			s.cats[catDeleted].TP++
		}
	}
}

// agreeing counts the times of o the row reports within the tolerance.
func (s *scorer) agreeing(r *Row, o *object) int {
	n := 0
	for i, want := range o.times {
		if !want.IsZero() && !r.Times[i].IsZero() && abs(r.Times[i].Sub(want)) <= s.tolerance(i) {
			n++
		}
	}
	return n
}

// tolerance is how far time i may be off: the tolerance asked for, or the
// volume's resolution for that time if it is coarser, as FAT keeps only
// the date of the last access.
func (s *scorer) tolerance(i int) time.Duration {
	return max(s.tol, s.x.resolution[i])
}

// deletedLabel names one object deleted from p in the report.
func deletedLabel(p string, o *object) string {
	return fmt.Sprintf("%s (deleted by operation %d)", p, o.op)
}

// missing counts what there was to find, and lists what was not found.
func (s *scorer) missing() {
	files, deleted, streams := s.cats[catFiles], s.cats[catDeleted], s.cats[catStreams]
	for p, o := range s.x.present {
		files.Expected++
		if s.files[p] == nil {
			files.FN++
			files.Missing = append(files.Missing, p)
		}
		for _, st := range o.streams {
			streams.Expected++
			if s.streams[streamKey{p, st.Name}] == nil {
				streams.FN++
				streams.Missing = append(streams.Missing, p+":"+st.Name)
			}
		}
	}
	for p, gens := range s.x.deleted {
		for _, g := range gens {
			if g.reused {
				continue
			}
			deleted.Expected++
			if s.gone[g] == nil {
				deleted.FN++
				deleted.Missing = append(deleted.Missing, deletedLabel(p, g))
			}
		}
	}
	files.Checked, deleted.Checked, streams.Checked = files.Expected, deleted.Expected, streams.Expected
}

// scoreTimes scores the times of every entry the tool found, present or
// deleted. A time the tool left unknown is missed; one further than the
// tolerance from the expected time is wrong.
func (s *scorer) scoreTimes() {
	for p, o := range s.x.present {
		s.scoreTimesOf(catTimes, s.files[p], o.times, p)
	}
	for p, gens := range s.x.deleted {
		for _, g := range gens {
			if g.reused {
				continue
			}
			s.scoreTimesOf(catTimes, s.gone[g], g.times, deletedLabel(p, g))
		}
	}
}

// scoreFileNames scores the times of the $FILE_NAME of every name the run
// left whose times are known. A hard-linked file's record holds one
// $FILE_NAME for each of its names, and a tool may give any of them for
// any name, as The Sleuth Kit gives one for all: a row is scored against
// the name whose times it agrees with best, its own on a tie.
func (s *scorer) scoreFileNames() {
	for p, t := range s.x.fileNames {
		o := s.x.present[p]
		if o == nil {
			continue
		}
		r := s.fileNames[p]
		if r != nil {
			best := s.agreeingTimes(r, t)
			for _, n := range slices.Sorted(slices.Values(o.names)) {
				if other, ok := s.x.fileNames[n]; ok && n != p && s.agreeingTimes(r, other) > best {
					t, best = other, s.agreeingTimes(r, other)
				}
			}
		}
		s.scoreTimesOf(catFileNames, r, t, p+" ($FILE_NAME)")
	}
}

// agreeingTimes counts the times of want the row reports within the
// tolerance.
func (s *scorer) agreeingTimes(r *Row, want times) int {
	return s.agreeing(r, &object{times: want})
}

// scoreTimesOf scores one entry's times in category cat; r is nil when the
// tool did not find it, and then they count only as expected.
func (s *scorer) scoreTimesOf(cat string, r *Row, ts times, label string) {
	c := s.cats[cat]
	for i, want := range ts {
		if want.IsZero() {
			continue
		}
		c.Expected++
		if r == nil {
			continue
		}
		c.Checked++
		got := r.Times[i]
		switch {
		case got.IsZero():
			c.FN++
			c.Wrong = append(c.Wrong, Wrong{Line: r.Line, Path: label, Field: timeNames[i], Expected: stamp(want)})
		case abs(got.Sub(want)) <= s.tolerance(i):
			c.TP++
		default:
			c.wrong(r, label, timeNames[i], stamp(want), stamp(got))
		}
	}
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// scoreHashes scores the digests the tool computed for the files and
// streams it found: its MD5 where it gives one, else its SHA-256. One it
// did not compute is not held against it.
func (s *scorer) scoreHashes() {
	c := s.cats[catHashes]
	check := func(r *Row, path, md5, sha256 string) {
		if md5 == "" && sha256 == "" {
			return
		}
		c.Expected++
		if r == nil {
			return
		}
		switch {
		case r.MD5 != "" && md5 != "":
			c.Checked++
			if r.MD5 == md5 {
				c.TP++
			} else {
				c.wrong(r, path, "md5", md5, r.MD5)
			}
		case r.SHA256 != "" && sha256 != "":
			c.Checked++
			if r.SHA256 == sha256 {
				c.TP++
			} else {
				c.wrong(r, path, "sha256", sha256, r.SHA256)
			}
		}
	}
	for p, o := range s.x.present {
		if o.kind == kindFile {
			check(s.files[p], p, o.md5, o.sha256)
		}
		for _, st := range o.streams {
			check(s.streams[streamKey{p, st.Name}], p+":"+st.Name, st.MD5, st.SHA256)
		}
	}
}

// scoreLinks scores what the tool says about links: that the names of a
// hard-linked file are one object (the same inode, and as many links as it
// has names, where the tool counts them), and where a symlink or junction
// points. A file with one name the tool says has more is wrong too.
func (s *scorer) scoreLinks() {
	c := s.cats[catLinks]
	seen := map[*object]bool{}
	names := make([]string, 0, len(s.x.present))
	for p := range s.x.present {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, p := range names {
		o := s.x.present[p]
		r := s.files[p]
		switch {
		case o.kind == kindSymlink || o.kind == kindJunction:
			c.Expected++
			if r == nil || r.Target == "" {
				continue
			}
			c.Checked++
			if s.ix.sameName(cleanTarget(r.Target), cleanTarget(o.target)) {
				c.TP++
			} else {
				c.wrong(r, p, "target", o.target, r.Target)
			}
		case len(o.names) > 1 && !seen[o]:
			seen[o] = true
			s.hardLinks(o)
		case len(o.names) == 1 && o.kind == kindFile && r != nil && r.Links > 1:
			c.FP++
			c.Extra = append(c.Extra, Extra{r.Line, p, fmt.Sprintf("reported with %d links, but the file has one name", r.Links)})
		}
	}
}

// hardLinks scores the names of one hard-linked file: each must have the
// inode of the first the tool gave one for, and as many links as the file
// has names. A tool that gives neither for a name is not judged on it; one
// that gives only the count is judged on that.
func (s *scorer) hardLinks(o *object) {
	c := s.cats[catLinks]
	names := slices.Sorted(slices.Values(o.names))
	ref, refName := "", ""
	for _, n := range names {
		if r := s.files[n]; r != nil && r.Inode != "" {
			ref, refName = inodeKey(r.Inode), n
			break
		}
	}
	for _, n := range names {
		c.Expected++
		r := s.files[n]
		if r == nil || (r.Inode == "" && r.Links == 0) {
			continue
		}
		c.Checked++
		switch {
		case r.Inode != "" && inodeKey(r.Inode) != ref:
			c.wrong(r, n, "inode", ref+" (as "+refName+")", r.Inode)
		case r.Links != 0 && r.Links != len(o.names):
			c.wrong(r, n, "links", strconv.Itoa(len(o.names)), strconv.Itoa(r.Links))
		default:
			c.TP++
		}
	}
}

// inodeKey is the part of an inode that names the object: TSK writes an
// NTFS one as entry-type-id, and only the MFT entry is the file's.
func inodeKey(s string) string {
	k, _, _ := strings.Cut(s, "-")
	return k
}

// cleanTarget puts a link target in one form for comparing.
func cleanTarget(t string) string {
	t = strings.ReplaceAll(t, `\`, "/")
	if len(t) > 1 {
		t = strings.TrimSuffix(t, "/")
	}
	return t
}
