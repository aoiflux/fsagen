package timeline

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/sandbox"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to record it)", err)
	}
	if w := strings.ReplaceAll(string(want), "\r", ""); w != got {
		t.Errorf("output differs from %s:\n--- want\n%s\n--- got\n%s", p, w, got)
	}
}

func out(t *testing.T, tl *Timeline, format string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tl.Write(&buf, format); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func generate(t *testing.T, root string) *Timeline {
	t.Helper()
	tl, err := Generate(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

func openRoot(t *testing.T) (string, *sandbox.FS) {
	t.Helper()
	root := t.TempDir()
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })
	return root, fsys
}

// TestTimelineZoneIndependent: the machine's time zone does not reach the
// timeline; every time is written in UTC.
func TestTimelineZoneIndependent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2021, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone("UTC+5", 5*3600)
	east := out(t, generate(t, root), "csv")
	time.Local = time.FixedZone("UTC-7", -7*3600)
	west := out(t, generate(t, root), "csv")

	// Reading a file for its digest does not move its access time, so the
	// two timelines are identical, and in UTC.
	if east != west {
		t.Errorf("the time zone changed the timeline:\n%s\n%s", east, west)
	}
	if strings.Contains(east, "+05:00") || strings.Contains(east, "-07:00") {
		t.Errorf("local time in the timeline:\n%s", east)
	}
	if !strings.Contains(east, "\na.txt,,file,1,") || !strings.Contains(east, ",2021-06-01T12:00:00Z,2021-06-01T12:00:00Z,") {
		t.Errorf("access and modification times not written in UTC:\n%s", east)
	}
}

// TestTimelineTieOrder: entries with the same time are ordered by path.
func TestTimelineTieOrder(t *testing.T) {
	when := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	var entries []Entry
	for i := 99; i >= 0; i-- {
		entries = append(entries, Entry{Path: fmt.Sprintf("f%02d", i), Mtime: when})
	}
	entries = append(entries, Entry{Path: "zz-earlier", Mtime: when.Add(-time.Second)})
	sortEntries(entries)
	if entries[0].Path != "zz-earlier" {
		t.Fatalf("first entry %s, want the earliest", entries[0].Path)
	}
	for i := 1; i < len(entries); i++ {
		if want := fmt.Sprintf("f%02d", i-1); entries[i].Path != want {
			t.Fatalf("entry %d is %s, want %s", i, entries[i].Path, want)
		}
	}
}

// TestNoWallClockInTimeline: the text formats carry no generation time.
func TestNoWallClockInTimeline(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tl := generate(t, root)
	for _, f := range []string{"txt", "macb"} {
		if s := out(t, tl, f); strings.Contains(s, "Generated:") {
			t.Errorf("wall-clock header in:\n%s", s)
		}
	}
}

// TestTimelinePassKeepsAtime: building a timeline reads every file and
// stream (for its digest) and lists every directory, and none of that moves
// an access time. The test first shows that an ordinary read does move one
// on this volume, and skips where it does not (last-access updates off,
// noatime mounts).
func TestTimelinePassKeepsAtime(t *testing.T) {
	root, fsys := openRoot(t)
	names := []string{"d/sub/a.txt", "d/b.txt"}
	for _, n := range names {
		if err := fsys.WriteFile(n, []byte("content of "+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if fsys.SupportsStreams() {
		if err := fsys.WriteStream("d/b.txt", "quill", []byte("payload")); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Date(2019, 5, 6, 7, 8, 9, 0, time.UTC)
	all := append(names, "d/sub", "d")
	stamp := func() {
		for _, n := range all {
			if err := fsys.SetTimes(n, sandbox.Times{Atime: old, Mtime: old}); err != nil {
				t.Fatal(err)
			}
		}
	}
	stamp()
	if _, err := os.ReadFile(filepath.Join(root, "d", "b.txt")); err != nil {
		t.Fatal(err)
	}
	if got, _ := fsys.Times("d/b.txt"); got.Atime.Equal(old) {
		t.Skip("this volume does not update access times on read")
	}
	stamp()
	generate(t, root)
	for _, n := range all {
		if got, _ := fsys.Times(n); !got.Atime.Equal(old) {
			t.Errorf("%s: the timeline pass moved the access time to %v", n, got.Atime)
		}
	}
}

// F-TL-4: every named stream is its own record, with its size and digest,
// whatever its name (here one with a space in it), as The Sleuth Kit lists
// them.
func TestStreamsQuillAndSpaceNameWithSizes(t *testing.T) {
	root, fsys := openRoot(t)
	if !fsys.SupportsStreams() {
		t.Skip("no named streams on this volume")
	}
	if err := fsys.WriteFile("a.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	streams := map[string]string{"quill": "payload", "my notes": "twelve bytes", "Zone.Identifier": "[ZoneTransfer]\r\nZoneId=3\r\n"}
	for name, data := range streams {
		if err := fsys.WriteStream("a.txt", name, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	body := out(t, generate(t, root), "bodyfile")
	for name, data := range streams {
		md5 := map[string]string{"quill": "321c3cf486ed509164edec1e1981fec8", "my notes": "c91fa94e14cf2fa5474beceff788c0dc", "Zone.Identifier": "fbccf14d504b7b2dbcb5a5bda75bd93b"}[name]
		re := regexp.MustCompile(`(?m)^([0-9a-f]{32})\|/a\.txt:` + regexp.QuoteMeta(name) + `\|[^|]+\|r/r[-rwx]{9}\|0\|0\|` + strconv.Itoa(len(data)) + `\|`)
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("no record for stream %q of %d bytes in:\n%s", name, len(data), body)
			continue
		}
		if m[1] != md5 {
			t.Errorf("stream %q: md5 %s, want %s", name, m[1], md5)
		}
	}
	if n := strings.Count(body, "/a.txt"); n != 4 {
		t.Errorf("%d records for a.txt, want the file and its three streams:\n%s", n, body)
	}
}

// F-TL-2: the change time and the creation time are two columns, each from
// its own source; neither is copied into the other.
func TestBodyfileCrtimeNotCtime(t *testing.T) {
	root, fsys := openRoot(t)
	if c := fsys.TimeCaps(); !c.Birth || !c.Change {
		t.Skip("creation and change times can only be set on Windows NTFS/ReFS")
	}
	if err := fsys.WriteFile("a.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := func(h int) time.Time { return time.Date(2019, 1, 1, h, 0, 0, 0, time.UTC) }
	if err := fsys.SetTimes("a.txt", sandbox.Times{Atime: ts(1), Mtime: ts(2), Ctime: ts(3), Btime: ts(4)}); err != nil {
		t.Fatal(err)
	}
	body := out(t, generate(t, root), "bodyfile")
	want := fmt.Sprintf("|%d|%d|%d|%d\n", ts(1).Unix(), ts(2).Unix(), ts(3).Unix(), ts(4).Unix())
	if !strings.Contains(body, "|/a.txt|") || !strings.HasSuffix(strings.SplitAfter(body, "\n")[0], want) {
		t.Errorf("want atime|mtime|ctime|crtime = %q in:\n%s", want, body)
	}
}

// sample is a timeline with one of everything a bodyfile has to express.
func sample() *Timeline {
	at := func(s int) time.Time { return time.Date(2021, 3, 1, 9, 0, s, 0, time.UTC) }
	return &Timeline{Source: SourceModelled, Entries: []Entry{
		{Path: "docs", Type: TypeDir, Mode: fs.ModeDir | 0o755, Inode: "2", Atime: at(1), Mtime: at(4), Ctime: at(4), Btime: at(1)},
		{Path: "docs/a.txt", Type: TypeFile, Mode: 0o644, Size: 5, Inode: "3", MD5: "5d41402abc4b2a76b9719d911017c592", Atime: at(1), Mtime: at(2), Ctime: at(3), Btime: at(1)},
		{Path: "docs/a.txt", Stream: "quill", Type: TypeStream, Mode: 0o644, Size: 7, Inode: "3", MD5: "321c3cf486ed509164edec1e1981fec8", Atime: at(1), Mtime: at(2), Ctime: at(3), Btime: at(1)},
		{Path: "docs/gone.txt", Type: TypeFile, Mode: 0o600, Size: 0, Inode: "4", MD5: "d41d8cd98f00b204e9800998ecf8427e", Mtime: at(3), Deleted: true},
		{Path: "docs/big.bin", Type: TypeFile, Mode: 0o444, Size: 1 << 40, Inode: "5", UID: 1000, GID: 100, Mtime: at(5), Atime: at(5)},
		{Path: "link", Type: TypeLink, Mode: 0o777, Inode: "6"},
	}}
}

// F-TL-6: the bodyfile is The Sleuth Kit's: slash paths with a leading
// slash and no root entry, TSK mode strings, 0 for a digest that was not
// computed and for an unknown time, streams as name:stream and deleted
// objects marked.
func TestBodyfileGolden(t *testing.T) {
	golden(t, "sample.bodyfile", out(t, sample(), "bodyfile"))
}

// bodyLine is one bodyfile record, parsed strictly.
type bodyLine struct {
	md5, name, inode, mode string
	uid, gid, size         int64
	times                  [4]int64
}

var (
	md5Field  = regexp.MustCompile(`^(0|[0-9a-f]{32})$`)
	modeField = regexp.MustCompile(`^[-rdlcbps]/[-rdlcbps][-r][-w][-xsS][-r][-w][-xsS][-r][-w][-xtT]$`)
	inoField  = regexp.MustCompile(`^[0-9]+(-[0-9]+-[0-9]+)?$|^0x[0-9a-f]+$`)
)

func parseBody(line string) (bodyLine, error) {
	f := strings.Split(line, "|")
	if len(f) != 11 {
		return bodyLine{}, fmt.Errorf("%d fields, want 11", len(f))
	}
	var b bodyLine
	b.md5, b.name, b.inode, b.mode = f[0], f[1], f[2], f[3]
	switch {
	case !md5Field.MatchString(b.md5):
		return b, fmt.Errorf("md5 %q", b.md5)
	case !strings.HasPrefix(b.name, "/") || b.name == "/":
		return b, fmt.Errorf("name %q", b.name)
	case !inoField.MatchString(b.inode):
		return b, fmt.Errorf("inode %q", b.inode)
	case !modeField.MatchString(b.mode):
		return b, fmt.Errorf("mode %q", b.mode)
	}
	nums := []*int64{&b.uid, &b.gid, &b.size, &b.times[0], &b.times[1], &b.times[2], &b.times[3]}
	for i, p := range nums {
		v, err := strconv.ParseInt(f[4+i], 10, 64)
		if err != nil || v < 0 {
			return b, fmt.Errorf("field %d %q", 5+i, f[4+i])
		}
		*p = v
	}
	return b, nil
}

func (b bodyLine) String() string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d", b.md5, b.name, b.inode, b.mode, b.uid, b.gid, b.size, b.times[0], b.times[1], b.times[2], b.times[3])
}

// F-TL-6: every line of a bodyfile, observed or modelled, parses strictly
// and writes back identically.
func TestBodyfileStrictParserRoundTrip(t *testing.T) {
	root, fsys := openRoot(t)
	for _, n := range []string{"a.txt", "d/b.txt", "d/e/c.log"} {
		if err := fsys.WriteFile(n, []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if fsys.SupportsStreams() {
		if err := fsys.WriteStream("a.txt", "Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"observed": out(t, generate(t, root), "bodyfile"), "sample": out(t, sample(), "bodyfile")} {
		lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
		if len(lines) < 5 {
			t.Errorf("%s: only %d lines", name, len(lines))
		}
		for _, l := range lines {
			b, err := parseBody(l)
			if err != nil {
				t.Errorf("%s: %v in %q", name, err, l)
				continue
			}
			if b.String() != l {
				t.Errorf("%s: %q wrote back as %q", name, l, b.String())
			}
		}
		if strings.Contains(body, "|/|") || strings.Contains(body, `\`) {
			t.Errorf("%s: a root entry or a backslash:\n%s", name, body)
		}
	}
}

// The Sleuth Kit's mactime reads the bodyfile, where it is installed.
func TestMactimeAccepts(t *testing.T) {
	mactime, err := exec.LookPath("mactime")
	if err != nil {
		t.Skip("mactime (The Sleuth Kit) is not installed")
	}
	p := filepath.Join(t.TempDir(), "sample.body")
	if err := os.WriteFile(p, []byte(out(t, sample(), "bodyfile")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(mactime, "-b", p, "-d", "-y", "-z", "UTC")
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mactime: %v\n%s", err, got)
	}
	// mactime groups each entry's times by instant, as WriteMACB does, and
	// shows an unknown (0) time as 0000-00-00.
	for _, want := range []string{
		`2021-03-01T09:00:01Z,0,.a.b,d/drwxr-xr-x,0,0,2,"/docs"`,
		`2021-03-01T09:00:02Z,5,m...,r/rrw-r--r--,0,0,3,"/docs/a.txt"`,
		`2021-03-01T09:00:02Z,7,m...,r/rrw-r--r--,0,0,3,"/docs/a.txt:quill"`,
		`2021-03-01T09:00:03Z,0,m...,r/rrw-------,0,0,4,"/docs/gone.txt (deleted)"`,
		`2021-03-01T09:00:04Z,0,m.c.,d/drwxr-xr-x,0,0,2,"/docs"`,
		`2021-03-01T09:00:05Z,1099511627776,ma..,r/rr--r--r--,1000,100,5,"/docs/big.bin"`,
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("mactime output lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(strings.ToLower(string(got)), "invalid") {
		t.Errorf("mactime rejected lines:\n%s", got)
	}
}

// F-TL-7: an entry's times that fall at the same instant share one line
// whose flags name them; each of the sixteen combinations of equal times
// gives the lines it should, and unknown times give none.
func TestMACBSixteenCombinations(t *testing.T) {
	t0 := time.Date(2021, 3, 1, 9, 0, 0, 0, time.UTC)
	tl := &Timeline{Source: SourceModelled}
	for i := 0; i < 16; i++ {
		e := Entry{Path: fmt.Sprintf("c%02d", i), Type: TypeFile, Mode: 0o644, Size: int64(i), Inode: strconv.Itoa(i + 1)}
		times := []*time.Time{&e.Mtime, &e.Atime, &e.Ctime, &e.Btime}
		for bit, p := range times {
			if i&(1<<bit) != 0 {
				*p = t0
			} else {
				*p = t0.Add(time.Duration(bit+1) * time.Hour)
			}
		}
		tl.Entries = append(tl.Entries, e)
	}
	tl.Entries = append(tl.Entries, Entry{Path: "unknown", Type: TypeFile, Mode: 0o644, Inode: "99"})
	got := out(t, tl, "macb")
	if strings.Contains(got, "/unknown") {
		t.Error("an entry with no known time has a line")
	}
	golden(t, "macb16.txt", got)
}

// F-TL-8: anything the walk cannot read is an error naming it, never a
// silently shorter timeline.
func TestWalkErrorReported(t *testing.T) {
	root, fsys := openRoot(t)
	if err := fsys.WriteFile("d/locked.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	unlock := lock(t, filepath.Join(root, "d", "locked.txt"))
	defer unlock()
	_, err := Generate(root, Options{})
	if err == nil || !strings.Contains(err.Error(), "d/locked.txt") {
		t.Fatalf("Generate = %v, want an error naming d/locked.txt", err)
	}
}

// The hash limit leaves the digest of what is larger out, and says so with
// 0 in the bodyfile rather than a wrong digest.
func TestHashLimit(t *testing.T) {
	root, fsys := openRoot(t)
	if err := fsys.WriteFile("small", []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("large", bytes.Repeat([]byte("x"), 100), 0o644); err != nil {
		t.Fatal(err)
	}
	tl, err := Generate(root, Options{HashLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	body := out(t, tl, "bodyfile")
	if !strings.Contains(body, "900150983cd24fb0d6963f7d28e17f72|/small|") || !strings.Contains(body, "\n0|/large|") && !strings.HasPrefix(body, "0|/large|") {
		t.Errorf("hash limit not applied:\n%s", body)
	}
}

// A name that would break a line-based format is refused there; CSV and
// JSON lines carry it.
func TestUnsafeNameRefused(t *testing.T) {
	tl := &Timeline{Entries: []Entry{{Path: "a|b", Type: TypeFile}}}
	var buf bytes.Buffer
	if err := tl.Write(&buf, "bodyfile"); err == nil {
		t.Error("a | in a name was written into a bodyfile")
	}
	for _, f := range []string{"csv", "jsonl", "macb", "txt"} {
		if err := tl.Write(&buf, f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	tl.Entries[0].Path = "a\nb"
	for _, f := range []string{"bodyfile", "macb", "txt"} {
		if err := tl.Write(&buf, f); err == nil {
			t.Errorf("%s: a newline in a name was written", f)
		}
	}
}

// Every format of the sample, pinned: the text formats label the source.
func TestFormatsGolden(t *testing.T) {
	for _, f := range Formats {
		golden(t, "sample."+f, out(t, sample(), f))
	}
	if s := out(t, sample(), "txt"); !strings.HasPrefix(s, "Modelled timeline") {
		t.Errorf("modelled txt not labelled:\n%s", s)
	}
	if s := out(t, &Timeline{Source: SourceObserved, Root: "/r"}, "macb"); !strings.HasPrefix(s, "Observed timeline of /r") {
		t.Errorf("observed macb not labelled:\n%s", s)
	}
}

// On Windows the mode is written as The Sleuth Kit writes it for NTFS:
// everything, less the write bits of a read-only file. A directory's size is
// whatever the file system reports.
func TestObservedModeAndDirSize(t *testing.T) {
	root, fsys := openRoot(t)
	if err := fsys.WriteFile("d/rw.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("d/ro.txt", []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(root, "d", "ro.txt"), 0o644)
	modes := map[string]string{}
	for _, e := range generate(t, root).Entries {
		modes[e.Path] = e.TSKMode()
		if e.Path == "d" {
			info, err := os.Lstat(filepath.Join(root, "d"))
			if err != nil {
				t.Fatal(err)
			}
			if e.Size != info.Size() {
				t.Errorf("directory size %d, the file system says %d", e.Size, info.Size())
			}
		}
	}
	want := map[string]string{"d/rw.txt": "r/rrw-r--r--", "d/ro.txt": "r/rr--r--r--", "d": "d/drwxr-xr-x"}
	if runtime.GOOS == "windows" {
		want = map[string]string{"d/rw.txt": "r/rrwxrwxrwx", "d/ro.txt": "r/rr-xr-xr-x", "d": "d/drwxrwxrwx"}
	}
	for p, w := range want {
		if modes[p] != w {
			t.Errorf("%s: mode %s, want %s", p, modes[p], w)
		}
	}
}

// TestEveryFormatHasAWriter: Write dispatches on the format name, and Formats
// is what a caller is told it may ask for. A name in one and not the other
// would either be unreachable or fail at the last moment.
func TestEveryFormatHasAWriter(t *testing.T) {
	for _, name := range Formats {
		if _, ok := writers[name]; !ok {
			t.Errorf("format %q is in Formats but has no writer", name)
		}
	}
	for name := range writers {
		if !slices.Contains(Formats, name) {
			t.Errorf("writers has %q, which is not in Formats", name)
		}
	}
}
