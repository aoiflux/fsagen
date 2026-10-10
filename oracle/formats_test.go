package oracle

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/timeline"
)

func TestDetect(t *testing.T) {
	cases := []struct{ first, want string }{
		{"# input-sha256 abc\n0|/a|1|r/rrw-r--r--|0|0|1|0|0|0|0\n", "bodyfile"},
		{"0|C:/a|64-128-1|r/rrwxrwxrwx|0|0|1|1|2|3|4\n", "bodyfile"},
		{strings.Join(l2tFields, ",") + "\n", "l2tcsv"},
		{"datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n", "dynamic"},
		{"\ufeffdatetime,timestamp_desc,display_name\n", "dynamic"},
		{`{"message":"m","datetime":"2026-01-01T00:00:00.000000+00:00","timestamp_desc":"Creation Time"}` + "\n", "timesketch"},
		{`{"path":"a","type":"file","size":1,"mode":"0644","uid":0,"gid":0}` + "\n", "jsonl"},
		{strings.Join(fsagenCSVFields, ",") + "\n", "csv"},
	}
	for _, c := range cases {
		f, err := detect([]byte(c.first))
		if err != nil || f.name != c.want {
			t.Errorf("detect(%q) = %s, %v; want %s", c.first, f.name, err, c.want)
		}
	}
	for _, bad := range []string{"", "\n\n", "hello world\n", `{"x":1}` + "\n", "{not json\n"} {
		if f, err := detect([]byte(bad)); err == nil {
			t.Errorf("detect(%q) = %s; want an error", bad, f.name)
		}
	}
}

// What The Sleuth Kit appends to a name is taken off and recorded, in the
// order fls writes it, and a name holding "|" survives.
func TestReadBodyfileTSK(t *testing.T) {
	in := strings.Join([]string{
		"0|C:/a.txt (deleted)|70-128-1|r/rrwxrwxrwx|0|0|5|1|2|3|4",
		"0|C:/b.txt ($FILE_NAME) (deleted-realloc)|71-48-2|r/rrwxrwxrwx|0|0|5|1|2|3|4",
		"0|/etc/link -> ../target (deleted)|12|l/lrwxrwxrwx|0|0|9|1|2|3|4",
		"0|/odd|name.txt|13|r/rrw-r--r--|0|0|9|1700000000.5|1700000000.000000001|0|0",
		strings.Repeat("ab", 32) + "|/s.txt:Zone.Identifier|14-128-4|-/rrw-r--r--|0|0|9|1|2|3|4",
	}, "\n")
	rows, err := readBodyfile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Line: 1, Path: "C:/a.txt", Whole: true, Kind: "file", Deleted: true, Inode: "70-128-1"},
		{Line: 2, Path: "C:/b.txt", Whole: true, Kind: "file", Deleted: true, FileName: true, Inode: "71-48-2"},
		{Line: 3, Path: "/etc/link", Whole: true, Kind: "link", Deleted: true, Target: "../target", Inode: "12"},
		{Line: 4, Path: "/odd|name.txt", Whole: true, Kind: "file", Inode: "13"},
		{Line: 5, Path: "/s.txt:Zone.Identifier", Whole: true, Kind: "file", Inode: "14-128-4", SHA256: strings.Repeat("ab", 32)},
	}
	for i, w := range want {
		r := rows[i]
		r.Times = times{}
		if r != w {
			t.Errorf("row %d = %+v\nwant %+v", i, r, w)
		}
	}
	if got := rows[3].Times; !got[atime].Equal(time.Unix(1700000000, 5e8)) || !got[mtime].Equal(time.Unix(1700000000, 1)) || !got[ctime].IsZero() {
		t.Errorf("fractional times = %v", got)
	}
	if _, err := readBodyfile([]byte("0|/a|1|r/r|0|0|1|x|0|0|0")); err == nil {
		t.Error("a time that is not a number was accepted")
	}
	if _, err := readBodyfile([]byte("0|/a|1|0|0|0")); err == nil {
		t.Error("a short line was accepted")
	}
}

// Plaso's l2tcsv groups an entry's times that share an instant into one
// line; they fold back into one row per entry, and lines that are not
// about the file system are left out.
func TestReadL2TCSV(t *testing.T) {
	rows := readRows(t, readL2TCSV, "testdata/plaso.l2tcsv")
	byPath := map[string]Row{}
	for _, r := range rows {
		byPath[r.Path] = r
	}
	if len(byPath) != len(rows) || len(rows) != 13 {
		t.Fatalf("%d rows for %d paths, want 13 of each", len(rows), len(byPath))
	}
	exe := byPath["/Users/victim/AppData/Local/Temp/wupdmgr32.exe"]
	stomped := time.Date(2019, 3, 7, 10, 12, 44, 0, time.UTC)
	if !exe.Times[atime].Equal(stomped) || !exe.Times[mtime].Equal(stomped) ||
		!exe.Times[ctime].Equal(time.Date(2026, 2, 3, 10, 20, 0, 0, time.UTC)) ||
		!exe.Times[crtime].Equal(time.Date(2026, 2, 3, 10, 18, 0, 0, time.UTC)) {
		t.Errorf("times %v", exe.Times)
	}
	if exe.Links != 2 || exe.Kind != "file" || exe.Inode == "" || !exe.Whole {
		t.Errorf("exe %+v", exe)
	}
	if doc := byPath["/Users/victim/Downloads/Invoice_4471.docm"]; doc.MD5 != "4bb031e47da512f764032ab96209a712" {
		t.Errorf("docm md5 %q", doc.MD5)
	}
	if byPath["/Users"].Kind != "dir" {
		t.Errorf("Users %+v", byPath["/Users"])
	}

	head := strings.Join(l2tFields, ",") + "\n"
	line := func(tz, desc, extra string) string {
		return "02/03/2026,10:15:00," + tz + ",M...,FILE,File stat,Content Modification Time,-,-,/a,TSK:/a " + desc + ",2,/a,5,-,filestat," + extra + "\n"
	}
	rows, err := readL2TCSV([]byte(head + line("UTC", "Type: file (unallocated)", "is_allocated: False; sha256_hash: "+strings.Repeat("CD", 32))))
	if err != nil || len(rows) != 1 || !rows[0].Deleted || rows[0].SHA256 != strings.Repeat("cd", 32) {
		t.Errorf("deleted row %+v, %v", rows, err)
	}
	if _, err := readL2TCSV([]byte(head + line("CET", "Type: file", "-"))); err == nil || !strings.Contains(err.Error(), "UTC") {
		t.Errorf("a timeline not in UTC: %v", err)
	}
	if _, err := readL2TCSV([]byte(head + "a,b,c\n")); err == nil {
		t.Error("a short line was accepted")
	}
}

// Plaso's dynamic CSV has one line per event; its display names carry the
// path-spec type and, from the NTFS back end, backslashes.
func TestReadDynamic(t *testing.T) {
	rows := readRows(t, readDynamic, "testdata/plaso-dynamic.csv")
	if len(rows) != 13 {
		t.Fatalf("%d rows, want 13", len(rows))
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.Path, `\Users`) || r.Times == (times{}) {
			t.Errorf("row %+v", r)
		}
	}
	extra := "datetime,timestamp_desc,source,message,display_name,filename,inode,is_allocated,md5_hash,number_of_links\n" +
		"2026-02-03T10:15:00.123456+00:00,Creation Time,FILE,m,OS:/x/a.txt,/x/a.txt,77,False,ABCDEF0123456789ABCDEF0123456789,3\n" +
		"0000-00-00T00:00:00.000000+00:00,Creation Time,FILE,m,OS:/x/b.txt,/x/b.txt,78,True,-,1\n"
	rows, err := readDynamic([]byte(extra))
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	r := rows[0]
	if r.Path != "/x/a.txt" || r.Inode != "77" || !r.Deleted || r.MD5 != "abcdef0123456789abcdef0123456789" || r.Links != 3 ||
		!r.Times[crtime].Equal(time.Date(2026, 2, 3, 10, 15, 0, 123456000, time.UTC)) {
		t.Errorf("row %+v", r)
	}
	if _, err := readDynamic([]byte("datetime,message\n")); err == nil {
		t.Error("a header without timestamp_desc was accepted")
	}
}

func TestDisplayPath(t *testing.T) {
	for in, want := range map[string]string{
		"OS:/home/a.txt":        "/home/a.txt",
		"TSK:/Users/a.txt":      "/Users/a.txt",
		`NTFS:\Users\a.txt`:     `\Users\a.txt`,
		`VSS2:TSK:/Users/a.txt`: "/Users/a.txt",
		`OS:C:\cases\out\a.txt`: `C:\cases\out\a.txt`,
		`C:\cases\out\a.txt`:    `C:\cases\out\a.txt`,
		"/no/prefix:Zone.Ident": "/no/prefix:Zone.Ident",
	} {
		if got := displayPath(in); got != want {
			t.Errorf("displayPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// fsagen's own timelines read back as what they were written from, in every
// format the oracle takes: names, streams, kinds, deletions, link targets,
// inodes, digests and times to the format's resolution.
func TestFsagenTimelinesReadBack(t *testing.T) {
	at := func(s int) time.Time { return time.Date(2026, 2, 3, 10, 0, s, 123456789, time.UTC) }
	tl := &timeline.Timeline{Source: timeline.SourceModelled, Entries: []timeline.Entry{
		{Path: "d", Type: timeline.TypeDir, Mode: fs.ModeDir | 0o755, Inode: "1", Atime: at(1), Mtime: at(2)},
		{Path: "d/a.txt", Type: timeline.TypeFile, Mode: 0o644, Size: 3, Inode: "2", Atime: at(3), Mtime: at(4), Ctime: at(5), Btime: at(6), MD5: strings.Repeat("1", 32), Links: 2},
		{Path: "d/a.txt", Stream: "Zone.Identifier", Type: timeline.TypeStream, Size: 9, Inode: "2", Atime: at(3), Mtime: at(4), MD5: strings.Repeat("2", 32)},
		{Path: "d/gone.txt", Type: timeline.TypeFile, Mode: 0o644, Inode: "3", Mtime: at(7), Deleted: true},
		{Path: "d/l", Type: timeline.TypeLink, Mode: 0o777, Inode: "4", Mtime: at(8), LinkTarget: "../t"},
	}}
	type want struct {
		path, stream string
		kind         string
		deleted      bool
		target       string
		links        int
	}
	wants := []want{{"d", "", "dir", false, "", 0}, {"d/a.txt", "", "file", false, "", 2}, {"d/a.txt", "Zone.Identifier", "file", false, "", 0}, {"d/gone.txt", "", "file", true, "", 0}, {"d/l", "", "link", false, "../t", 0}}
	for _, name := range []string{"bodyfile", "timesketch", "jsonl", "csv"} {
		var b bytes.Buffer
		if err := tl.Write(&b, name); err != nil {
			t.Fatal(err)
		}
		f, err := detect(b.Bytes())
		if err != nil || f.name != name {
			t.Fatalf("%s detected as %s, %v", name, f.name, err)
		}
		rows, err := f.read(b.Bytes())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rows) != len(wants) {
			t.Fatalf("%s: %d rows, want %d", name, len(rows), len(wants))
		}
		byKey := map[string]Row{}
		for _, r := range rows {
			p := strings.TrimPrefix(r.Path, "/")
			stream := r.Stream
			if r.Whole {
				p, stream = splitStream(p)
			}
			byKey[p+":"+stream] = r
		}
		for i, w := range wants {
			r, ok := byKey[w.path+":"+w.stream]
			if !ok {
				t.Errorf("%s: no row for %s:%s", name, w.path, w.stream)
				continue
			}
			if r.Kind != w.kind || r.Deleted != w.deleted || r.Inode != tl.Entries[i].Inode || r.MD5 != tl.Entries[i].MD5 {
				t.Errorf("%s: %s: %+v", name, w.path, r)
			}
			// The bodyfile and the timesketch events carry no link count,
			// and only the bodyfile and jsonl carry a link's target.
			if (name == "jsonl" && r.Links != w.links) || ((name == "bodyfile" || name == "jsonl") && r.Target != w.target) {
				t.Errorf("%s: %s: links %d target %q", name, w.path, r.Links, r.Target)
			}
			e := tl.Entries[i]
			resolution := map[string]time.Duration{"bodyfile": time.Second, "timesketch": time.Microsecond}[name]
			for j, t0 := range [4]time.Time{e.Atime, e.Mtime, e.Ctime, e.Btime} {
				want := t0
				if resolution != 0 {
					want = t0.Truncate(resolution)
				}
				if !r.Times[j].Equal(want) {
					t.Errorf("%s: %s %s = %v, want %v", name, w.path, timeNames[j], r.Times[j], want)
				}
			}
		}
	}
}

// A Plaso json_line event (one line per time, the stream on the path) reads
// as the timesketch format.
func TestReadPlasoJSONLine(t *testing.T) {
	in := `{"__container_type__":"event","data_type":"fs:stat","datetime":"2026-02-03T10:15:00.000001+00:00","timestamp":1770113700000001,"timestamp_desc":"Creation Time","display_name":"TSK:/a.txt:Zone.Identifier","filename":"/a.txt:Zone.Identifier","inode":66,"is_allocated":true,"number_of_links":1,"md5_hash":"AA` + strings.Repeat("0", 30) + `"}
{"data_type":"fs:stat:ntfs","timestamp":1770113700000000,"timestamp_desc":"Creation Time","filename":"/a.txt","attribute_type":48,"is_allocated":true}
{"data_type":"windows:evtx:record","timestamp":1770113700000000,"timestamp_desc":"Creation Time","filename":"/a.txt"}
`
	rows, err := readTimesketch([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Path != "/a.txt:Zone.Identifier" || !r.Whole || r.Inode != "66" || r.Links != 1 || r.MD5 != "aa"+strings.Repeat("0", 30) ||
		!r.Times[crtime].Equal(time.UnixMicro(1770113700000001).UTC()) {
		t.Errorf("row %+v", r)
	}
	if !rows[1].FileName {
		t.Errorf("an MFT $FILE_NAME event is not marked: %+v", rows[1])
	}
}
