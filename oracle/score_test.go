package oracle

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/ledger"
)

// macroPhish is the macro-phish example's expected state and its modelled
// bodyfile, the starting point for the perturbations below.
func macroPhish(t *testing.T) (*Expected, []Row) {
	t.Helper()
	x := goldenExpected(t, "windows", "playbook-macro-phish")
	rows := readRows(t, readBodyfile, filepath.Join(goldenDir, "windows", "bodyfile", "playbook-macro-phish.body"))
	return x, rows
}

func score(t *testing.T, x *Expected, rows []Row, opts Options) map[string]*Category {
	t.Helper()
	cats, _, err := Score(x, rows, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*Category{}
	for _, c := range cats {
		out[c.Name] = c
	}
	return out
}

func rowAt(t *testing.T, rows []Row, path string) int {
	t.Helper()
	i := slices.IndexFunc(rows, func(r Row) bool { return r.Path == path })
	if i < 0 {
		t.Fatalf("no row %s", path)
	}
	return i
}

const docm = "/Users/victim/Downloads/Invoice_4471.docm"

// The perturbations the plan names: a row dropped lowers recall and is
// listed missing, a time a second off fails with no tolerance and passes
// with a second's, and a row the run never made lowers precision.
func TestPerturbations(t *testing.T) {
	x, rows := macroPhish(t)

	t.Run("dropped", func(t *testing.T) {
		i := rowAt(t, rows, docm)
		cats := score(t, x, slices.Delete(slices.Clone(rows), i, i+1), Options{})
		files := cats[catFiles]
		if files.FN != 1 || files.FP != 0 || !slices.Equal(files.Missing, []string{strings.TrimPrefix(docm, "/")}) {
			t.Errorf("files %+v", files)
		}
		if v, _ := files.Recall.Value(); v >= 1 {
			t.Errorf("recall %s", files.Recall)
		}
		if p, _ := files.Precision.Value(); p != 1 {
			t.Errorf("precision %s", files.Precision)
		}
	})

	t.Run("shifted", func(t *testing.T) {
		shifted := slices.Clone(rows)
		i := rowAt(t, shifted, docm)
		shifted[i].Times[mtime] = shifted[i].Times[mtime].Add(time.Second)
		if c := score(t, x, shifted, Options{})[catTimes]; c.FP != 1 || c.FN != 1 || len(c.Wrong) != 1 || c.Wrong[0].Field != "mtime" {
			t.Errorf("tolerance 0: %+v", c)
		}
		if c := score(t, x, shifted, Options{Tolerance: time.Second})[catTimes]; c.FP != 0 || c.FN != 0 {
			t.Errorf("tolerance 1s: %+v", c)
		}
		if c := score(t, x, shifted, Options{Tolerance: time.Second - 1})[catTimes]; c.FP != 1 {
			t.Errorf("tolerance 1s-1ns: %+v", c)
		}
	})

	t.Run("unknown time", func(t *testing.T) {
		blank := slices.Clone(rows)
		i := rowAt(t, blank, docm)
		blank[i].Times[crtime] = time.Time{}
		if c := score(t, x, blank, Options{})[catTimes]; c.FP != 0 || c.FN != 1 || c.Wrong[0].Found != "" {
			t.Errorf("%+v", c)
		}
	})

	t.Run("extra", func(t *testing.T) {
		extra := append(slices.Clone(rows), Row{Line: 99, Path: "/Users/victim/Downloads/payload.zip", Whole: true})
		files := score(t, x, extra, Options{})[catFiles]
		if files.FP != 1 || files.FN != 0 || len(files.Extra) != 1 || files.Extra[0].Line != 99 {
			t.Errorf("files %+v", files)
		}
		if p, _ := files.Precision.Value(); p >= 1 {
			t.Errorf("precision %s", files.Precision)
		}
	})

	t.Run("twice", func(t *testing.T) {
		twice := append(slices.Clone(rows), rows[rowAt(t, rows, docm)])
		if files := score(t, x, twice, Options{})[catFiles]; files.FP != 1 || !strings.Contains(files.Extra[0].Reason, "again") {
			t.Errorf("files %+v", files)
		}
	})

	t.Run("wrong digest", func(t *testing.T) {
		bad := slices.Clone(rows)
		bad[rowAt(t, bad, docm)].MD5 = strings.Repeat("0", 32)
		if c := score(t, x, bad, Options{})[catHashes]; c.FP != 1 || c.FN != 1 || c.Wrong[0].Field != "md5" {
			t.Errorf("%+v", c)
		}
		none := slices.Clone(rows)
		none[rowAt(t, none, docm)].MD5 = ""
		if c := score(t, x, none, Options{})[catHashes]; c.FP != 0 || c.FN != 0 || c.Checked != c.Expected-1 {
			t.Errorf("a digest not computed is held against the tool: %+v", c)
		}
	})

	t.Run("split link", func(t *testing.T) {
		split := slices.Clone(rows)
		split[rowAt(t, split, "/Users/Public/Libraries/cache.dat")].Inode = "99"
		if c := score(t, x, split, Options{})[catLinks]; c.FP != 1 || c.FN != 1 || c.Wrong[0].Field != "inode" {
			t.Errorf("%+v", c)
		}
		counted := slices.Clone(rows)
		counted[rowAt(t, counted, "/Users/Public/Libraries/cache.dat")].Links = 3
		if c := score(t, x, counted, Options{})[catLinks]; c.FP != 1 || c.Wrong[0].Field != "links" {
			t.Errorf("%+v", c)
		}
	})
}

// A tool's paths are found under whatever it calls the output root, which
// is detected, and rows elsewhere, the file system's own entries and
// $FILE_NAME records are set aside, not counted wrong.
func TestPrefixes(t *testing.T) {
	x, model := macroPhish(t)
	mount := func(prefix string, backslash bool) []Row {
		var out []Row
		for _, r := range model {
			p := prefix + r.Path
			if backslash {
				p = strings.ReplaceAll(p, "/", `\`)
			}
			r.Path = p
			out = append(out, r)
		}
		if prefix != "" {
			out = append(out, Row{Line: 100, Path: "/mnt/other/file.txt", Whole: true})
		}
		out = append(out,
			Row{Line: 101, Path: prefix + "/$MFT", Whole: true},
			Row{Line: 102, Path: prefix + "/Users ($FILE_NAME)", Whole: true, FileName: true},
			Row{Line: 103, Path: prefix, Whole: true, Kind: "dir"},
		)
		return out
	}
	for _, c := range []struct {
		prefix    string
		backslash bool
		shown     string
	}{{"/mnt/case/out", false, "/mnt/case/out"}, {"C:/cases/out", true, "C:/cases/out"}, {"", false, "/"}} {
		cats, rep, err := Score(x, mount(c.prefix, c.backslash), Options{})
		if err != nil {
			t.Fatal(err)
		}
		perfect(t, cats)
		if rep.Prefix != c.shown || !rep.PrefixDetected || rep.VolumeFiles != 1 || rep.FilenameRecords != 1 {
			t.Errorf("%q: %+v", c.prefix, rep)
		}
		if c.prefix != "" && rep.OutsidePrefix != 1 {
			t.Errorf("%q: %d outside", c.prefix, rep.OutsidePrefix)
		}
	}

	cats, rep, err := Score(x, mount("/mnt/case/out", false), Options{Prefix: "/mnt/case/out/", PrefixSet: true})
	if err != nil || rep.PrefixDetected {
		t.Fatal(err, rep)
	}
	perfect(t, cats)
	if cats, _, _ := Score(x, mount("/mnt/case/out", false), Options{Prefix: "/mnt/case", PrefixSet: true}); category(cats, catFiles).TP != 0 {
		t.Errorf("a wrong prefix still found %d names", category(cats, catFiles).TP)
	}
	if _, _, err := Score(x, []Row{{Path: "/nothing/here"}}, Options{}); err == nil {
		t.Error("rows naming nothing in the run were scored")
	}
}

// On a volume that ignores case a name matches whatever case the tool
// writes it in, and in Plaso's CSVs a comma in a name, which Plaso writes
// as a space, still matches.
func TestCaseAndCommas(t *testing.T) {
	x := newExpected()
	x.foldLedger([]ledger.Entry{{N: 1, Outcome: ledger.Done, Action: "create", Path: "Docs/Q1,Q2 Report.txt", Object: 1, Kind: "file"}})
	rows := []Row{{Path: "/docs/q1 q2 report.txt", Whole: true}, {Path: "/DOCS", Whole: true}}
	if c := score(t, x, rows, Options{Fold: true, Commas: true})[catFiles]; c.TP != 2 || c.FP != 0 {
		t.Errorf("folded: %+v", c)
	}
	if _, _, err := Score(x, rows, Options{Commas: true}); err == nil {
		t.Error("names in another case matched with case kept")
	}
	if c := score(t, x, rows, Options{Fold: true})[catFiles]; c.TP != 1 || c.FP != 1 {
		t.Errorf("commas kept: %+v", c)
	}
}

// A colon starts a stream name only on a volume that keeps streams;
// elsewhere it is part of a name, and a name the run did not make is an
// extra file, not an extra stream.
func TestColonsWithoutStreams(t *testing.T) {
	entries := []ledger.Entry{
		{N: 1, Outcome: ledger.Done, Action: "create", Path: "a.txt", Object: 1, Kind: "file"},
		{N: 2, Outcome: ledger.Done, Action: "create", Path: "b:c.txt", Object: 2, Kind: "file"},
	}
	rows := []Row{{Path: "/a.txt", Whole: true}, {Path: "/b:c.txt", Whole: true}, {Line: 3, Path: "/a.txt:x", Whole: true}}
	for _, streams := range []bool{false, true} {
		x := newExpected()
		x.namedStreams = streams
		x.foldLedger(entries)
		cats := score(t, x, rows, Options{})
		files, st := cats[catFiles], cats[catStreams]
		if files.TP != 2 || (streams && (files.FP != 0 || st.FP != 1)) || (!streams && (files.FP != 1 || st.FP != 0)) {
			t.Errorf("named streams %v: files %+v streams %+v", streams, files, st)
		}
	}
}

// Several objects deleted from one path are each a deleted entry, and a
// tool's deleted row is credited to the one whose times it shows.
func TestDeletedGenerations(t *testing.T) {
	t1, t2 := "2026-01-01T10:00:00Z", "2026-01-02T10:00:00Z"
	tm := func(s string) *ledger.Times { return &ledger.Times{Atime: s, Mtime: s, Ctime: s, Crtime: s} }
	x := newExpected()
	x.foldLedger([]ledger.Entry{
		{N: 1, Outcome: ledger.Done, Action: "create", Path: "tmp/x.dat", Object: 2, Kind: "file", Times: tm(t1)},
		{N: 2, Outcome: ledger.Done, Action: "delete", Path: "tmp/x.dat", Object: 2, Kind: "file", Times: tm(t1)},
		{N: 3, Outcome: ledger.Done, Action: "create", Path: "tmp/x.dat", Object: 3, Kind: "file", Times: tm(t2)},
		{N: 4, Outcome: ledger.Done, Action: "delete", Path: "tmp/x.dat", Object: 3, Kind: "file", Times: tm(t2)},
	})
	second, _ := time.Parse(time.RFC3339, t2)
	row := Row{Line: 7, Path: "/tmp/x.dat", Whole: true, Deleted: true, Times: times{second, second, second, second}}
	cats := score(t, x, []Row{{Path: "/tmp", Whole: true}, row}, Options{})
	if c := cats[catDeleted]; c.Expected != 2 || c.TP != 1 || c.FN != 1 || !slices.Equal(c.Missing, []string{"tmp/x.dat (deleted by operation 2)"}) {
		t.Errorf("deleted %+v", c)
	}
	if c := cats[catTimes]; c.TP != 4 || c.FP != 0 {
		t.Errorf("the row was not credited to the deletion its times match: %+v", c)
	}
	both := []Row{{Path: "/tmp", Whole: true}, row, row, row}
	all, rep, _ := Score(x, both, Options{})
	if c := category(all, catDeleted); c.TP != 2 || c.FP != 0 || rep.OldNames != 1 {
		t.Errorf("deleted %+v, old names %d", c, rep.OldNames)
	}
}

// What is left of a renamed file under its old name is a real trace, not
// an error; a deleted entry the run never had anything at is.
func TestOldNames(t *testing.T) {
	x := newExpected()
	x.foldLedger([]ledger.Entry{
		{N: 1, Outcome: ledger.Done, Action: "create", Path: "a/old.txt", Object: 2, Kind: "file"},
		{N: 2, Outcome: ledger.Done, Action: "rename", Path: "a/old.txt", NewPath: "b/new.txt", Object: 2, Kind: "file"},
	})
	rows := []Row{
		{Path: "/a", Whole: true}, {Path: "/b", Whole: true}, {Path: "/b/new.txt", Whole: true},
		{Line: 4, Path: "/a/old.txt", Whole: true, Deleted: true},
		{Line: 5, Path: "/a/never.txt", Whole: true, Deleted: true},
		{Line: 6, Path: "/a/old.txt", Whole: true},
	}
	cats, rep, err := Score(x, rows, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OldNames != 1 {
		t.Errorf("old names %d", rep.OldNames)
	}
	if c := category(cats, catDeleted); c.FP != 1 || c.Extra[0].Line != 5 {
		t.Errorf("deleted %+v", c)
	}
	if c := category(cats, catFiles); c.TP != 3 || c.FP != 1 || c.Extra[0].Line != 6 || !strings.Contains(c.Extra[0].Reason, "moved or deleted") {
		t.Errorf("files %+v", c)
	}
}

// A symlink is scored on where it points, where the tool says.
func TestSymlinkTargets(t *testing.T) {
	x := newExpected()
	x.foldLedger([]ledger.Entry{{N: 1, Outcome: ledger.Done, Action: "symlink", Path: "l", Object: 1, Kind: "symlink", Target: `..\t`}})
	for target, ok := range map[string]bool{"../t": true, `..\t`: true, "../u": false, "": true} {
		c := score(t, x, []Row{{Path: "/l", Whole: true, Kind: "link", Target: target}}, Options{})[catLinks]
		switch {
		case target == "" && c.Checked != 0:
			t.Errorf("no target reported, but checked: %+v", c)
		case target != "" && ok != (c.TP == 1):
			t.Errorf("target %q: %+v", target, c)
		}
	}
}

// A modelled timeline gives directories their times; one of another run is
// refused.
func TestUseModel(t *testing.T) {
	x, model := macroPhish(t)
	if err := x.UseModel(model); err != nil {
		t.Fatal(err)
	}
	cats, _, err := Score(x, model, Options{})
	if err != nil {
		t.Fatal(err)
	}
	perfect(t, cats)
	if c := category(cats, catTimes); c.Expected != 16+4*9 {
		t.Errorf("times expected %d; the nine directories' four times each were not added", c.Expected)
	}

	other, _ := macroPhish(t)
	missing := slices.DeleteFunc(slices.Clone(model), func(r Row) bool { return r.Path == "/Users/victim/Documents" })
	if err := other.UseModel(missing); err == nil || !strings.Contains(err.Error(), "does not list Users/victim/Documents") {
		t.Errorf("a model missing a directory: %v", err)
	}
	extra := append(slices.Clone(model), Row{Path: "/elsewhere.txt", Whole: true})
	if err := other.UseModel(extra); err == nil || !strings.Contains(err.Error(), "elsewhere.txt") {
		t.Errorf("a model with a name the run did not leave: %v", err)
	}
}

// The times of a name's $FILE_NAME are scored where they are known: those
// a timestomp set on an image, kept through a move of the directory above
// and forgotten when the name itself moves, and every name's from a
// modelled timeline that lists them. A $FILE_NAME row of a name the run did
// not leave, or of a deleted entry, is set aside.
func TestFileNames(t *testing.T) {
	stomped := "2001-02-03T04:05:06Z"
	fn := &ledger.Times{Mtime: stomped, Crtime: stomped}
	x := newExpected()
	x.foldLedger([]ledger.Entry{
		{N: 1, Outcome: ledger.Done, Action: "create", Path: "d/a.txt", Object: 1, Kind: "file"},
		{N: 2, Outcome: ledger.Done, Action: "create", Path: "b.txt", Object: 2, Kind: "file"},
		{N: 3, Outcome: ledger.Done, Action: "timestomp", Path: "d/a.txt", Object: 1, Kind: "file", FnTimes: fn, Uncontrolled: []string{"fn_atime", "fn_ctime"}},
		{N: 4, Outcome: ledger.Done, Action: "timestomp", Path: "b.txt", Object: 2, Kind: "file", FnTimes: fn},
		{N: 5, Outcome: ledger.Done, Action: "rename", Path: "d", NewPath: "e", Object: 3, Kind: "dir"},
		{N: 6, Outcome: ledger.Done, Action: "rename", Path: "b.txt", NewPath: "c.txt", Object: 2, Kind: "file"},
	})
	at := must(time.Parse(time.RFC3339, stomped))
	if got := x.fileNames["e/a.txt"]; got != (times{mtime: at, crtime: at}) || len(x.fileNames) != 1 {
		t.Fatalf("expected $FILE_NAME times %+v", x.fileNames)
	}
	rows := []Row{
		{Path: "/e/a.txt", Whole: true},
		{Path: "/e/a.txt", Whole: true, FileName: true, Times: times{mtime: at, crtime: at.Add(time.Second)}},
		{Path: "/c.txt", Whole: true},
		{Path: "/c.txt", Whole: true, FileName: true, Times: times{mtime: at}},
		{Path: "/gone.txt", Whole: true, FileName: true, Deleted: true},
	}
	cats, rep, err := Score(x, rows, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := category(cats, catFileNames)
	if c.Expected != 2 || c.TP != 1 || c.FP != 1 || c.FN != 1 || len(c.Wrong) != 1 || c.Wrong[0].Field != "crtime" || rep.FilenameRecords != 1 {
		t.Errorf("filenames %+v, %d set aside", c, rep.FilenameRecords)
	}
	if c := score(t, x, rows, Options{Tolerance: time.Second})[catFileNames]; c.TP != 2 || c.FP != 0 {
		t.Errorf("within a second: %+v", c)
	}

	modelled := append(slices.Clone(rows[:4]), Row{Path: "/e", Whole: true})
	modelled[3].Times = times{at, at, at, at}
	if err := x.UseModel(modelled); err != nil {
		t.Fatal(err)
	}
	if c := score(t, x, rows, Options{Tolerance: time.Second})[catFileNames]; c.Expected != 2+4 || c.Checked != 6 || c.TP != 3 || c.FN != 3 {
		t.Errorf("with a model: %+v", c)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
