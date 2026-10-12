package oracle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenDir holds the recorded ledgers and modelled bodyfiles of every
// example, for both platforms.
const goldenDir = "../testdata/golden/v8"

// goldenExpected folds a recorded ledger, as LoadExpected would without the
// sidecar files the goldens do not keep.
func goldenExpected(t *testing.T, platform, name string) *Expected {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, platform, "ledger", name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseLedger(data)
	if err != nil {
		t.Fatal(err)
	}
	x := newExpected()
	x.namedStreams = platform == "windows"
	x.foldLedger(entries)
	return x
}

func readRows(t *testing.T, read func([]byte) ([]Row, error), name string) []Row {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := read(data)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func category(cats []*Category, name string) *Category {
	for _, c := range cats {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// perfect fails the test for every category with a false positive or
// negative.
func perfect(t *testing.T, cats []*Category) {
	t.Helper()
	for _, c := range cats {
		if c.FP != 0 || c.FN != 0 {
			t.Errorf("%s: tp %d fp %d fn %d\n  missing %v\n  extra %v\n  wrong %v", c.Name, c.TP, c.FP, c.FN, c.Missing, c.Extra, c.Wrong)
		}
	}
}

// The modelled bodyfile of every example is what the scenario intends, so
// scored against the ledger it must be found whole, on both platforms: every
// name, deletion and stream, every time the ledger knows, every digest and
// every link. It is how the ledger fold is checked against the model it
// stands in for. The examples' times are whole seconds, so the bodyfile
// keeps them exactly, and no tolerance is needed.
func TestModelledBodyfilesScoreOne(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		bodies, _ := filepath.Glob(filepath.Join(goldenDir, platform, "bodyfile", "*.body"))
		if len(bodies) == 0 {
			t.Fatalf("no golden bodyfiles for %s", platform)
		}
		for _, body := range bodies {
			name := strings.TrimSuffix(filepath.Base(body), ".body")
			t.Run(platform+"/"+name, func(t *testing.T) {
				x := goldenExpected(t, platform, name)
				rows := readRows(t, readBodyfile, body)
				cats, rep, err := Score(x, rows, Options{})
				if err != nil {
					t.Fatal(err)
				}
				perfect(t, cats)
				for _, c := range cats {
					t.Logf("%-8s expected %3d checked %3d tp %3d", c.Name, c.Expected, c.Checked, c.TP)
				}
				if rep.Prefix != "/" || rep.OutsidePrefix != 0 || rep.VolumeFiles != 0 || rep.OldNames != 0 {
					t.Errorf("paths %+v", rep)
				}
				if c := category(cats, catTimes); c.Checked != c.Expected {
					t.Errorf("times: %d checked of %d expected", c.Checked, c.Expected)
				}
			})
		}
	}
}
