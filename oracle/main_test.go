package oracle

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden report and scorecard")

const fixtureMeta = "testdata/macro-phish.fsagen"

func runMain(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &out, &errs)
	return code, out.String(), errs.String()
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to record it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("%s differs from what was recorded; got:\n%s", name, got)
	}
}

// The report and scorecard for a listing in the shape fls -r -m gives of an
// NTFS image of the macro-phish run, with mistakes of every kind a tool can
// make: a file missed, a directory and a deleted entry and a stream made
// up, a time and a digest wrong, a directory named in another case (which
// NTFS does not tell apart), the volume's own files, $FILE_NAME records,
// and a row from another volume.
func TestGoldenReport(t *testing.T) {
	sc := filepath.Join(t.TempDir(), "scorecard.json")
	code, out, errs := runMain(t, "", "--meta", fixtureMeta, "--scorecard", sc, "testdata/fls.body")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	golden(t, "fls.report.txt", []byte(out))
	data, err := os.ReadFile(sc)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "fls.scorecard.json", data)
}

// Plaso's two CSV outputs of the same run, one through the TSK back end and
// one through the NTFS one, find everything they report.
func TestPlasoOutputsScoreOne(t *testing.T) {
	for _, name := range []string{"plaso.l2tcsv", "plaso-dynamic.csv"} {
		t.Run(name, func(t *testing.T) {
			sc := filepath.Join(t.TempDir(), "scorecard.json")
			code, out, errs := runMain(t, "", "--meta", fixtureMeta, "--scorecard", sc, "--categories", "files,deleted,streams,times,links", filepath.Join("testdata", name))
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errs)
			}
			var card struct {
				Format     string
				Categories []struct {
					Name            string
					Checked, FP, FN int
				}
				Overall struct{ FP, FN int }
			}
			data, _ := os.ReadFile(sc)
			if err := json.Unmarshal(data, &card); err != nil {
				t.Fatal(err)
			}
			if card.Overall.FP != 0 || card.Overall.FN != 0 || len(card.Categories) != 5 {
				t.Errorf("%s", out)
			}
			for _, c := range card.Categories {
				if c.Name == catLinks && c.Checked != 2 {
					t.Errorf("links checked %d, want both names of the hard-linked file\n%s", c.Checked, out)
				}
			}
		})
	}
}

func TestMainExitCodes(t *testing.T) {
	failed := t.TempDir()
	for _, f := range []string{"ledger.jsonl", "run-info.json", "SHA256SUMS"} {
		data, _ := os.ReadFile(filepath.Join(fixtureMeta, f))
		os.WriteFile(filepath.Join(failed, f), data, 0o644)
	}
	os.WriteFile(filepath.Join(failed, "run-manifest.json"), []byte(`{"status":"failed","mode":"playbook"}`), 0o644)

	other := t.TempDir()
	for _, f := range []string{"ledger.jsonl", "run-info.json", "run-manifest.json"} {
		data, _ := os.ReadFile(filepath.Join(fixtureMeta, f))
		os.WriteFile(filepath.Join(other, f), data, 0o644)
	}
	sums, _ := os.ReadFile(filepath.Join(fixtureMeta, "SHA256SUMS"))
	os.WriteFile(filepath.Join(other, "SHA256SUMS"), bytes.Replace(sums, []byte("0c4d"), []byte("ffff"), 1), 0o644)

	body, _ := os.ReadFile("testdata/fls.body")
	cases := []struct {
		name  string
		stdin string
		args  []string
		code  int
		say   string
	}{
		{"help", "", []string{"-h"}, exitOK, "Usage: fsagen diff-oracle"},
		{"no output", "", []string{"--meta", fixtureMeta}, exitUsage, "missing the tool's output"},
		{"no meta", "", []string{"testdata/fls.body"}, exitUsage, "--meta is required"},
		{"two outputs", "", []string{"--meta", fixtureMeta, "a", "b"}, exitUsage, "unexpected argument"},
		{"format", "", []string{"--meta", fixtureMeta, "--format", "xml", "x"}, exitUsage, "--format must be one of bodyfile, l2tcsv"},
		{"tolerance", "", []string{"--meta", fixtureMeta, "--time-tolerance", "soon", "x"}, exitUsage, "--time-tolerance"},
		{"negative tolerance", "", []string{"--meta", fixtureMeta, "--time-tolerance", "-1s", "x"}, exitUsage, "--time-tolerance"},
		{"case", "", []string{"--meta", fixtureMeta, "--case", "upper", "x"}, exitUsage, "--case"},
		{"categories", "", []string{"--meta", fixtureMeta, "--categories", "files,colours", "x"}, exitUsage, `"colours"`},
		{"fail-under range", "", []string{"--meta", fixtureMeta, "--fail-under", "2", "x"}, exitUsage, "between 0 and 1"},
		{"missing meta", "", []string{"--meta", "testdata/nowhere", "testdata/fls.body"}, exitError, "not a run's sidecar directory"},
		{"failed run", "", []string{"--meta", failed, "testdata/fls.body"}, exitError, "did not complete"},
		{"another run's sums", "", []string{"--meta", other, "testdata/fls.body"}, exitError, "not from one run"},
		{"unreadable output", "", []string{"--meta", fixtureMeta, "--format", "l2tcsv", "testdata/fls.body"}, exitError, "l2tcsv header"},
		{"below", "", []string{"--meta", fixtureMeta, "--fail-under", "0.95", "testdata/fls.body"}, exitBelow, "below --fail-under 0.95"},
		{"above", "", []string{"--meta", fixtureMeta, "--fail-under", "0.5", "testdata/fls.body"}, exitOK, ""},
		{"stdin", string(body), []string{"--meta", fixtureMeta, "-"}, exitOK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := runMain(t, c.stdin, c.args...)
			if code != c.code || !strings.Contains(out+errs, c.say) {
				t.Errorf("exit %d (want %d)\nstdout:\n%s\nstderr:\n%s", code, c.code, out, errs)
			}
		})
	}
}

// --categories scores only the categories named, and the overall score is
// theirs alone; --case and --time-tolerance are what the report says they
// were.
func TestMainOptions(t *testing.T) {
	sc := filepath.Join(t.TempDir(), "scorecard.json")
	code, out, errs := runMain(t, "", "--meta", fixtureMeta, "--categories", "links,files", "--case", "exact", "--time-tolerance", "0", "--scorecard", sc, "testdata/fls.body")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var card struct {
		Case       string
		Tolerance  string `json:"time_tolerance"`
		Categories []struct {
			Name       string
			TP, FP, FN int
		}
		Overall struct{ TP int }
	}
	data, _ := os.ReadFile(sc)
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatal(err)
	}
	if card.Case != caseExact || card.Tolerance != "0s" || len(card.Categories) != 2 || card.Categories[0].Name != catFiles || card.Categories[1].Name != catLinks {
		t.Errorf("scorecard %+v\n%s", card, out)
	}
	// With case kept, the Downloads directory fls wrote as "downloads" is
	// not found, and the file in it neither.
	if f := card.Categories[0]; f.FN != 3 || f.FP != 3 {
		t.Errorf("files with case kept: %+v", f)
	}
	if card.Overall.TP != card.Categories[0].TP+card.Categories[1].TP {
		t.Errorf("overall %+v counts categories not asked for", card.Overall)
	}
}
