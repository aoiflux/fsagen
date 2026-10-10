package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runOracle runs fsagen diff-oracle through the same entry point main uses.
func runOracle(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{diffOracle}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// fsagen's own timelines of a run, scored against it. The modelled one is
// the scenario itself, so it scores 1 in every category with no tolerance at
// all, directory times included once it is given as the model too. The
// observed one, read back from the disk, scores 1 on everything a live
// volume keeps: every name, stream, time the run controls, digest and link
// (its deleted entries are gone, which is why that category is left out).
func TestDiffOracleScoresFsagenTimelines(t *testing.T) {
	if !linkCaps(t).Hard {
		t.Skip("this volume stores no hard links, which the macro-phish example makes")
	}
	for _, example := range []string{"playbook-macro-phish.yaml", "playbook-basic.yaml"} {
		t.Run(example, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			model := filepath.Join(dir, "model.jsonl")
			if code, _, stderr := runCLI(t, "--playbook", filepath.Join("examples", example), "--seed", "3", "--timeline-source", "modelled", "--timeline", model, out); code != 0 {
				t.Fatalf("generate: exit %d: %s", code, stderr)
			}
			meta := out + ".fsagen"
			if code, report, stderr := runOracle(t, "--meta", meta, "--model", model, "--time-tolerance", "0", "--fail-under", "1", model); code != 0 {
				t.Errorf("modelled: exit %d: %s\n%s", code, stderr, report)
			}

			observed := filepath.Join(dir, "observed.jsonl")
			if code, _, stderr := runCLI(t, "--timeline", observed, out); code != 0 {
				t.Fatalf("observed timeline: exit %d: %s", code, stderr)
			}
			code, report, stderr := runOracle(t, "--meta", meta, "--categories", "files,streams,times,hashes,links", "--time-tolerance", "0", "--fail-under", "1", observed)
			if code != 0 {
				t.Errorf("observed: exit %d: %s\n%s", code, stderr, report)
			}
			if !strings.Contains(report, "output root . (detected)") {
				t.Errorf("an observed timeline's paths are relative to the output root:\n%s", report)
			}
		})
	}
}

// A bulk corpus has no ledger; SHA256SUMS alone says what is there, so its
// observed timeline is scored on names, and finds them all. SHA256SUMS
// knows SHA-256s and the timeline gives MD5s, so no digest can be checked,
// and none is held against it.
func TestDiffOracleScoresBulk(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bulk")
	if code, _, stderr := runCLI(t, "--bulk", "1", "--depth", "2", "--seed", "5", out); code != 0 {
		t.Fatalf("generate: exit %d: %s", code, stderr)
	}
	observed := filepath.Join(dir, "observed.csv")
	if code, _, stderr := runCLI(t, "--timeline", observed, out); code != 0 {
		t.Fatalf("observed timeline: exit %d: %s", code, stderr)
	}
	scorecard := filepath.Join(dir, "scorecard.json")
	code, report, stderr := runOracle(t, "--meta", out+".fsagen", "--scorecard", scorecard, "--fail-under", "1", observed)
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, stderr, report)
	}
	var card struct {
		Operations int
		Categories []struct {
			Name                      string
			Expected, Checked, TP, FP int
		}
	}
	data, _ := os.ReadFile(scorecard)
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatal(err)
	}
	files, hashes := card.Categories[0], card.Categories[4]
	if card.Operations != 0 || files.Expected < 50 || files.TP != files.Expected || hashes.Expected == 0 || hashes.Checked != 0 {
		t.Errorf("files %+v, hashes %+v\n%s", files, hashes, report)
	}
}

// diff-oracle is a subcommand only as the first argument; an output
// directory of that name is written ./diff-oracle, and generates as any
// other.
func TestDiffOracleDispatch(t *testing.T) {
	if code, out, _ := runOracle(t, "-h"); code != 0 || !strings.HasPrefix(out, "Usage: fsagen diff-oracle") {
		t.Errorf("diff-oracle -h: exit %d\n%s", code, out)
	}
	if code, _, stderr := runOracle(t); code != exitUsage || !strings.Contains(stderr, "fsagen diff-oracle: missing") {
		t.Errorf("diff-oracle with nothing: exit %d: %s", code, stderr)
	}
	dir := t.TempDir()
	in := writeYAML(t, dir, "m.yaml", "operations:\n  - { action: create, path: a.txt, content: hello }\n")
	t.Chdir(dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"--manifest", in, "./" + diffOracle}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if data, err := os.ReadFile(filepath.Join(dir, diffOracle, "a.txt")); err != nil || string(data) != "hello" {
		t.Errorf("./diff-oracle/a.txt = %q, %v", data, err)
	}
	var help bytes.Buffer
	if code := run([]string{"-h"}, &help, &errOut); code != 0 || !strings.Contains(help.String(), "fsagen diff-oracle --meta DIR") {
		t.Errorf("fsagen -h does not mention the subcommand:\n%s", help.String())
	}
}
