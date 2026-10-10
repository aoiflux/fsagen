package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/internal/memtarget"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/ledger"
	manifestpkg "github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/runinfo"
)

// A target in memory, claiming what a Windows NTFS volume offers, takes
// every shipped example through the same generating pass the command runs,
// in the order an image takes it: execute, settle, finish, verify, digest.
// Every name, byte, stream and link it ends up holding, the ledger, the
// answer key and SHA256SUMS are the Windows goldens', byte for byte, on
// whatever platform the test runs. That is what proves the target
// interfaces carry a whole scenario, and that nothing in the pass reaches
// past them to the disk.
func TestOneGoTargetReproducesWindowsGoldens(t *testing.T) {
	dir := filepath.Join("testdata", "golden", fmt.Sprintf("v%d", constant.GeneratorVersion), "windows")
	for _, path := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			c := &config{seed: exampleSeed}
			if exampleMode(path) == compile.ModeManifest {
				c.manifest = path
			} else {
				c.playbook = path
			}
			prog, err := compile.Load(inputMode(c), path, compile.Options{Seed: exampleSeed})
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()
			mem := memtarget.New(memtarget.WindowsCaps)
			caps := manifestpkg.Caps(mem)
			if err := compile.Preflight(prog, caps, false); err != nil {
				t.Fatal(err)
			}
			metaDir := t.TempDir()
			g := runGeneration(c, mem, prog, caps, runinfo.New(string(inputMode(c)), c.seed), metaDir)
			if g.err != nil {
				t.Fatal(g.err)
			}
			if mem.Finishes != 1 || mem.WritesAfterFinish != 0 {
				t.Errorf("finished %d time(s), with %d write(s) after", mem.Finishes, mem.WritesAfterFinish)
			}

			got, err := testutil.FingerprintOf(mem)
			if err != nil {
				t.Fatal(err)
			}
			in := testutil.InputHash(t, path)
			examples := filepath.Join(dir, "examples", name+".txt")
			testutil.CheckGolden(t, examples, in, got, false)
			testutil.CheckGolden(t, filepath.Join(dir, "ledger", name+".jsonl"), in, string(ledger.Bytes(g.entries)), false)
			key := manifestpkg.AnswerKey(prog.Model, g.entries, caps)
			testutil.CheckGolden(t, filepath.Join(dir, "answer-key", name+".jsonl"), in, string(ledger.FactBytes(key)), false)

			sums, err := os.ReadFile(filepath.Join(metaDir, runinfo.SumsFileName))
			if err != nil {
				t.Fatal(err)
			}
			if want := sumsOf(t, examples); string(sums) != want {
				t.Errorf("%s:\n%s\nwant (from %s):\n%s", runinfo.SumsFileName, sums, examples, want)
			}
		})
	}
}

// A bulk corpus written into a target in memory is the bulk golden's, and
// is finished once before it is digested.
func TestOneGoTargetTakesBulk(t *testing.T) {
	c := &config{seed: 7, bulk: 1, depth: 1, bulkStart: bulkGoldenStart}
	rm := runinfo.New(modeBulk, c.seed)
	recordBulkOptions(rm, c)
	mem := memtarget.New(memtarget.WindowsCaps)
	if g := runGeneration(c, mem, nil, manifestpkg.Caps(mem), rm, t.TempDir()); g.err != nil {
		t.Fatal(g.err)
	}
	if mem.Finishes != 1 || mem.WritesAfterFinish != 0 {
		t.Errorf("finished %d time(s), with %d write(s) after", mem.Finishes, mem.WritesAfterFinish)
	}
	got, err := testutil.FingerprintOf(mem)
	if err != nil {
		t.Fatal(err)
	}
	in := testutil.SpecHash(fmt.Sprintf("seed=%d limit=%d depth=%d start=%s", c.seed, c.bulk, c.depth, bulkGoldenStart))
	golden := filepath.Join("testdata", "golden", fmt.Sprintf("v%d", constant.GeneratorVersion), "bulk", "one-of-each.txt")
	testutil.CheckGolden(t, golden, in, got, false)
}

// sumsOf is the SHA256SUMS a fingerprint golden implies: a line for every
// file and stream, sorted by path.
func sumsOf(t *testing.T, golden string) string {
	t.Helper()
	data, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	type line struct{ path, sum string }
	var lines []line
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.SplitN(l, " ", 4); len(f) == 4 && (f[0] == "f" || f[0] == "s") {
			lines = append(lines, line{f[3], f[1]})
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].path < lines[j].path })
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%s  %s\n", l.sum, l.path)
	}
	return b.String()
}
