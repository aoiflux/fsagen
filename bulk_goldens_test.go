package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/internal/testutil"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/sandbox"
)

// bulkGoldenStart is the reference time the pinned corpora are built with. It
// is explicit rather than left to DefaultStart so the dates inside the files
// stay put if that default ever moves.
const bulkGoldenStart = "2026-03-04T08:00:00Z"

// bulkCorpora are the bulk shapes pinned by fingerprint. one-of-each is one
// file of every kind, which keeps the golden short enough to read; two-levels
// repeats a kind within a directory and nests, which is what exercises the
// deterministic name-retry in Plan.
var bulkCorpora = []struct {
	name         string
	seed         int64
	limit, depth int
}{
	{"one-of-each", 7, 1, 1},
	{"two-levels", 7, 2, 2},
}

// TestBulkGoldens pins the names and bytes of a bulk corpus.
//
// Nothing recorded covered bulk mode before this: every shipped example is a
// manifest or a playbook, so a change to any of the generators behind --bulk
// could alter the largest output fsagen writes while the whole suite stayed
// green. Generator version 6 was exactly that — it rebuilt the bulk eml, mbox
// and pdf and moved not one golden file.
//
// It is platform-independent, and so lives beside the dry-run goldens rather
// than under an OS directory: a fingerprint records names, sizes and digests
// but never times, and a bulk file's bytes come from the seed and the start
// time alone.
func TestBulkGoldens(t *testing.T) {
	start, err := time.Parse(time.RFC3339, bulkGoldenStart)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range bulkCorpora {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			fsys, err := sandbox.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer fsys.Close()
			opts := libgen.Options{Seed: c.seed, Start: start}
			if err := libgen.Generate(fsys, c.limit, c.depth, opts); err != nil {
				t.Fatal(err)
			}
			got, err := testutil.Fingerprint(root)
			if err != nil {
				t.Fatal(err)
			}
			in := testutil.SpecHash(fmt.Sprintf("seed=%d limit=%d depth=%d start=%s",
				c.seed, c.limit, c.depth, bulkGoldenStart))
			golden := filepath.Join("testdata", "golden",
				fmt.Sprintf("v%d", constant.GeneratorVersion), "bulk", c.name+".txt")
			testutil.CheckGolden(t, golden, in, got, *update)
		})
	}
}
