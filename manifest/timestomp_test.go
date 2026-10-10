package manifest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/sandbox"
)

// On a live volume a timestomp sets the $STANDARD_INFORMATION times it names,
// as mace does. Its $FILE_NAME times stop the run before anything is written,
// or with skip are dropped, and the ledger and answer key give them as what
// the scenario means rather than what is on disk.
func TestTimestompOnLiveVolume(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	p := writeFile(t, dir, "pb.yaml", pb+`  - { actor: u, offset: 1m, actions: [ { action: create, path: a.txt, content: x } ] }
  - { actor: u, offset: 2m, actions: [ { action: timestomp, path: a.txt, mtime: "2019-01-01T00:00:00Z", fn_mtime: "2018-01-01T00:00:00Z" } ] }
`)
	_, err := ExecuteFile(compile.ModePlaybook, root, p, compile.Options{Seed: 1})
	if err == nil || !strings.Contains(err.Error(), "$FILE_NAME modification time cannot be set on a live volume") {
		t.Fatalf("without skip: %v", err)
	}
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Errorf("a refused run wrote %d entries", len(left))
	}

	res, err := ExecuteFile(compile.ModePlaybook, root, p, compile.Options{Seed: 1, SkipUnsupported: true})
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	y2019 := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	expect(t, fsys, "a.txt", sandbox.Times{Atime: at(1), Mtime: y2019, Btime: at(1)})

	e := res.Ledger[1]
	wantFN := ledger.Times{Atime: "2021-03-01T09:01:00Z", Mtime: "2018-01-01T00:00:00Z", Ctime: "2021-03-01T09:01:00Z", Crtime: "2021-03-01T09:01:00Z"}
	if e.FnTimes == nil || *e.FnTimes != wantFN {
		t.Errorf("ledger $FILE_NAME times = %+v, want %+v", e.FnTimes, wantFN)
	}
	if !slices.Equal(e.Explicit, []string{"mtime"}) {
		t.Errorf("explicit = %v; a dropped fn_mtime was not applied", e.Explicit)
	}
	for _, f := range compile.FileNameTimeFields {
		if !slices.Contains(e.Uncontrolled, f) {
			t.Errorf("uncontrolled %v lacks %s", e.Uncontrolled, f)
		}
	}
	if res.Ledger[0].FnTimes != nil {
		t.Error("a create's ledger entry carries $FILE_NAME times")
	}

	var stomp *ledger.Fact
	for _, f := range res.AnswerKey() {
		if f.Event == ledger.Stomped {
			stomp = &f
		}
	}
	switch {
	case stomp == nil:
		t.Fatal("no stomped fact")
	case stomp.FnControlled == nil || *stomp.FnControlled:
		t.Errorf("fn_controlled = %v on a live volume", stomp.FnControlled)
	case stomp.Delta == nil || stomp.Delta.Mtime != "31536000" || stomp.Delta.Crtime != "0":
		t.Errorf("delta = %+v", stomp.Delta)
	case stomp.TimestompDetected == nil || *stomp.TimestompDetected:
		t.Errorf("detected = %v with equal creation times", stomp.TimestompDetected)
	}
}
