package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/libntfs"
)

// A wiped file on an NTFS image leaves what SDelete leaves in the change
// journal: a record under every name it was renamed through, since SDelete
// opens the file afresh for each rename, and its delete under the last.
func TestWipeJournalsEveryRename(t *testing.T) {
	dir := t.TempDir()
	scene := filepath.Join(dir, "wipe.yaml")
	const yaml = `start: 2026-03-11T10:00:00Z
operations:
  - action: create
    path: Tools/stage.exe
    content: payload
  - action: delete
    path: Tools/stage.exe
    wipe: { renames: 3 }
`
	if err := os.WriteFile(scene, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "wipe.img")
	if code, _, stderr := runCLI(t, "--seed", "1", "--manifest", scene, "--image", img, "--image-fs", "ntfs", "--image-size", "64M"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}

	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	start := int64(container.MBRStart) * 512
	vol, err := libntfs.OpenWithOptions(io.NewSectionReader(f, start, info.Size()-start), libntfs.Options{ReadOnly: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	var names []string
	if err := vol.EachUSNRecord(func(r *libntfs.USNRecord) error {
		if !slices.Contains(names, r.Name) {
			names = append(names, r.Name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"stage.exe", "AAAAA.AAA", "BBBBB.BBB", "CCCCC.CCC"} {
		if !slices.Contains(names, want) {
			t.Errorf("the journal has no record under %s; it names %q", want, names)
		}
	}
}
