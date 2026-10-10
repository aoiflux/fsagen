//go:build windows

package conformance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	ntfs "www.velocidex.com/golang/go-ntfs/parser"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/sandbox"
)

// TestSlackSurvivesOnRawNTFS: what fsagen leaves in a file's slack on a live
// NTFS volume is still there when the volume is read raw, the way a carver
// reads it. The file is found through its MFT record with Velocidex's
// go-ntfs, the cluster its content ends in is located from the record's data
// runs, and the bytes past the end of the content are read off the device.
//
// The canary repeats its marker at every sector boundary: Windows may zero
// the rest of the sector the file ends in when the file shrinks, and must
// leave the sectors after it alone. This test requires the markers from the
// first boundary on, and reports whether the sector the file ends in kept
// its share too.
//
// Reading a volume raw needs an administrator, so this skips otherwise.
func TestSlackSurvivesOnRawNTFS(t *testing.T) {
	root := t.TempDir()
	probe, err := sandbox.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ntfsVolume, cluster := probe.SlackBestEffort(), probe.ClusterSize()
	probe.Close()
	if !ntfsVolume || cluster == 0 {
		t.Skip("the temporary directory is not on NTFS")
	}
	letter := strings.ToUpper(root[:1])
	device := `\\.\` + letter + ":"
	raw, err := os.Open(device)
	if err != nil {
		t.Skipf("cannot open %s raw (an administrator can): %v", device, err)
	}
	defer raw.Close()

	const size = 5000
	baseDir := t.TempDir()
	body := fmt.Sprintf("start: 2024-03-15T09:00:00Z\noperations:\n  - action: create\n    path: slack.bin\n    content_len: %d\n    slack: { cluster_size: %d }\n", size, cluster)
	if err := os.WriteFile(filepath.Join(baseDir, "m.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := manifest.ExecuteFile(compile.ModeManifest, root, filepath.Join(baseDir, "m.yaml"), compile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	object := res.Ledger[0].Object
	flushVolume(t, device)

	paged, err := ntfs.NewPagedReader(raw, 1024, 10000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := ntfs.GetNTFSContext(paged, 0)
	if err != nil {
		t.Fatalf("go-ntfs cannot read %s: %v", device, err)
	}
	rel := strings.ReplaceAll(filepath.Join(root, "slack.bin")[3:], `\`, "/")
	stream, err := ntfs.GetDataForPath(ctx, rel)
	if err != nil {
		t.Fatalf("go-ntfs cannot find %s: %v", rel, err)
	}
	if got := ntfs.RangeSize(stream); got != size && got != int64(cluster*((size+cluster-1)/cluster)) {
		t.Logf("go-ntfs reports the data stream as %d bytes", got)
	}

	diskEnd := int64(-1)
	for _, run := range ntfs.DebugRuns(stream, 0) {
		if run.Level == 0 && !run.IsSparse && run.FromOffset <= size-1 && size-1 < run.FromOffset+run.Length {
			diskEnd = run.ToOffset + (size - run.FromOffset)
		}
	}
	if diskEnd < 0 {
		t.Fatalf("no data run covers the end of the content: %v", ntfs.DebugRuns(stream, 0))
	}
	slackLen := cluster - size%cluster
	got := make([]byte, slackLen)
	if _, err := paged.ReadAt(got, diskEnd); err != nil {
		t.Fatal(err)
	}

	marker := []byte(fmt.Sprintf("FSAGEN-SLACK:%d:", object))
	first := 512 - size%512 // the first sector boundary past the end of the content
	for i := first; i < slackLen; i += 512 {
		if !bytes.HasPrefix(got[i:], marker) {
			t.Errorf("no canary at the sector boundary %d bytes into the slack; the raw bytes there are %q", i, got[i:min(i+len(marker), slackLen)])
		}
	}
	if bytes.HasPrefix(got, marker) {
		t.Logf("the sector the file ends in kept its slack too (no RAM-slack zeroing here)")
	} else {
		t.Logf("the sector the file ends in was cleared past the end of the file, as Windows may do; the canary survives from the next sector")
	}
}

// flushVolume asks Windows to write everything cached for the volume, so a
// raw read sees what the file system now holds.
func flushVolume(t *testing.T, device string) {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(device)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Logf("could not open %s to flush it: %v", device, err)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.FlushFileBuffers(h); err != nil {
		t.Logf("could not flush %s: %v", device, err)
	}
}
