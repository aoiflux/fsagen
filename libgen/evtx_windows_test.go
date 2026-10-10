//go:build windows

package libgen

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEvtxReadByWindows: Windows' own event log reader, through
// Get-WinEvent -Path, opens a generated log and renders every record to
// exactly the XML the events describe, in the order they were written. It
// skips where PowerShell cannot be run.
func TestEvtxReadByWindows(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	data, err := BuildEvtx(sampleEvtxSpec())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "Security.evtx")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `$e = @(Get-WinEvent -Path $env:EVTX_PATH -Oldest -ErrorAction Stop | ForEach-Object { $_.ToXml() }); ConvertTo-Json -Compress -InputObject $e`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "EVTX_PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("Get-WinEvent: %v\n%s", err, stderr)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got) != len(sampleEvtxXML) {
		t.Fatalf("Windows read %d events, want %d", len(got), len(sampleEvtxXML))
	}
	for i := range got {
		if got[i] != sampleEvtxXML[i] {
			t.Errorf("event %d: Windows renders\n%s\nwant\n%s", i, got[i], sampleEvtxXML[i])
		}
	}
}

// TestEvtxChunksReadByWindows: Windows reads every record of a log that
// spans several chunks, each with its own names and templates, in order.
func TestEvtxChunksReadByWindows(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	proc, _ := EvtxBuiltins(4688)
	var events []EvtxEvent
	for i := range 600 {
		ev := proc.Event
		ev.Fields = append([]EvtxField(nil), proc.Event.Fields...)
		ev.Time = sampleEvtxSpec().Events[0].Time.Add(time.Duration(i) * time.Second)
		set(&ev, "CommandLine", fmt.Sprintf("powershell.exe -enc %s", strings.Repeat("QQBCAEMA", 1+i%40)))
		events = append(events, ev)
	}
	data, err := BuildEvtx(EvtxSpec{Channel: "Security", Computer: "WS01", FirstRecordID: 500, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.LittleEndian.Uint16(data[42:]); n < 3 {
		t.Fatalf("the log has %d chunks; the test needs several", n)
	}
	path := filepath.Join(t.TempDir(), "Security.evtx")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `$ids = @(Get-WinEvent -Path $env:EVTX_PATH -Oldest -ErrorAction Stop | ForEach-Object { $_.RecordId }); ConvertTo-Json -Compress -InputObject $ids`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "EVTX_PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Get-WinEvent: %v", err)
	}
	var ids []int
	if err := json.Unmarshal(out, &ids); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(ids) != len(events) {
		t.Fatalf("Windows read %d of %d events", len(ids), len(events))
	}
	for i, id := range ids {
		if id != 500+i {
			t.Fatalf("event %d has record id %d, want %d", i, id, 500+i)
		}
	}
}
