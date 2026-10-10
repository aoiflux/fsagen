package compile

import (
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestPrefetchBlockRules: a .pf with a prefetch block is a prefetch file
// without saying so; a prefetch file needs its block and takes no filler; a
// file named the way Windows names one must be that program's; and every
// value the block gives is checked against what the format can hold.
func TestPrefetchBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+"    path: Windows/Prefetch/CMD.EXE-D269B812.pf\n    prefetch: { executable: 'C:\\Windows\\System32\\cmd.exe', harddisk_volume: 8 }\n")
	if got := p.Ops[0].Format; got != spec.FormatPrefetch {
		t.Errorf("format %q, want prefetch inferred from .pf", got)
	}
	mustLoad(t, ModeManifest, head+"    path: evidence/cmd-copy.pf\n    prefetch: { executable: 'C:\\Windows\\System32\\cmd.exe' }\n")

	const exe = "executable: 'C:\\Tools\\a.exe'"
	for _, tc := range []struct{ name, body, want string }{
		{"no block", "    path: a.pf\n", "needs a prefetch block"},
		{"filler", "    path: a.pf\n    content_len: 16\n    prefetch: { " + exe + " }\n", "no region for filler"},
		{"wrong format", "    path: a.txt\n    format: text\n    prefetch: { " + exe + " }\n", "only applies with format: prefetch"},
		{"no executable", "    path: a.pf\n    prefetch: { run_count: 3 }\n", "executable is required"},
		{"relative executable", "    path: a.pf\n    prefetch: { executable: 'tools\\a.exe' }\n", "not an absolute Windows path"},
		{"drive root", "    path: a.pf\n    prefetch: { executable: 'C:\\' }\n", "drive's root"},
		{"version", "    path: a.pf\n    prefetch: { " + exe + ", version: win7 }\n", "version"},
		{"nine runs", "    path: a.pf\n    prefetch: { " + exe + ", last_run_times: [2024-01-01T00:00:00Z, 2024-01-02T00:00:00Z, 2024-01-03T00:00:00Z, 2024-01-04T00:00:00Z, 2024-01-05T00:00:00Z, 2024-01-06T00:00:00Z, 2024-01-07T00:00:00Z, 2024-01-08T00:00:00Z, 2024-01-09T00:00:00Z] }\n", "keeps the last 8"},
		{"run twice", "    path: a.pf\n    prefetch: { " + exe + ", last_run_times: [2024-01-01T00:00:00Z, 2024-01-01T00:00:00Z] }\n", "appears twice"},
		{"bad run time", "    path: a.pf\n    prefetch: { " + exe + ", last_run_times: [yesterday] }\n", "last_run_times[0]"},
		{"before 1601", "    path: a.pf\n    prefetch: { " + exe + ", last_run_times: ['1500-01-01T00:00:00Z'] }\n", "outside what a FILETIME holds"},
		{"count below runs", "    path: a.pf\n    prefetch: { " + exe + ", run_count: 1, last_run_times: [2024-01-01T00:00:00Z, 2024-01-02T00:00:00Z] }\n", "less than the 2"},
		{"negative count", "    path: a.pf\n    prefetch: { " + exe + ", run_count: -1 }\n", "run_count"},
		{"negative volume number", "    path: a.pf\n    prefetch: { " + exe + ", harddisk_volume: -1 }\n", "negative"},
		{"bad referenced file", "    path: a.pf\n    prefetch: { " + exe + ", referenced_files: ['lib.dll'] }\n", "referenced_files[0]"},
		{"volume not used", "    path: a.pf\n    prefetch: { " + exe + ", volumes: [{ drive: D }] }\n", "no listed file is on D:"},
		{"volume letter", "    path: a.pf\n    prefetch: { " + exe + ", volumes: [{ drive: CD }] }\n", "not a drive letter"},
		{"volume twice", "    path: a.pf\n    prefetch: { " + exe + ", volumes: [{ drive: C }, { drive: 'c:' }] }\n", "appears twice"},
		{"volume serial", "    path: a.pf\n    prefetch: { " + exe + ", volumes: [{ drive: C, serial: 12345 }] }\n", "volume serial"},
		{"volume time", "    path: a.pf\n    prefetch: { " + exe + ", volumes: [{ drive: C, created: soon }] }\n", "volumes[0].created"},
		{"another program's name", "    path: CMD.EXE-D269B812.pf\n    prefetch: { executable: 'C:\\Windows\\System32\\cmd.exe' }\n", "named like the prefetch file of another program"},
		{"right name, other volume", "    path: CMD.EXE-D269B812.pf\n    prefetch: { executable: 'C:\\Windows\\System32\\cmd.exe', harddisk_volume: 3 }\n", "HarddiskVolume3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
