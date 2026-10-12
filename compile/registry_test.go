package compile

import (
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestRegistryBlockRules: a hive is known by its name (NTUSER.DAT, SYSTEM)
// or a .hve extension, but not by .dat alone; it needs its block and takes
// no filler; each artefact must be in the hive Windows keeps it in; and
// every key and value is checked as the hive will be built.
func TestRegistryBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+
		"    path: Users/user1/NTUSER.DAT\n    registry: { run: [ { name: Updater, command: 'C:\\x.exe' } ] }\n"+
		"  - action: create\n    path: config/SYSTEM\n    registry: { usbstor: [ { vendor: Generic, product: Storage, revision: '1.00', serial: ABC123 } ] }\n"+
		"  - action: create\n    path: lab/sample.hve\n    registry: { keys: [ { path: 'A\\B' } ] }\n"+
		"  - action: create\n    path: stage/0.dat\n    content_len: 16\n")
	for i, want := range []spec.Format{spec.FormatRegistry, spec.FormatRegistry, spec.FormatRegistry, ""} {
		if got := p.Ops[i].Format; got != want {
			t.Errorf("op %d (%s): format %q, want %q", i, p.Ops[i].Path, got, want)
		}
	}

	for _, tc := range []struct{ name, body, want string }{
		{"no block", "    path: NTUSER.DAT\n", "needs a registry block"},
		{"filler", "    path: a.hve\n    content_len: 16\n    registry: { keys: [ { path: A } ] }\n", "no region for filler"},
		{"wrong format", "    path: a.txt\n    format: text\n    registry: { keys: [ { path: A } ] }\n", "only applies with format: regf"},
		{"run in SYSTEM", "    path: SYSTEM\n    registry: { run: [ { name: x, command: y } ] }\n", "Run key belongs in NTUSER.DAT or SOFTWARE"},
		{"userassist in SOFTWARE", "    path: SOFTWARE\n    registry: { userassist: [ { path: 'C:\\a.exe' } ] }\n", "userassist belongs in NTUSER.DAT"},
		{"usbstor in NTUSER", "    path: NTUSER.DAT\n    registry: { usbstor: [ { vendor: V, product: P, revision: '1', serial: S } ] }\n", "usbstor belongs in SYSTEM"},
		{"run without command", "    path: NTUSER.DAT\n    registry: { run: [ { name: x } ] }\n", "needs a name and a command"},
		{"empty path part", "    path: a.hve\n    registry: { keys: [ { path: 'A\\\\B' } ] }\n", "empty component"},
		{"key twice", "    path: a.hve\n    registry: { keys: [ { path: 'A\\B' }, { path: 'a\\b', values: [ { name: x, data: y } ] }, { path: 'A\\B', values: [ { name: X, data: z } ] } ] }\n", `value "X" is given twice`},
		{"bad type", "    path: a.hve\n    registry: { keys: [ { path: A, values: [ { name: x, type: REG_LINK, data: y } ] } ] }\n", "REG_LINK"},
		{"bad dword", "    path: a.hve\n    registry: { keys: [ { path: A, values: [ { name: x, type: REG_DWORD, data: lots } ] } ] }\n", "32-bit"},
		{"bad binary", "    path: a.hve\n    registry: { keys: [ { path: A, values: [ { name: x, type: REG_BINARY, data: xyz } ] } ] }\n", "hex bytes"},
		{"multi as data", "    path: a.hve\n    registry: { keys: [ { path: A, values: [ { name: x, type: REG_MULTI_SZ, data: y } ] } ] }\n", "takes strings"},
		{"bad time", "    path: a.hve\n    registry: { keys: [ { path: A, last_written: later } ] }\n", "keys[0].last_written"},
		{"usb vendor", "    path: SYSTEM\n    registry: { usbstor: [ { vendor: AVendorTooLong, product: P, revision: '1', serial: S } ] }\n", "vendor"},
		{"userassist path", "    path: NTUSER.DAT\n    registry: { userassist: [ { path: tool.exe } ] }\n", "not an absolute Windows path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
