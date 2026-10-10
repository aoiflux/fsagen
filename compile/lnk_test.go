package compile

import (
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestLNKBlockRules: a .lnk with an lnk block is a link without saying so; a
// link needs its block and takes no filler; and every value the block gives
// is checked against what a link can hold before anything is written.
func TestLNKBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+"    path: Desktop/tool.lnk\n    lnk: { target: 'C:\\Tools\\tool.exe' }\n")
	if got := p.Ops[0].Format; got != spec.FormatLNK {
		t.Errorf("format %q, want lnk inferred from .lnk", got)
	}

	for _, tc := range []struct{ name, body, want string }{
		{"no block", "    path: a.lnk\n", "needs an lnk block"},
		{"filler", "    path: a.lnk\n    content_len: 16\n    lnk: { target: 'C:\\a' }\n", "no region for filler"},
		{"wrong format", "    path: a.txt\n    format: text\n    lnk: { target: 'C:\\a' }\n", "only applies with format: lnk"},
		{"no target", "    path: a.lnk\n    lnk: { arguments: x }\n", "target is required"},
		{"relative target", "    path: a.lnk\n    lnk: { target: 'tools\\a.exe' }\n", "not an absolute Windows path"},
		{"target type", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_type: link }\n", "target_type"},
		{"show", "    path: a.lnk\n    lnk: { target: 'C:\\a', show_command: hidden }\n", "show_command"},
		{"drive", "    path: a.lnk\n    lnk: { target: 'C:\\a', drive_type: network }\n", "drive_type"},
		{"serial", "    path: a.lnk\n    lnk: { target: 'C:\\a', volume_serial: 12345 }\n", "volume serial"},
		{"machine", "    path: a.lnk\n    lnk: { target: 'C:\\a', machine_id: A-MACHINE-NAME-TOO-LONG }\n", "machine_id"},
		{"label", "    path: a.lnk\n    lnk: { target: 'C:\\a', volume_label: Étiquette }\n", "volume_label"},
		{"size", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_size: -1 }\n", "negative"},
		{"attribute", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_attributes: [compressed] }\n", "target_attributes"},
		{"attribute twice", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_attributes: [hidden, hidden] }\n", "appears twice"},
		{"bad time", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_mtime: yesterday }\n", "target_mtime"},
		{"before 1601", "    path: a.lnk\n    lnk: { target: 'C:\\a', target_crtime: '1500-01-01T00:00:00Z' }\n", "outside what a FILETIME holds"},
		{"icon index", "    path: a.lnk\n    lnk: { target: 'C:\\a', icon_index: 9999999999 }\n", "icon_index"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
