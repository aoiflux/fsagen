package compile

import (
	"strings"
	"testing"
)

const slackHead = "start: 2026-01-01T00:00:00Z\noperations:\n"

// TestSlackRules: a slack block is checked on its own when the scenario is
// compiled, and against the file it belongs to when the scenario is
// simulated: the file must have content whose size is known before the run,
// and that content must stop short of a cluster's end.
func TestSlackRules(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"kind", "  - { action: create, path: a, content_len: 5000, slack: { kind: zeros } }\n", "kind \"zeros\""},
		{"cluster not a power of two", "  - { action: create, path: a, content_len: 5000, slack: { cluster_size: 3000 } }\n", "not a cluster size"},
		{"cluster too small", "  - { action: create, path: a, content_len: 5000, slack: { cluster_size: 256 } }\n", "not a cluster size"},
		{"fragment needs a source", "  - { action: create, path: a, content_len: 5000, slack: { kind: fragment } }\n", "needs fragment_of"},
		{"source needs fragment", "  - { action: create, path: a, content_len: 5000, slack: { fragment_of: x } }\n", "only applies with kind: fragment"},
		{"structured", "  - { action: create, path: a.exe, slack: {} }\n", "built during the run"},
		{"empty", "  - { action: create, path: a, content: '', slack: {} }\n", "empty file has no cluster"},
		{"whole clusters", "  - { action: create, path: a, content_len: 8192, slack: {} }\n", "leaving no slack"},
		{"unknown fragment", "  - { action: create, path: a, content_len: 5000, slack: { kind: fragment, fragment_of: nobody } }\n", `unknown id "nobody"`},
		{"deleted fragment", "  - { action: create, id: src, path: s, content: x }\n  - { action: delete, path: s }\n" +
			"  - { action: create, path: a, content_len: 5000, slack: { kind: fragment, fragment_of: src } }\n", "names 0 live files"},
		{"append", "  - { action: append, path: a, content: x, slack: {} }\n", "does not apply to append"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, slackHead+tc.body, tc.want)
		})
	}

	p := mustLoad(t, ModeManifest, slackHead+
		"  - { action: create, id: src, path: s, content: original }\n"+
		"  - { action: create, path: a, content_len: 5000, slack: { kind: fragment, fragment_of: src } }\n"+
		"  - { action: update, path: a, content: 'hello', slack: { cluster_size: 512 } }\n")
	if got := p.Ops[1].FragmentPath; got != "s" {
		t.Errorf("fragment resolved to %q, want s", got)
	}
	for i, want := range [][2]int{{5000, 4096*2 - 5000}, {5, 507}} {
		off, n := SlackRange(&p.Ops[1+i])
		if off != want[0] || n != want[1] {
			t.Errorf("op %d slack at %d+%d, want %d+%d", 2+i, off, n, want[0], want[1])
		}
	}
}

// TestSlackPreflight: whether slack can be kept is a capability. A target
// that cannot keep it refuses before anything is written, or, with skip,
// writes the file without its slack and says so; a live NTFS volume refuses
// a cluster size that is not its own and a file small enough to live in its
// MFT record.
func TestSlackPreflight(t *testing.T) {
	load := func(body string) *Program {
		t.Helper()
		return mustLoad(t, ModeManifest, slackHead+body)
	}
	big := "  - { action: create, path: a, content_len: 5000, slack: {} }\n"
	small := "  - { action: create, path: a, content_len: 1000, slack: {} }\n"
	ntfs := Caps{Slack: SlackBestEffort, ClusterSize: 4096, ResidentData: true}
	ntfsImage := Caps{Slack: SlackExact, ClusterSize: 4096, ResidentData: true}

	for _, tc := range []struct {
		name string
		body string
		caps Caps
		want string
	}{
		{"none", big, Caps{Slack: SlackNone}, "slack needs a target that keeps bytes"},
		{"unset", big, Caps{}, "slack needs a target that keeps bytes"},
		{"cluster mismatch", big, Caps{Slack: SlackBestEffort, ClusterSize: 65536}, "this volume's are 65536 bytes"},
		{"resident", small, ntfs, "inside its NTFS MFT record"},
		{"resident on an image", small, ntfsImage, "inside its NTFS MFT record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Preflight(load(tc.body), tc.caps, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--on-unsupported=skip") {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			p := load(tc.body)
			if err := Preflight(p, tc.caps, true); err != nil {
				t.Fatalf("with skip: %v", err)
			}
			if op := p.Ops[0]; op.Skip != "" || !strings.Contains(op.SlackDropped, tc.want) {
				t.Errorf("with skip: op skipped %q, slack dropped %q; want the file kept and the slack dropped", op.Skip, op.SlackDropped)
			}
		})
	}

	for name, caps := range map[string]Caps{
		"ntfs":            ntfs,
		"unknown cluster": {Slack: SlackBestEffort},
		"image":           {Slack: SlackExact, ClusterSize: 4096},
		"image small":     {Slack: SlackExact},
		"ntfs image":      ntfsImage,
	} {
		p := load(big)
		if name == "image small" {
			p = load(small)
		}
		if err := Preflight(p, caps, false); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
