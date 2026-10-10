package compile

import (
	"slices"
	"testing"
)

const mfHead = "start: 2026-03-11T09:00:00Z\noperations:\n"

// TestMitreValidation: a mitre list is a non-empty set of well-formed
// technique IDs, on a manifest operation, a playbook action or a step, and
// every action accepts one.
func TestMitreValidation(t *testing.T) {
	for _, tc := range []struct {
		name, mode, body, want string
	}{
		{"bad id", "m", mfHead + "  - { action: create, path: a, content: x, mitre: [T107] }\n", `"T107" is not an ATT&CK technique ID`},
		{"lower case", "m", mfHead + "  - { action: create, path: a, content: x, mitre: [t1070] }\n", `"t1070" is not`},
		{"bad sub-technique", "m", mfHead + "  - { action: create, path: a, content: x, mitre: [T1070.6] }\n", `"T1070.6" is not`},
		{"empty", "m", mfHead + "  - { action: create, path: a, content: x, mitre: [] }\n", "is empty"},
		{"duplicate", "m", mfHead + "  - { action: create, path: a, content: x, mitre: [T1070, T1070] }\n", "T1070 is listed twice"},
		{"action", "p", pbHead + "  - { actor: u, actions: [ { action: create, path: a, content: x, mitre: [X1] } ] }\n", `"X1" is not`},
		{"step", "p", pbHead + "  - { actor: u, mitre: [T1], actions: [ { action: create, path: a, content: x } ] }\n", `"T1" is not`},
		{"step empty", "p", pbHead + "  - { actor: u, mitre: [], actions: [ { action: create, path: a, content: x } ] }\n", "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := ModeManifest
			if tc.mode == "p" {
				mode = ModePlaybook
			}
			mustFail(t, mode, tc.body, "mitre", tc.want)
		})
	}

	// Every action takes the key, including ones with no other optional field.
	p := mustLoad(t, ModeManifest, mfHead+
		"  - { action: create, path: a, content: x, mitre: [T1070.006, T1564.004] }\n"+
		"  - { action: delete, path: a, mitre: [T1070.004] }\n")
	if got := p.Ops[1].Techniques(); !slices.Equal(got, []string{"T1070.004"}) {
		t.Errorf("delete techniques = %v", got)
	}
}

// TestMitreStepInheritance: an action exhibits its step's techniques as well
// as its own, sorted and listed once; an untagged action in an untagged step
// exhibits none.
func TestMitreStepInheritance(t *testing.T) {
	p := mustLoad(t, ModePlaybook, pbHead+
		"  - actor: u\n    mitre: [T1564.004, T1070]\n    actions:\n"+
		"      - { action: create, path: a, content: x, mitre: [T1070, T1036] }\n"+
		"      - { action: create, path: b, content: x }\n"+
		"  - actor: u\n    offset: 1m\n    actions:\n"+
		"      - { action: create, path: c, content: x }\n")
	want := map[string][]string{
		"home/a": {"T1036", "T1070", "T1564.004"},
		"home/b": {"T1070", "T1564.004"},
		"home/c": nil,
	}
	for _, op := range p.Ops {
		if got := op.Techniques(); !slices.Equal(got, want[op.Path]) {
			t.Errorf("%s: techniques = %v, want %v", op.Path, got, want[op.Path])
		}
	}
}

// TestMitreLeavesRandomKeyAlone: an action with no id takes its random key
// from a hash of its YAML, and the mitre key is left out of that hash, so
// tagging an action never changes the bytes it writes. Any other key still
// counts.
func TestMitreLeavesRandomKeyAlone(t *testing.T) {
	key := func(mode Mode, body string) string {
		t.Helper()
		p := mustLoad(t, mode, body)
		return p.Ops[0].Rand.Stream().Hex(16)
	}
	plain := key(ModeManifest, mfHead+"  - { action: create, path: a, content_len: 64 }\n")
	tagged := key(ModeManifest, mfHead+"  - { action: create, path: a, content_len: 64, mitre: [T1070] }\n")
	other := key(ModeManifest, mfHead+"  - { action: create, path: a, content_len: 65 }\n")
	if plain != tagged {
		t.Errorf("tagging a manifest operation changed its random key")
	}
	if plain == other {
		t.Errorf("changing content_len left the random key alone; the comparison proves nothing")
	}

	pPlain := key(ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: a, content_len: 64 } ] }\n")
	pTagged := key(ModePlaybook, pbHead+"  - { actor: u, mitre: [T1036], actions: [ { action: create, path: a, content_len: 64, mitre: [T1070] } ] }\n")
	if pPlain != pTagged {
		t.Errorf("tagging a playbook action or its step changed the action's random key")
	}
}
