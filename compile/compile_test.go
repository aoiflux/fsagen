package compile

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/render"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
)

func load(t *testing.T, mode Mode, body string, opts Options) (*Program, error) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "input.yaml")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(mode, file, opts)
	if p != nil {
		t.Cleanup(func() { p.Close() })
	}
	return p, err
}

func mustFail(t *testing.T, mode Mode, body string, want ...string) {
	t.Helper()
	_, err := load(t, mode, body, Options{})
	if err == nil {
		t.Fatalf("accepted; want an error mentioning %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error does not mention %q:\n%v", w, err)
		}
	}
}

func mustLoad(t *testing.T, mode Mode, body string) *Program {
	t.Helper()
	p, err := load(t, mode, body, Options{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

const pbHead = "start: 2026-03-11T09:00:00Z\nactors: [ { name: u, base: home } ]\nsteps:\n"

// Every struct in the input model rejects an unknown key, naming its line
// and column and listing the keys that are valid there.
func TestUnknownKeyPerStruct(t *testing.T) {
	for _, tc := range []struct {
		name, mode, body, where string
	}{
		{"Manifest", "m", "operations: []\nbogus: 1\n", "2:1"},
		{"Operation", "m", "operations:\n  - action: create\n    path: a\n    birthtime: 2020-01-01T00:00:00Z\n", "4:5"},
		{"PdfSpec", "m", "operations:\n  - action: create\n    path: a.pdf\n    format: pdf\n    pdf: { titel: x }\n", "5:12"},
		{"EmailSpec", "m", "operations:\n  - action: email\n    path: a.eml\n    email: { form: x }\n", "4:14"},
		{"Header", "m", "operations:\n  - action: email\n    path: a.eml\n    email: { headers: [ { nam: x } ] }\n", "4:27"},
		{"Attachment", "m", "operations:\n  - action: email\n    path: a.eml\n    email: { attachments: [ { src: x } ] }\n", "4:31"},
		{"VaultSpec", "m", "operations:\n  - action: ansible-vault\n    path: v.yml\n    vault: { pasword: x }\n", "4:14"},
		{"Playbook", "p", pbHead + "  - { actor: u, actions: [ { action: create, path: a } ] }\nextra: 1\n", "5:1"},
		{"Actor", "p", "start: now\nactors: [ { name: u, bse: x } ]\nsteps: []\n", "2:22"},
		{"Step", "p", pbHead + "  - { actor: u, repeats: 2, actions: [ { action: create, path: a } ] }\n", "4:17"},
		{"Action", "p", pbHead + "  - { actor: u, actions: [ { action: create, path: a, conten: x } ] }\n", "4:55"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := ModeManifest
			if tc.mode == "p" {
				mode = ModePlaybook
			}
			_, err := load(t, mode, tc.body, Options{})
			if err == nil {
				t.Fatal("unknown key accepted")
			}
			if !strings.Contains(err.Error(), "input.yaml:"+tc.where+":") || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "valid fields:") {
				t.Errorf("error lacks position %s, 'unknown field' or the valid-key list:\n%v", tc.where, err)
			}
		})
	}
}

func TestDuplicateKey(t *testing.T) {
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    path: b\n", "duplicate key \"path\"", ":4:5:")
}

func TestBadTimeIsError(t *testing.T) {
	for _, field := range []string{"atime: '2021-01-01 00:00:00'", "mtime: yesterday"} {
		mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n    "+field+"\n", "is not an RFC 3339 time")
	}
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a.pdf\n    format: pdf\n    content: x\n    pdf: { created: 2026-13-01 }\n", "created", "RFC 3339")
	mustFail(t, ModeManifest, "operations:\n  - action: email\n    path: a.eml\n    email: { date: 'Mon, 2 Mar 2026' }\n", "date", "RFC 3339")
	mustFail(t, ModePlaybook, "start: 2026-03-11 09:00\nactors: [ { name: u } ]\nsteps: [ { actor: u, actions: [ { action: create, path: a, content: x } ] } ]\n", "start", "RFC 3339")
	// Fractional seconds are valid RFC 3339.
	mustLoad(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n    mtime: 2021-01-01T00:00:00.123456789Z\n")
}

func TestStartRequired(t *testing.T) {
	mustFail(t, ModePlaybook, "actors: [ { name: u } ]\nsteps: [ { actor: u, actions: [ { action: create, path: a, content: x } ] } ]\n", "start: is required")
	p := mustLoad(t, ModePlaybook, "start: now\nactors: [ { name: u } ]\nsteps: [ { actor: u, actions: [ { action: create, path: a, content: x } ] } ]\n")
	if !p.StartNow {
		t.Error("start: now should be recorded as not reproducible")
	}
}

func TestDurations(t *testing.T) {
	// The action offset was once silently ignored; it has been validated since
	// 7accc8d and must stay that way.
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: a, content: x, offset: '5 minutes' } ] }\n", "offset", "unknown unit")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 2, every: -5m, actions: [ { action: create, path: 'a${ITER}', content: x } ] }\n", "every", "negative")
	if d, err := parseDuration("0d"); err != nil || d != 0 {
		t.Errorf("0d = %v, %v", d, err)
	}
	if d, err := parseDuration("2d6h"); err != nil || d.Hours() != 54 {
		t.Errorf("2d6h = %v, %v", d, err)
	}
}

func TestUnknownCondition(t *testing.T) {
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 3, every: 1m, condition: frist, actions: [ { action: create, path: 'c${ITER}', content: c } ] }\n", `unknown condition "frist"`, "iteration index")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, batch_count: 2, actions: [ { action: create, path: 'c${BATCH}', content: c, condition: Odd } ] }\n", `unknown condition "Odd"`, "batch index")
}

// Each condition selects exactly the documented indices: step conditions
// test the iteration, action conditions the batch.
func TestConditionIndices(t *testing.T) {
	for cond, want := range map[string][]string{
		"odd": {"1", "3"}, "even": {"0", "2", "4"}, "first": {"0"}, "last": {"4"},
	} {
		p := mustLoad(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 5, every: 1m, condition: "+cond+", actions: [ { action: create, path: 'i${ITER}', content: c } ] }\n")
		p2 := mustLoad(t, ModePlaybook, pbHead+"  - { actor: u, batch_count: 5, actions: [ { action: create, path: 'b${BATCH}', content: c, condition: "+cond+" } ] }\n")
		for _, prog := range []*Program{p, p2} {
			var got []string
			for _, op := range prog.Ops {
				got = append(got, op.Path[len(op.Path)-1:])
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got %v, want %v", cond, got, want)
			}
		}
	}
}

func TestTemplateRules(t *testing.T) {
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: both.eml, template: email, content: 'From: attacker@evil.test' } ] }\n", "template", "cannot be combined with content")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: t.txt, template: emial } ] }\n", `unknown template "emial"`)
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: delete, path: t.txt, template: log } ] }\n", "template", "does not apply to delete")
}

func TestTokens(t *testing.T) {
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: 'undefined_${VAR:nope}.txt', content: v } ] }\n", `undefined variable "nope"`)
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: '${RAND:8}'\n", "unknown token ${RAND:8}")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: '${ACTOR}.txt'\n    content: x\n", "only defined in playbooks")
	p := mustLoad(t, ModeManifest, "operations:\n  - action: create\n    path: run.sh\n    content: 'echo $${HOME}'\n")
	if p.Ops[0].Content != "echo ${HOME}" {
		t.Errorf("escape: %q", p.Ops[0].Content)
	}
}

func TestDeleteMissing(t *testing.T) {
	mustFail(t, ModeManifest, "operations:\n  - action: delete\n    path: does_not_exist.txt\n", "does_not_exist.txt does not exist", "missing_ok")
	p := mustLoad(t, ModeManifest, "operations:\n  - action: delete\n    path: does_not_exist.txt\n    missing_ok: true\n")
	if p.Ops[0].NoOp == "" {
		t.Error("a missing_ok delete of a missing path should be a recorded no-op")
	}
}

// 24 files created under one id in one step are all deleted by a later
// "refs:" step, even though ${SEQ} and ${RND} have moved on.
func TestRefsDeleteAllStaging(t *testing.T) {
	p := mustLoad(t, ModePlaybook, pbHead+
		"  - { actor: u, batch_count: 24, actions: [ { action: create, path: 'stg_${SEQ}_${RND:6}.tmp', id: staging, content: x } ] }\n"+
		"  - { actor: u, offset: 1h, actions: [ { action: delete, refs: staging } ] }\n")
	var created, deleted []string
	for _, op := range p.Ops {
		switch op.Action {
		case "create":
			created = append(created, op.Path)
		case "delete":
			deleted = append(deleted, op.Path)
		}
	}
	if len(created) != 24 || !reflect.DeepEqual(created, deleted) {
		t.Fatalf("created %d, deleted %d (%v)", len(created), len(deleted), deleted)
	}
	if len(p.Model.Paths()) != 1 { // only the actor base directory remains
		t.Errorf("model still holds %v", p.Model.Paths())
	}
}

func TestRefErrors(t *testing.T) {
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: a, id: x, content: a }, { action: create, path: b, id: x, content: b } ] }\n", `id "x" is already declared`)
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: delete, ref: nope } ] }\n", `unknown id "nope"`)
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: a, id: x, content: a }, { action: delete, ref: x }, { action: mace, ref: x, mtime: 2020-01-01T00:00:00Z } ] }\n", "already been deleted")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, batch_count: 2, actions: [ { action: create, path: 'a${BATCH}', id: x, content: a } ] }\n  - { actor: u, actions: [ { action: delete, ref: x } ] }\n", "names 2 paths", "refs:")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: delete, path: a, ref: x } ] }\n", "exactly one of path, ref and refs")
}

func TestIDFollowsRename(t *testing.T) {
	p := mustLoad(t, ModePlaybook, pbHead+"  - { actor: u, actions: [ { action: create, path: a.txt, id: doc, content: a }, { action: rename, ref: doc, new_path: b.txt }, { action: delete, ref: doc } ] }\n")
	if got := p.Ops[2].Path; got != "home/b.txt" {
		t.Errorf("delete after rename targets %q, want home/b.txt", got)
	}
}

func TestPreconditions(t *testing.T) {
	mustFail(t, ModeManifest, "operations:\n  - action: update\n    path: never_created.txt\n    content: x\n", "does not exist; use create")
	mustFail(t, ModeManifest, "operations:\n  - action: truncate\n    path: log.txt\n", "does not exist; use create")
	mustFail(t, ModeManifest, "operations:\n  - action: motw\n    path: a/zone9.exe\n    zone_id: 3\n", "base a/zone9.exe does not exist")
	mustFail(t, ModeManifest, "operations:\n  - action: ads\n    path: x.bin\n    stream: quill\n    content: h\n", "base x.bin does not exist")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: a\n  - action: create\n    path: b\n    content: b\n  - action: rename\n    path: a\n    new_path: b\n", "b already exists")
	mustFail(t, ModeManifest, "operations:\n  - action: copy\n    path: nope\n    new_path: b\n", "nope does not exist")
	mustFail(t, ModeManifest, "operations:\n  - action: mace\n    path: nope\n    mtime: 2020-01-01T00:00:00Z\n", "nope does not exist")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: d/f\n    content: x\n  - action: delete\n    path: d\n", "not empty")
	// append creates a missing log: that is how logs come into being.
	mustLoad(t, ModeManifest, "operations:\n  - action: append\n    path: var/log/app.log\n    content: line\n")
}

func TestValueRules(t *testing.T) {
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: z.exe\n    content: MZ\n  - action: motw\n    path: z.exe\n    zone_id: 9\n", "zone_id", "out of range")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n    mode: '0999'\n", "mode", "invalid mode")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    type: dir\n    path: d\n    mode: rwx\n", "mode")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content_len: 0\n", "content_len", "at least 1")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n    content_len: 5\n", "content_len", "no effect")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: z.exe\n    content: MZ\n  - action: motw\n    path: z.exe\n    host_url: \"http://x\\r\\nZoneId=0\"\n", "host_url", "line breaks")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a.pdf\n    content: x\n    format: xlsx\n", "unknown format \"xlsx\"")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    type: folder\n", "unknown type")
	mustFail(t, ModeManifest, "operations:\n  - action: Create\n    path: a\n", `unknown action "Create"`)
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    stream: s\n    content: x\n", "stream", "does not apply to create")
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n  - action: rename\n    path: a\n    new_path: b\n    mtime: 2020-01-01T00:00:00Z\n", "mtime", "does not apply to rename")
	mustFail(t, ModeManifest, "operations:\n  - action: mace\n    path: a\n", "at least one of atime, mtime, ctime and crtime")
	mustFail(t, ModeManifest, "operations:\n  - action: ansible-vault\n    path: v.yml\n    content: x\n    vault: { password: p, salt: abc }\n", "salt")
}

func TestPathRules(t *testing.T) {
	for _, bad := range []string{"../ESCAPED.txt", "a/../../x", "/x", "C:/x", "C:x", `a\b`, "notes."} {
		mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: '"+bad+"'\n    content: x\n", "path:")
	}
	mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: a\n    content: x\n  - action: rename\n    path: a\n    new_path: ../out\n", "new_path", "escapes")
	// A trailing '/' is a directory on every platform.
	p := mustLoad(t, ModeManifest, "operations:\n  - action: create\n    path: trailing_slash_dir/\n")
	if !p.Ops[0].Dir || p.Ops[0].Path != "trailing_slash_dir" {
		t.Errorf("trailing slash: dir=%v path=%q", p.Ops[0].Dir, p.Ops[0].Path)
	}
}

func TestRepeatWithoutEvery(t *testing.T) {
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 3, actions: [ { action: create, path: 'c${ITER}', content: c } ] }\n", "without every")
	mustLoad(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 3, every: 0s, actions: [ { action: create, path: 'c${ITER}', content: c } ] }\n")
	mustFail(t, ModePlaybook, pbHead+"  - { actor: u, repeat: 0, actions: [ { action: create, path: c, content: c } ] }\n", "repeat", "at least 1")
}

func TestPortability(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"  - action: create\n    path: CON\n    content: x\n", "reserved device name"},
		{"  - action: create\n    path: logs/con.txt\n    content: x\n", "reserved device name"},
		{"  - action: create\n    path: LPT1.log\n    content: x\n", "reserved device name"},
		{"  - action: create\n    path: Docs/a\n    content: x\n  - action: create\n    path: docs/b\n    content: x\n", "collides"},
		{"  - action: create\n    path: \"caf\\u00e9\"\n    content: x\n  - action: create\n    path: \"cafe\\u0301\"\n    content: x\n", "collides"},
		{"  - action: create\n    path: " + strings.Repeat("d/", 101) + "f\n    content: x\n", "portable budget"},
	} {
		body := "operations:\n" + tc.body
		mustFail(t, ModeManifest, body, tc.want, "--allow-nonportable")
		if _, err := load(t, ModeManifest, body, Options{AllowNonportable: true}); err != nil {
			t.Errorf("--allow-nonportable should lift %q: %v", tc.want, err)
		}
	}
	// Trailing dots and spaces are silently stripped by Windows; no flag lifts that.
	if _, err := load(t, ModeManifest, "operations:\n  - action: create\n    path: 'notes. '\n    content: x\n", Options{AllowNonportable: true}); err == nil {
		t.Error("trailing dot/space accepted with --allow-nonportable")
	}
}

// TestTypedExtensionInfersOrRefuses: an extension that promises a structured
// file gets one built, and one fsagen still cannot build is refused rather
// than filled with base32 text.
func TestTypedExtensionInfersOrRefuses(t *testing.T) {
	for _, tc := range []struct{ path, format string }{
		{"a/dropper.exe", "pe"}, {"lib/helper.dll", "pe"},
		{"a/exfil.zip", "zip"}, {"app.jar", "zip"},
		{"img.PNG", "png"}, {"img.JPG", "jpeg"}, {"scan.jpeg", "jpeg"},
		{"notes.docx", "docx"}, {"clip.mp4", "mp4"},
	} {
		p := mustLoad(t, ModeManifest, "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: "+tc.path+"\n    content_len: 4096\n")
		if got := p.Ops[0].Format; got != tc.format {
			t.Errorf("%s: format %q, want %q", tc.path, got, tc.format)
		}
	}
	for _, tc := range []struct{ path, want string }{
		{"History.sqlite", "chrome_history"},
		{"places.db", "firefox_places"},
		{"a.pdf", "format: pdf"},
		{"book.xlsx", "spreadsheet"},
		{"deck.pptx", "presentation"},
		{"anim.gif", "GIF"},
		{"msg.eml", "action: email"},
	} {
		mustFail(t, ModeManifest, "operations:\n  - action: create\n    path: "+tc.path+"\n    content_len: 4096\n", tc.want, "format: text")
	}
	// Literal content is the author's own bytes, whatever the name says.
	p := mustLoad(t, ModeManifest, "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: a/dropper.exe\n    format: text\n    content_len: 16\n  - action: create\n    path: lure.exe\n    content: MZ\n  - action: create\n    path: r.pdf\n    format: pdf\n    content_len: 64\n")
	if len(p.Ops) != 3 {
		t.Fatal(len(p.Ops))
	}
	for i, want := range []string{"text", "", "pdf"} {
		if got := p.Ops[i].Format; got != want {
			t.Errorf("op %d format %q, want %q", i+1, got, want)
		}
	}
	// Adding filler to a structured file would corrupt it.
	mustFail(t, ModeManifest, "operations:\n  - action: append\n    path: a.exe\n    content_len: 8\n", "would corrupt")
}

func TestPlaybookMissingOperations(t *testing.T) {
	mustFail(t, ModePlaybook, "start: now\nactors: [ { name: u } ]\nsteps: [ { actor: nobody, actions: [ { action: create, path: a, content: x } ] } ]\n", `unknown actor "nobody"`)
	mustFail(t, ModePlaybook, "start: now\nactors: [ { name: u }, { name: U } ]\nsteps: [ { actor: u, actions: [ { action: create, path: a, content: x } ] } ]\n", "defined twice")
	mustFail(t, ModeManifest, "operations: []\n", "no operations")
}

func TestContentFileConfined(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "yaml")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(parent, "outside_secret.txt"), []byte("TOP-SECRET-OUTSIDE"), 0o644)
	file := filepath.Join(dir, "m.yaml")
	os.WriteFile(file, []byte("operations:\n  - action: create\n    path: loot.txt\n    content_file: ../outside_secret.txt\n"), 0o644)

	if _, err := Load(ModeManifest, file, Options{}); err == nil || !strings.Contains(err.Error(), "--allow-external-sources") {
		t.Fatalf("err = %v, want a confinement error", err)
	}
	p, err := Load(ModeManifest, file, Options{AllowExternalSources: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Ops[0].Content != "TOP-SECRET-OUTSIDE" {
		t.Errorf("content = %q", p.Ops[0].Content)
	}
	if in := p.Sources.Inputs(); len(in) != 1 || in[0].Path != "../outside_secret.txt" {
		t.Errorf("the external read should be recorded: %+v", in)
	}
}

func TestSourceRootMustExistInOutput(t *testing.T) {
	mustFail(t, ModeManifest, "start: 2026-01-01T00:00:00Z\noperations:\n  - action: email\n    path: m.eml\n    email: { from: a@x, attachments: [ { source_root: ../../outside_secret.txt } ] }\n", "source_root", "escapes")
	mustFail(t, ModeManifest, "start: 2026-01-01T00:00:00Z\noperations:\n  - action: email\n    path: m.eml\n    email: { from: a@x, attachments: [ { source_root: report.pdf } ] }\n", "does not exist in the output at this point")
}

// F-IN-14: every string field is templated, in manifests and playbooks alike,
// because both go through Prepare. The walk covers nested specs; only the
// content body (templated separately) and literal ids are skipped.
func TestEveryStringFieldRenders(t *testing.T) {
	var op spec.Operation
	op.Pdf, op.Email, op.Vault = &spec.PdfSpec{}, &spec.EmailSpec{Headers: []spec.Header{{}}, Attachments: []spec.Attachment{{}}}, &spec.VaultSpec{}
	op.Email.To, op.Email.Cc, op.Email.Bcc, op.Email.References = []string{""}, []string{""}, []string{""}, []string{""}

	var fill func(v reflect.Value, name string)
	var fields []string
	fill = func(v reflect.Value, name string) {
		switch v.Kind() {
		case reflect.Pointer:
			fill(v.Elem(), name)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				f := v.Type().Field(i)
				// Ids and refs name things literally and are tagged so.
				if f.Tag.Get("render") == "-" || (name == "" && f.Name == "Content") {
					continue
				}
				if f.Name == "Content" && name != "" && !strings.HasSuffix(name, "Attachments") {
					continue
				}
				fill(v.Field(i), name+"."+f.Name)
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				fill(v.Index(i), name)
			}
		case reflect.String:
			v.SetString("${VAR:v}")
			fields = append(fields, name)
		}
	}
	fill(reflect.ValueOf(&op).Elem(), "")
	op.Render = new(false) // so attachment content is left alone below

	// content_file is rendered too, then read: give it a source to find.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "X"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := sandbox.OpenSources(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	got, err := Prepare(op, src, render.Context{Variables: map[string]string{"v": "X"}})
	if err != nil {
		t.Fatal(err)
	}
	var check func(v reflect.Value, name string)
	check = func(v reflect.Value, name string) {
		switch v.Kind() {
		case reflect.Pointer:
			check(v.Elem(), name)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				f := v.Type().Field(i)
				// ContentFile is consumed by Prepare; that the rendered name
				// "X" was found and read proves it was templated.
				if f.Name == "Content" || f.Name == "ContentFile" || f.Tag.Get("render") == "-" {
					continue
				}
				check(v.Field(i), name+"."+f.Name)
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				check(v.Index(i), name)
			}
		case reflect.String:
			if v.String() != "X" {
				t.Errorf("%s was not rendered: %q", name, v.String())
			}
		}
	}
	check(reflect.ValueOf(&got).Elem(), "")
	if len(fields) < 30 {
		t.Errorf("only %d string fields were exercised; the walk is not reaching nested specs", len(fields))
	}
}

func TestPrepareOperationRendersNestedSpecs(t *testing.T) {
	op := spec.Operation{
		Action: "email",
		Path:   "mail/${VAR:box}/msg.eml",
		Email: &spec.EmailSpec{
			From:    "a@${VAR:domain}",
			To:      []string{"b@${VAR:domain}"},
			Subject: "Hello ${VAR:who}",
			Headers: []spec.Header{{Name: "X-Origin", Value: "${VAR:domain}"}},
			Attachments: []spec.Attachment{
				{SourceFile: "content/${VAR:who}.pdf", Name: "${VAR:who}.pdf"},
			},
		},
	}
	got, err := Prepare(op, nil, render.Context{
		Variables: map[string]string{"box": "Inbox", "domain": "acme.example", "who": "priyan"},
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if got.Path != "mail/Inbox/msg.eml" || got.Email.From != "a@acme.example" || got.Email.To[0] != "b@acme.example" ||
		got.Email.Subject != "Hello priyan" || got.Email.Headers[0].Value != "acme.example" ||
		got.Email.Attachments[0].SourceFile != "content/priyan.pdf" {
		t.Errorf("not fully templated: %+v %+v", got, got.Email)
	}
}

// An error names the file, line and column, the step and action, and the field.
func TestErrorShape(t *testing.T) {
	_, err := load(t, ModePlaybook, pbHead+"  - actor: u\n    actions:\n      - action: create\n        path: x\n        content: y\n        condition: frist\n", Options{})
	if err == nil {
		t.Fatal("accepted")
	}
	if !regexp.MustCompile(`input\.yaml:9:9: step 1 action 1 \[create\]: condition: unknown condition "frist"`).MatchString(err.Error()) {
		t.Errorf("unexpected shape: %v", err)
	}
}

// An explicit content, even an empty one, is written exactly; random text is
// drawn only when the operation gives no content of its own. (Generator
// version 1 wrote 1024 random characters for content: ”.)
func TestEmptyContentIsEmpty(t *testing.T) {
	p := mustLoad(t, ModeManifest, "variables: { x: '' }\noperations:\n  - action: create\n    path: empty.log\n    content: ''\n  - action: append\n    path: a.log\n    content: \"${VAR:x}\"\n  - action: create\n    path: r.txt\n  - action: append\n    path: r.txt\n  - action: create\n    path: n.txt\n    content_len: 9\n")
	for i, want := range []int{0, 0, 1024, 256, 9} {
		if got := p.Ops[i].Random; got != want {
			t.Errorf("op %d: Random = %d, want %d", i+1, got, want)
		}
	}
	if p.Ops[0].Content != "" {
		t.Errorf("content = %q", p.Ops[0].Content)
	}
}
