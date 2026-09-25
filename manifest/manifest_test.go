package manifest

import (
	"bytes"
	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/util"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runManifest(t *testing.T, body string, vars map[string]string) (root, baseDir string) {
	t.Helper()
	baseDir = t.TempDir()
	root = t.TempDir()
	writeFile(t, baseDir, "manifest.yaml", body)
	if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{Vars: vars}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return root, baseDir
}

// content_file must land verbatim: shell scripts and PEM keys routinely contain
// ${...} sequences that are not our templates.
func TestContentFileIsNotTemplatedByDefault(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nline ${SEQ} ${VAR:org} ${RND:8}\n"
	writeFile(t, baseDir, "content/id_rsa", key)
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: home/.ssh/id_rsa
    content_file: content/id_rsa
`)

	if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{Vars: map[string]string{"org": "ACME"}}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "home", ".ssh", "id_rsa"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != key {
		t.Errorf("content_file was modified:\ngot  %q\nwant %q", got, key)
	}
}

func TestContentFileTemplatedWhenRenderTrue(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "content/report.md", "# Report for ${VAR:org}\n")
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: report.md
    content_file: content/report.md
    render: true
`)

	if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{Vars: map[string]string{"org": "ACME Corp"}}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "report.md"))
	if string(got) != "# Report for ACME Corp\n" {
		t.Errorf("got %q", got)
	}
}

func TestInlineContentIsTemplated(t *testing.T) {
	root, _ := runManifest(t, `
operations:
  - action: create
    path: out.txt
    content: "org=${VAR:org} seq=${SEQ}"
`, map[string]string{"org": "ACME"})

	got, _ := os.ReadFile(filepath.Join(root, "out.txt"))
	if string(got) != "org=ACME seq=1" {
		t.Errorf("got %q", got)
	}
}

func TestContentAndContentFileAreMutuallyExclusive(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "content/a.txt", "x")
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: out.txt
    content: "inline"
    content_file: content/a.txt
`)
	err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want a mutual-exclusion error", err)
	}
}

func TestUnknownKeyIsRejected(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: out.txt
    content_fil: typo
`)
	err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "content_fil") {
		t.Errorf("err = %v, want the typo to be reported", err)
	}
}

func TestManifestVariablesAreOverriddenByCLI(t *testing.T) {
	root, _ := runManifest(t, `
variables:
  org: "from manifest"
  keep: "manifest value"
operations:
  - action: create
    path: out.txt
    content: "${VAR:org}|${VAR:keep}"
`, map[string]string{"org": "from cli"})

	got, _ := os.ReadFile(filepath.Join(root, "out.txt"))
	if string(got) != "from cli|manifest value" {
		t.Errorf("got %q, want CLI to win and manifest values to survive", got)
	}
}

func TestFileModeIsApplied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows maps only the write bit; mode is meaningful on the Linux tree")
	}
	root, _ := runManifest(t, `
operations:
  - action: create
    path: id_rsa
    content: "key"
    mode: "0600"
`, nil)

	info, err := os.Stat(filepath.Join(root, "id_rsa"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

// An explicit mode on a directory create is for that directory; missing
// parents get the default. A rotate's mode is for the new empty file, set
// exactly (not narrowed by the umask).
func TestDirAndRotateModesAreApplied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows maps only the write bit; mode is meaningful on the Linux tree")
	}
	root, _ := runManifest(t, `
operations:
  - { action: create, path: a/b/, type: dir, mode: "0777" }
  - { action: append, path: logs/app.log, content: "x" }
  - { action: rotate, path: logs/app.log, new_path: logs/app.log.1, mode: "0666" }
`, nil)
	for p, want := range map[string]os.FileMode{"a": 0o755, "a/b": 0o777, "logs/app.log": 0o666} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}

func TestDefaultFileModeIsNot0777(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not carry POSIX permission bits")
	}
	root, _ := runManifest(t, `
operations:
  - action: create
    path: plain.txt
    content: "x"
`, nil)

	info, _ := os.Stat(filepath.Join(root, "plain.txt"))
	if got := info.Mode().Perm(); got != sandbox.FileMode {
		t.Errorf("default mode = %o, want %o", got, sandbox.FileMode)
	}
}

func TestCopyProducesIdenticalBytes(t *testing.T) {
	root, _ := runManifest(t, `
operations:
  - action: create
    path: reports/a.txt
    content: "the report"
  - action: copy
    path: reports/a.txt
    new_path: staging/b.txt
    mtime: "2026-03-14T02:47:00Z"
`, nil)

	a, err := os.ReadFile(filepath.Join(root, "reports", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "staging", "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("copy differs: %q vs %q", a, b)
	}

	info, _ := os.Stat(filepath.Join(root, "staging", "b.txt"))
	want := time.Date(2026, 3, 14, 2, 47, 0, 0, time.UTC)
	if !info.ModTime().UTC().Equal(want) {
		t.Errorf("copy mtime = %v, want %v", info.ModTime().UTC(), want)
	}
}

// update of a file that does not exist used to create it, directories and all,
// so a typo in an update path silently produced a new file. It is now refused
// before anything is written, pointing at create.
func TestUpdateMissingIsError(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: update
    path: deep/nested/file.txt
    content: "written"
`)
	err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "does not exist; use create") {
		t.Fatalf("err = %v, want an update-of-missing-file error pointing at create", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("nothing should be written, found %v", entries)
	}
}

func TestMaceStampsTimes(t *testing.T) {
	root, _ := runManifest(t, `
operations:
  - action: create
    path: vault.yml
    content: "encrypted"
    mtime: "2025-11-02T09:00:00Z"
  - action: mace
    path: vault.yml
    atime: "2026-03-14T02:30:00Z"
    mtime: "2025-11-02T09:00:00Z"
`, nil)

	info, _ := os.Stat(filepath.Join(root, "vault.yml"))
	want := time.Date(2025, 11, 2, 9, 0, 0, 0, time.UTC)
	if !info.ModTime().UTC().Equal(want) {
		t.Errorf("mtime = %v, want %v (read, not modified)", info.ModTime().UTC(), want)
	}
}

func TestPDFFormatProducesRealPDFWithMetadata(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "content/report.md", "# Findings\n\n| Host | Secret |\n|---|---|\n| FS01 | ssh-key |\n\n- one\n- two\n")
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: report.pdf
    format: pdf
    content_file: content/report.md
    pdf:
      title: "Configuration Review"
      author: "svc-agent@acme.local"
      creator: "SentinelIQ 2.1.4"
      producer: "SentinelIQ Report Engine"
      created: "2026-03-14T02:33:12Z"
      modified: "2026-03-14T02:33:12Z"
`)

	if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "report.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("not a PDF, starts with %q", data[:min(8, len(data))])
	}
	for _, want := range []string{
		"/Title (Configuration Review)",
		"/Author (svc-agent@acme.local)",
		"/Creator (SentinelIQ 2.1.4)",
		"/Producer (SentinelIQ Report Engine)",
		"/CreationDate (D:20260314023312)",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("PDF is missing %s", want)
		}
	}
}

// Byte-stable PDFs are what let a report be attached to a message and match its
// on-disk copy hash for hash.
func TestPDFRenderIsReproducible(t *testing.T) {
	baseDir := t.TempDir()
	writeFile(t, baseDir, "content/report.md", "# R\n\n| a | b |\n|---|---|\n| 1 | 2 |\n")
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: report.pdf
    format: pdf
    content_file: content/report.md
    pdf:
      created: "2026-03-14T02:33:12Z"
      modified: "2026-03-14T02:33:12Z"
`)

	read := func() []byte {
		root := t.TempDir()
		if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(root, "report.pdf"))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	if !bytes.Equal(read(), read()) {
		t.Error("two renders of the same input differ")
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: out.xlsx
    format: xlsx
    content: "x"
`)
	err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("err = %v, want an unknown-format error", err)
	}
}

func TestEmailActionWritesParseableEml(t *testing.T) {
	root, _ := runManifest(t, `
operations:
  - action: email
    path: Inbox/0001.eml
    email:
      from: "Dana <d@northbridge.example>"
      to: ["priyan@acme.example"]
      subject: "Assessment"
      date: "2026-03-02T09:14:00Z"
      message_id: "<a@northbridge.example>"
      body_text: "Hello"
`, nil)

	data, err := os.ReadFile(filepath.Join(root, "Inbox", "0001.eml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("Subject: Assessment\r\n")) {
		t.Errorf("missing subject header:\n%s", data)
	}

	// With no explicit times, the file should carry the message Date.
	info, _ := os.Stat(filepath.Join(root, "Inbox", "0001.eml"))
	want := time.Date(2026, 3, 2, 9, 14, 0, 0, time.UTC)
	if !info.ModTime().UTC().Equal(want) {
		t.Errorf("mtime = %v, want the Date header %v", info.ModTime().UTC(), want)
	}
}

func TestEmailMboxAppends(t *testing.T) {
	root, _ := runManifest(t, `
operations:
  - action: email
    path: thread.mbox
    format: mbox
    email:
      from: "a@x.example"
      to: ["b@y.example"]
      subject: "First"
      date: "2026-03-01T10:00:00Z"
      body_text: "one"
  - action: email
    path: thread.mbox
    format: mbox
    email:
      from: "b@y.example"
      to: ["a@x.example"]
      subject: "Second"
      date: "2026-03-01T11:00:00Z"
      body_text: "two"
`, nil)

	data, err := os.ReadFile(filepath.Join(root, "thread.mbox"))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte("\nFrom ")); n != 1 {
		// One separator between the two entries; the first is at offset 0.
		t.Errorf("From_ separators = %d, want the second message appended", n)
	}
	if !bytes.Contains(data, []byte("Subject: First")) || !bytes.Contains(data, []byte("Subject: Second")) {
		t.Error("both messages should be present")
	}
}

func TestAnsibleVaultActionRoundTrips(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	const plaintext = "---\nflag: \"FLAG{x}\"\n"
	writeFile(t, baseDir, "content/vault.yml", plaintext)
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: ansible-vault
    path: group_vars/prod/vault.yml
    content_file: content/vault.yml
    vault:
      password: "${VAR:vault_password}"
`)

	if err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{Vars: map[string]string{"vault_password": "pw123"}}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "group_vars", "prod", "vault.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("$ANSIBLE_VAULT;1.1;AES256\n")) {
		t.Errorf("bad vault header: %q", data[:min(40, len(data))])
	}

	got, err := util.AnsibleVaultDecrypt(data, "pw123")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

// An undefined variable used to be left in the output verbatim, where a ':' in
// "${VAR:x}" could even create an NTFS stream. It is now an error.
func TestUndefinedVariableIsError(t *testing.T) {
	baseDir := t.TempDir()
	root := t.TempDir()
	writeFile(t, baseDir, "manifest.yaml", `
operations:
  - action: create
    path: out.txt
    content: "value=${VAR:missing}"
`)
	err := ExecuteManifest(root, filepath.Join(baseDir, "manifest.yaml"), compile.Options{})
	if err == nil || !strings.Contains(err.Error(), `undefined variable "missing"`) {
		t.Fatalf("err = %v, want an undefined-variable error", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "out.txt")); !os.IsNotExist(statErr) {
		t.Error("out.txt should not have been written")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
