package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func openTemp(t *testing.T) (*FS, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	fsys, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })
	return fsys, parent
}

// os.Root is the second line of defence behind pathpolicy: even a path that
// reached it unchecked cannot write outside the root.
func TestNothingWrittenOutsideRoot(t *testing.T) {
	fsys, parent := openTemp(t)
	for _, p := range []string{"../ESCAPED.txt", "a/../../ESCAPED.txt"} {
		if err := fsys.WriteFile(p, []byte("x"), FileMode); err == nil {
			t.Errorf("WriteFile(%q) succeeded", p)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, "ESCAPED.txt")); !os.IsNotExist(err) {
		t.Error("a file was written outside the root")
	}
}

func TestSymlinkOutOfRootRefused(t *testing.T) {
	fsys, parent := openTemp(t)
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(fsys.Dir(), "link")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if err := fsys.WriteFile("link/x.txt", []byte("x"), FileMode); err == nil {
		t.Error("write through a symlink leaving the root succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "x.txt")); !os.IsNotExist(err) {
		t.Error("a file was written outside the root through a symlink")
	}
}

func TestSourcesConfined(t *testing.T) {
	parent := t.TempDir()
	yamlDir := filepath.Join(parent, "yaml")
	os.MkdirAll(filepath.Join(yamlDir, "content"), 0o755)
	os.WriteFile(filepath.Join(yamlDir, "content", "ok.txt"), []byte("inside"), 0o644)
	secret := filepath.Join(parent, "secret.txt")
	os.WriteFile(secret, []byte("TOP-SECRET"), 0o644)

	src, err := OpenSources(yamlDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if data, err := src.ReadFile("content/ok.txt"); err != nil || string(data) != "inside" {
		t.Fatalf("inside read: %q, %v", data, err)
	}
	for _, p := range []string{"../secret.txt", filepath.ToSlash(secret)} {
		if _, err := src.ReadFile(p); err == nil || !strings.Contains(err.Error(), "--allow-external-sources") {
			t.Errorf("ReadFile(%q) err = %v, want a confinement error", p, err)
		}
	}
	if got := src.Inputs(); len(got) != 1 || got[0].Path != "content/ok.txt" {
		t.Errorf("Inputs = %+v", got)
	}

	ext, err := OpenSources(yamlDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	if data, err := ext.ReadFile("../secret.txt"); err != nil || string(data) != "TOP-SECRET" {
		t.Errorf("allowed external read: %q, %v", data, err)
	}
}

func TestStreams(t *testing.T) {
	fsys, _ := openTemp(t)
	if runtime.GOOS != "windows" {
		if err := fsys.WriteStream("x", "s", nil); err != ErrStreamsUnsupported {
			t.Errorf("WriteStream on %s: %v", runtime.GOOS, err)
		}
		return
	}
	if !fsys.SupportsStreams() {
		t.Skipf("volume %q has no named streams", fsys.FilesystemName())
	}
	if err := fsys.WriteFile("implant.exe", []byte("MZ"), FileMode); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteStream("implant.exe", "quill", []byte("hidden")); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteStream("implant.exe", "a b", []byte("12345")); err != nil {
		t.Fatal(err)
	}
	streams, err := fsys.Streams("implant.exe")
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 2 || streams[0] != (Stream{"a b", 5}) || streams[1] != (Stream{"quill", 6}) {
		t.Errorf("Streams = %+v", streams)
	}
	if data, err := fsys.ReadStream("implant.exe", "quill"); err != nil || string(data) != "hidden" {
		t.Errorf("ReadStream = %q, %v", data, err)
	}
	if base, _ := fsys.ReadFile("implant.exe"); string(base) != "MZ" {
		t.Errorf("base content changed: %q", base)
	}
	// A stream is only ever opened relative to a base that exists in the root.
	if err := fsys.WriteStream("missing.exe", "s", []byte("x")); err == nil {
		t.Error("stream on a missing base succeeded")
	}
	if err := fsys.WriteStream("implant.exe", "../x", []byte("x")); err == nil {
		t.Error("stream name with a separator accepted")
	}
}
