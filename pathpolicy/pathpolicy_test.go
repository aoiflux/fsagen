package pathpolicy

import (
	"strings"
	"testing"
)

func TestOutputRejects(t *testing.T) {
	for _, tc := range []struct{ base, path, want string }{
		{"", "../x", "escapes the output root"},
		{"", "a/../../x", "escapes the output root"},
		{"users/bob", "../../../x", "escapes the output root"},
		{"", "/x", "absolute"},
		{"", "C:/x", "contains ':'"},
		{"", "C:x", "contains ':'"},
		{"", "a:b", "contains ':'"},
		{"", `a\b`, `contains '\'`},
		{"", "a\x00b", "NUL"},
		{"", "notes.", "dot or space"},
		{"", "dir /file", "dot or space"},
		{"", ".", "output root itself"},
		{"", "a/..", "output root itself"},
		{"", "", "empty"},
		{"", strings.Repeat("x", 256), "longer than 255"},
		{`c:\users`, "x", "actor base"},
	} {
		if _, _, err := Output(tc.base, tc.path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Output(%q, %q) err = %v, want it to mention %q", tc.base, tc.path, err, tc.want)
		}
	}
}

// A ".." that stays inside the root is allowed: an actor based in AppData can
// reach its sibling Documents directory.
func TestOutputAllowsInsideDotDot(t *testing.T) {
	got, dir, err := Output("users/alice/AppData/Roaming", "../../Documents/x.docx")
	if err != nil || got != "users/alice/Documents/x.docx" || dir {
		t.Fatalf("got %q, %v, %v", got, dir, err)
	}
}

// A trailing '/' marks a directory on every platform, not only where the
// separator happens to be '/'.
func TestOutputTrailingSlashIsDirectory(t *testing.T) {
	got, dir, err := Output("home", "trailing_slash_dir/")
	if err != nil || !dir || got != "home/trailing_slash_dir" {
		t.Fatalf("got %q, dir=%v, err=%v", got, dir, err)
	}
}

func TestPortable(t *testing.T) {
	for _, bad := range []string{"CON", "con.txt", "a/LPT1.log", "Aux.tar.gz", "COM¹", "x/NUL", strings.Repeat("a/", 101)} {
		if err := Portable(bad); err == nil {
			t.Errorf("Portable(%q) accepted a non-portable path", bad)
		}
	}
	for _, good := range []string{"console.txt", "com10", "a/lpt", "docs/report.pdf"} {
		if err := Portable(good); err != nil {
			t.Errorf("Portable(%q) = %v", good, err)
		}
	}
}

func TestFoldKey(t *testing.T) {
	if FoldKey("Docs/Report.TXT") != FoldKey("docs/report.txt") {
		t.Error("case variants should share a fold key")
	}
	// "é" precomposed and decomposed are the same name on APFS and NTFS.
	if FoldKey("caf\u00e9") != FoldKey("cafe\u0301") {
		t.Error("NFC and NFD forms should share a fold key")
	}
	if FoldKey("a") == FoldKey("b") {
		t.Error("different names must not collide")
	}
}

func TestStream(t *testing.T) {
	for _, bad := range []string{"", "a:b", "a/b", `a\b`, "a\x00", strings.Repeat("s", 256)} {
		if Stream(bad) == nil {
			t.Errorf("Stream(%q) accepted", bad)
		}
	}
	for _, good := range []string{"quill", "a b", "Zone.Identifier"} {
		if err := Stream(good); err != nil {
			t.Errorf("Stream(%q) = %v", good, err)
		}
	}
}

func TestSource(t *testing.T) {
	for _, tc := range []struct {
		in       string
		clean    string
		external bool
	}{
		{"content/id_rsa", "content/id_rsa", false},
		{"content/../content/x", "content/x", false},
		{"../outside.txt", "../outside.txt", true},
		{"/etc/passwd", "/etc/passwd", true},
	} {
		clean, external, err := Source(tc.in)
		if err != nil || clean != tc.clean || external != tc.external {
			t.Errorf("Source(%q) = %q, %v, %v; want %q, %v", tc.in, clean, external, err, tc.clean, tc.external)
		}
	}
	for _, bad := range []string{"", `a\b`, "a:b"} {
		if _, _, err := Source(bad); err == nil {
			t.Errorf("Source(%q) accepted", bad)
		}
	}
}
