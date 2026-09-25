package sandbox

import (
	"io"
	iofs "io/fs"
	"runtime"
	"testing"
	"time"
)

func within(a, b time.Time, g time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d < g || (g <= 1 && d == 0)
}

// Every time the platform can set comes back as set, to the volume's
// resolution, on files and directories alike.
func TestSetTimesRoundTrip(t *testing.T) {
	fsys, _ := openTemp(t)
	if err := fsys.WriteFile("d/f.txt", []byte("x"), FileMode); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2021, 3, 4, 5, 6, 7, 123456700, time.UTC)
	want := Times{Btime: base, Ctime: base.Add(time.Hour), Mtime: base.Add(2 * time.Hour), Atime: base.Add(3 * time.Hour)}
	caps, g := fsys.TimeCaps(), fsys.Granularity()
	for _, name := range []string{"d/f.txt", "d"} {
		if err := fsys.SetTimes(name, want); err != nil {
			t.Fatal(err)
		}
		got, err := fsys.Times(name)
		if err != nil {
			t.Fatal(err)
		}
		if !within(got.Atime, want.Atime, g.Atime) || !within(got.Mtime, want.Mtime, g.Mtime) {
			t.Errorf("%s: atime/mtime = %v/%v, want %v/%v", name, got.Atime, got.Mtime, want.Atime, want.Mtime)
		}
		if caps.Birth && !within(got.Btime, want.Btime, g.Btime) {
			t.Errorf("%s: birth = %v, want %v", name, got.Btime, want.Btime)
		}
		if caps.Change && !within(got.Ctime, want.Ctime, g.Ctime) {
			t.Errorf("%s: change = %v, want %v", name, got.Ctime, want.Ctime)
		}
	}
}

// The spike behind the capability matrix: on NTFS the change time set
// through FILE_BASIC_INFO is stored exactly and survives closing the handle.
func TestChangeTimeSticks(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("change time can only be set on Windows")
	}
	fsys, _ := openTemp(t)
	if !fsys.TimeCaps().Change {
		t.Skipf("%s does not store a change time", fsys.FilesystemName())
	}
	if err := fsys.WriteFile("f.txt", []byte("x"), FileMode); err != nil {
		t.Fatal(err)
	}
	c := time.Date(2020, 1, 2, 3, 4, 5, 600, time.UTC)
	if err := fsys.SetTimes("f.txt", Times{Ctime: c}); err != nil {
		t.Fatal(err)
	}
	got, err := fsys.Times("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ctime.Equal(c) {
		t.Errorf("change time = %v, want %v", got.Ctime, c)
	}
}

// A zero time in Times leaves that time alone.
func TestSetTimesZeroLeavesAlone(t *testing.T) {
	fsys, _ := openTemp(t)
	if err := fsys.WriteFile("f.txt", []byte("x"), FileMode); err != nil {
		t.Fatal(err)
	}
	m := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	a := time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := fsys.SetTimes("f.txt", Times{Mtime: m, Atime: a}); err != nil {
		t.Fatal(err)
	}
	if err := fsys.SetTimes("f.txt", Times{Mtime: m.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, _ := fsys.Times("f.txt")
	if !got.Atime.Equal(a) || !got.Mtime.Equal(m.Add(time.Hour)) {
		t.Errorf("got atime %v mtime %v", got.Atime, got.Mtime)
	}
	if err := fsys.SetTimes(".", Times{Mtime: m}); err == nil {
		t.Error("stamping the root itself succeeded")
	}
}

// Reading through OpenQuiet leaves the access time where it was. The test
// first proves that an ordinary read on this volume does move it, and skips
// when it does not (last-access updates disabled, noatime mounts).
func TestOpenQuietKeepsAtime(t *testing.T) {
	fsys, _ := openTemp(t)
	if err := fsys.WriteFile("f.txt", []byte("some content"), FileMode); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC)
	stamp := func() {
		if err := fsys.SetTimes("f.txt", Times{Atime: old, Mtime: old}); err != nil {
			t.Fatal(err)
		}
	}
	stamp()
	if _, err := fsys.ReadFile("f.txt"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fsys.Times("f.txt"); got.Atime.Equal(old) {
		t.Skip("this volume does not update access times on read")
	}
	stamp()
	f, err := fsys.OpenQuiet("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(data) != "some content" {
		t.Fatalf("read %q, %v", data, err)
	}
	if got, _ := fsys.Times("f.txt"); !got.Atime.Equal(old) {
		t.Errorf("a quiet read moved the access time to %v", got.Atime)
	}
}

func TestCopyStreams(t *testing.T) {
	fsys, _ := openTemp(t)
	if !fsys.SupportsStreams() {
		t.Skip("no named streams on this volume")
	}
	for _, n := range []string{"a.txt", "b.txt"} {
		if err := fsys.WriteFile(n, []byte(n), FileMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := fsys.WriteStream("a.txt", "Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := fsys.CopyStreams("a.txt", "b.txt"); err != nil {
		t.Fatal(err)
	}
	got, err := fsys.ReadStream("b.txt", "Zone.Identifier")
	if err != nil || string(got) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Errorf("copied stream = %q, %v", got, err)
	}
}

// Listing a directory through ReadDirQuiet leaves its access time alone.
func TestReadDirQuietKeepsAtime(t *testing.T) {
	fsys, _ := openTemp(t)
	for _, n := range []string{"d/a.txt", "d/b.txt"} {
		if err := fsys.WriteFile(n, []byte(n), FileMode); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC)
	stamp := func() {
		if err := fsys.SetTimes("d", Times{Atime: old, Mtime: old}); err != nil {
			t.Fatal(err)
		}
	}
	stamp()
	if _, err := iofs.ReadDir(fsys.root.FS(), "d"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fsys.Times("d"); got.Atime.Equal(old) {
		t.Skip("this volume does not update directory access times on listing")
	}
	stamp()
	entries, err := fsys.ReadDirQuiet("d")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "a.txt" || entries[1].Name() != "b.txt" {
		t.Fatalf("entries = %v", entries)
	}
	if got, _ := fsys.Times("d"); !got.Atime.Equal(old) {
		t.Errorf("a quiet listing moved the access time to %v", got.Atime)
	}
}
