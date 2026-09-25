//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// F-TL-2 on Linux: the birth time comes from statx where the file system
// keeps one (btrfs, ext4, xfs) and is unknown where it does not; it is
// never another time copied into its place. The inode number and owner are
// the file's own.
func TestLinuxBtimeFromStatxOrZero(t *testing.T) {
	root := t.TempDir()
	fsys, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	before := time.Now().Add(-time.Second)
	if err := fsys.WriteFile("a.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second)

	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, filepath.Join(root, "a.txt"), unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &st); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := fsys.SetTimes("a.txt", Times{Atime: old, Mtime: old}); err != nil {
		t.Fatal(err)
	}
	m, err := fsys.Meta("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mask&unix.STATX_BTIME == 0 {
		t.Logf("%s keeps no birth time", root)
		if !m.Btime.IsZero() {
			t.Errorf("birth time %v where statx reports none", m.Btime)
		}
	} else {
		want := time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)).UTC()
		if !m.Btime.Equal(want) || m.Btime.Before(before) || m.Btime.After(after) {
			t.Errorf("birth time %v, want statx's %v, between %v and %v", m.Btime, want, before, after)
		}
	}
	if !m.Mtime.Equal(old) || !m.Atime.Equal(old) || m.Ctime.Equal(old) || m.Btime.Equal(old) {
		t.Errorf("times %+v after setting access and modification to %v", m.Times, old)
	}
	if m.ID != strconv.FormatUint(st.Ino, 10) || m.UID != os.Getuid() || m.GID != os.Getgid() {
		t.Errorf("id %s uid %d gid %d, want %d %d %d", m.ID, m.UID, m.GID, st.Ino, os.Getuid(), os.Getgid())
	}
}

// A volume that keeps whole seconds (its root's change time, which only the
// kernel sets, falls on a whole second) is verified to the second; one that
// keeps nanoseconds far more finely. On the first the verify pass would
// otherwise fail every fraction of a second the scenario asks for.
func TestGranularityFromRootChangeTime(t *testing.T) {
	root := t.TempDir()
	fsys, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, root, 0, unix.STATX_CTIME, &st); err != nil {
		t.Fatal(err)
	}
	g := fsys.Granularity()
	t.Logf("%s (%s): change time %d.%09d, resolution %v", root, fsys.FilesystemName(), st.Ctime.Sec, st.Ctime.Nsec, g.Mtime)
	if whole := st.Ctime.Nsec == 0; whole != (g.Mtime >= time.Second) {
		t.Errorf("resolution %v for a root whose change time is %d.%09d", g, st.Ctime.Sec, st.Ctime.Nsec)
	}
	// The volume keeps what it keeps: a time set with a fraction reads back
	// within the resolution fsagen assumes.
	if err := fsys.WriteFile("a", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2021, 3, 1, 9, 0, 0, 987654321, time.UTC)
	if err := fsys.SetTimes("a", Times{Mtime: want}); err != nil {
		t.Fatal(err)
	}
	got, err := fsys.Times("a")
	if err != nil {
		t.Fatal(err)
	}
	if d := want.Sub(got.Mtime); d < 0 || d >= g.Mtime {
		t.Errorf("mtime %v read back as %v, outside the resolution %v", want, got.Mtime, g.Mtime)
	}
}
