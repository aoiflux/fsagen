package libgen

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// utmpRecord mirrors glibc's struct utmp on 64-bit Linux, field for field.
type utmpRecord struct {
	Type     int16
	_        int16
	PID      int32
	Line     [32]byte
	ID       [4]byte
	User     [32]byte
	Host     [256]byte
	Exit     [2]int16
	Session  int32
	Sec      int32
	Usec     int32
	AddrV6   [4]int32
	Reserved [20]byte
}

func cstr(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }

func sampleUtmp() []UtmpRecord {
	t := time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC)
	return []UtmpRecord{
		{Kind: "boot", Host: "6.8.0-31-generic", Time: t},
		{Kind: "login", User: "user1", Line: "pts/0", Host: "203.0.113.7", PID: 2201, Session: 3, Time: t.Add(10*time.Minute + 123456*time.Microsecond)},
		{Kind: "login", User: "user2", Line: "pts/1", Host: "2001:db8::7", PID: 2350, Session: 4, Time: t.Add(20 * time.Minute)},
		{Kind: "logout", Line: "pts/0", Time: t.Add(70 * time.Minute)},
		{Kind: "shutdown", Host: "6.8.0-31-generic", Time: t.Add(2 * time.Hour)},
	}
}

// TestUtmpLayout: each record is glibc's 384-byte struct utmp — the size
// binary.Read finds for the mirror above — with the type, line, id, user,
// host, session, time and address where glibc keeps them; a logout carries
// its login's line, id and pid and no user.
func TestUtmpLayout(t *testing.T) {
	if n := binary.Size(utmpRecord{}); n != UtmpSize {
		t.Fatalf("struct utmp is %d bytes here, want %d", n, UtmpSize)
	}
	recs := sampleUtmp()
	data, err := BuildUtmp(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(recs)*UtmpSize {
		t.Fatalf("%d bytes for %d records", len(data), len(recs))
	}
	got := make([]utmpRecord, len(recs))
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, got); err != nil {
		t.Fatal(err)
	}
	type want struct {
		typ                     int16
		line, id, user, host    string
		pid, session, sec, usec int32
		addr                    [4]int32
	}
	ip4 := [4]int32{int32(binary.LittleEndian.Uint32([]byte{203, 0, 113, 7}))}
	ip6 := [4]int32{
		int32(binary.LittleEndian.Uint32([]byte{0x20, 0x01, 0x0d, 0xb8})), 0, 0,
		int32(binary.LittleEndian.Uint32([]byte{0, 0, 0, 7})),
	}
	sec := func(r UtmpRecord) int32 { return int32(r.Time.Unix()) }
	for i, w := range []want{
		{2, "~", "~~", "reboot", "6.8.0-31-generic", 0, 0, sec(recs[0]), 0, [4]int32{}},
		{7, "pts/0", "ts/0", "user1", "203.0.113.7", 2201, 3, sec(recs[1]), 123456, ip4},
		{7, "pts/1", "ts/1", "user2", "2001:db8::7", 2350, 4, sec(recs[2]), 0, ip6},
		{8, "pts/0", "ts/0", "", "", 2201, 0, sec(recs[3]), 0, [4]int32{}},
		{1, "~", "~~", "shutdown", "6.8.0-31-generic", 0, 0, sec(recs[4]), 0, [4]int32{}},
	} {
		r := got[i]
		g := want{r.Type, cstr(r.Line[:]), cstr(r.ID[:]), cstr(r.User[:]), cstr(r.Host[:]), r.PID, r.Session, r.Sec, r.Usec, r.AddrV6}
		if g != w {
			t.Errorf("record %d\n got %+v\nwant %+v", i, g, w)
		}
	}
}

// TestUtmpRefuses: a time after 2038 or before 1970, or a field too long
// for its slot, is refused rather than cut down.
func TestUtmpRefuses(t *testing.T) {
	ok := UtmpRecord{Kind: "login", User: "a", Line: "pts/0", Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	for name, change := range map[string]func(*UtmpRecord){
		"2038":      func(r *UtmpRecord) { r.Time = time.Date(2038, 1, 19, 3, 14, 8, 0, time.UTC) },
		"1969":      func(r *UtmpRecord) { r.Time = time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC) },
		"long user": func(r *UtmpRecord) { r.User = strings.Repeat("u", 33) },
		"long host": func(r *UtmpRecord) { r.Host = strings.Repeat("h", 257) },
		"kind":      func(r *UtmpRecord) { r.Kind = "reboot" },
	} {
		r := ok
		change(&r)
		if _, err := BuildUtmp([]UtmpRecord{r}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := BuildUtmp([]UtmpRecord{ok}); err != nil {
		t.Errorf("a good record was refused: %v", err)
	}
}

// TestUtmpReadByUtilLinux: util-linux's own tools, where installed, read
// the records: utmpdump prints each one back, and last pairs the login with
// its logout and reports the boot.
func TestUtmpReadByUtilLinux(t *testing.T) {
	dump, err1 := exec.LookPath("utmpdump")
	last, err2 := exec.LookPath("last")
	if err1 != nil || err2 != nil {
		t.Skip("utmpdump and last are not installed")
	}
	data, err := BuildUtmp(sampleUtmp())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wtmp")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(dump, path).CombinedOutput()
	if err != nil {
		t.Fatalf("utmpdump: %v\n%s", err, out)
	}
	for _, s := range []string{"[2] [00000] [~~  ] [reboot  ] [~           ] [6.8.0-31-generic", "[7] [02201] [ts/0] [user1   ] [pts/0       ] [203.0.113.7", "203.0.113.7", "2001:db8::7", "2024-03-15T09:10:00,123456+00:00"} {
		if !strings.Contains(string(out), s) {
			t.Errorf("utmpdump output lacks %q:\n%s", s, out)
		}
	}
	cmd := exec.Command(last, "-F", "-x", "-w", "-f", path)
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("last: %v\n%s", err, out)
	}
	for _, s := range []string{"user1    pts/0        203.0.113.7      Fri Mar 15 09:10:00 2024 - Fri Mar 15 10:10:00 2024", "reboot   system boot", "user2"} {
		if !strings.Contains(string(out), s) {
			t.Errorf("last output lacks %q:\n%s", s, out)
		}
	}
}
