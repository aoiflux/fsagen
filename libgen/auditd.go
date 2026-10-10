package libgen

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// A Linux audit log (/var/log/audit/audit.log) as auditd writes it in its
// raw format: one line per record, "type=... msg=audit(<seconds>.<ms>:<serial>):"
// then the record's fields. The records of one event share its time and
// serial. A program's execution is the kernel's SYSCALL record for execve,
// then EXECVE with its arguments, CWD, a PATH per file the call opened (the
// program and its loader) and PROCTITLE; a login is the user-space records
// PAM and sshd write. Strings the kernel does not trust are written as hex
// when they hold a space, a quote or anything outside printable ASCII, as
// the kernel does, and ausearch decodes them back.

// AuditKinds is the closed set of events: a program's execution, and the
// authentication, login and session start of a login.
var AuditKinds = []string{"execve", "auth", "login", "session_start"}

// AuditEvent is one event as a scenario describes it.
type AuditEvent struct {
	Kind string
	Time time.Time
	// User is the account: whose login, or who ran the program.
	User string
	// UID is the user's id, and AUID the login's (the user who logged in,
	// which su and sudo keep). Session is the login session's number.
	UID, AUID, Session uint32
	PID, PPID          uint32
	// Exe is the program's path; Argv its arguments, the program first;
	// Cwd where it ran. For a login, Exe is the service (sshd).
	Exe  string
	Argv []string
	Cwd  string
	// Key is the audit rule's key, which ausearch -k finds; empty is none.
	Key string
	// Host, Addr and Terminal are where a login came from and on what.
	Host, Addr, Terminal string
	// TTY is the terminal of an executed program, pts0; empty is none.
	TTY     string
	Success bool
}

// AuditLog is a log: its events in order, numbered from FirstSerial.
type AuditLog struct {
	FirstSerial uint64
	Events      []AuditEvent
}

// loader is the dynamic loader every dynamically linked x86-64 program maps.
const loader = "/lib64/ld-linux-x86-64.so.2"

// BuildAuditLog writes the log. Each event takes the next serial and a gap
// of up to four, as other events would have taken those between; values a
// real record carries that the scenario does not give (the syscall's
// argument pointers, the files' inodes) come from s.
func BuildAuditLog(log AuditLog, s *prng.Stream) ([]byte, error) {
	var b strings.Builder
	serial := log.FirstSerial
	for i, e := range log.Events {
		if !slices.Contains(AuditKinds, e.Kind) {
			return nil, fmt.Errorf("event %d: kind %q (want one of: %s)", i, e.Kind, strings.Join(AuditKinds, ", "))
		}
		stamp := fmt.Sprintf("msg=audit(%d.%03d:%d):", e.Time.Unix(), e.Time.Nanosecond()/1_000_000, serial)
		res := "success"
		if !e.Success {
			res = "failed"
		}
		host, addr, term := or(e.Host, "?"), or(e.Addr, "?"), or(e.Terminal, "?")
		switch e.Kind {
		case "execve":
			argv := e.Argv
			if len(argv) == 0 {
				argv = []string{e.Exe}
			}
			exit, success := "0", "yes"
			if !e.Success {
				exit, success = "-13", "no"
			}
			tty := or(e.TTY, "(none)")
			ptrs := make([]string, 4)
			for j := range ptrs {
				ptrs[j] = fmt.Sprintf("%x", 0x550000000000|s.Uint64()&0xffffffffff)
			}
			key := "(null)"
			if e.Key != "" {
				key = auditString(e.Key)
			}
			comm := argv[0]
			if k := strings.LastIndexByte(comm, '/'); k >= 0 {
				comm = comm[k+1:]
			}
			if len(comm) > 15 {
				comm = comm[:15] // TASK_COMM_LEN
			}
			fmt.Fprintf(&b, "type=SYSCALL %s arch=c000003e syscall=59 success=%s exit=%s a0=%s a1=%s a2=%s a3=%s items=2 ppid=%d pid=%d auid=%d uid=%d gid=%d euid=%d suid=%d fsuid=%d egid=%d sgid=%d fsgid=%d tty=%s ses=%d comm=%s exe=%s key=%s\n",
				stamp, success, exit, ptrs[0], ptrs[1], ptrs[2], ptrs[3], e.PPID, e.PID, e.AUID, e.UID, e.UID, e.UID, e.UID, e.UID, e.UID, e.UID, e.UID, tty, e.Session, auditString(comm), auditString(e.Exe), key)
			fmt.Fprintf(&b, "type=EXECVE %s argc=%d", stamp, len(argv))
			for j, a := range argv {
				fmt.Fprintf(&b, " a%d=%s", j, auditString(a))
			}
			b.WriteString("\n")
			fmt.Fprintf(&b, "type=CWD %s cwd=%s\n", stamp, auditString(or(e.Cwd, "/")))
			for j, p := range []string{e.Exe, loader} {
				fmt.Fprintf(&b, "type=PATH %s item=%d name=%s inode=%d dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\n",
					stamp, j, auditString(p), 100000+s.IntN(4_000_000))
			}
			title := []byte(strings.Join(argv, "\x00"))
			if len(title) > 128 { // the kernel keeps at most 128 bytes of a proctitle
				title = title[:128]
			}
			fmt.Fprintf(&b, "type=PROCTITLE %s proctitle=%s\n", stamp, auditBytes(title))
		case "auth":
			grantors := "pam_unix"
			if !e.Success {
				grantors = "?"
			}
			fmt.Fprintf(&b, "type=USER_AUTH %s pid=%d uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=%s acct=%s exe=%s hostname=%s addr=%s terminal=%s res=%s'\n",
				stamp, e.PID, grantors, auditString(e.User), auditString(e.Exe), host, addr, term, res)
		case "login":
			fmt.Fprintf(&b, "type=USER_LOGIN %s pid=%d uid=0 auid=%d ses=%d msg='op=login id=%d exe=%s hostname=%s addr=%s terminal=%s res=%s'\n",
				stamp, e.PID, e.AUID, e.Session, e.UID, auditString(e.Exe), host, addr, term, res)
		case "session_start":
			fmt.Fprintf(&b, "type=USER_START %s pid=%d uid=0 auid=%d ses=%d msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_umask,pam_lastlog acct=%s exe=%s hostname=%s addr=%s terminal=%s res=%s'\n",
				stamp, e.PID, e.AUID, e.Session, auditString(e.User), auditString(e.Exe), host, addr, term, res)
		}
		serial += 1 + uint64(s.IntN(5))
	}
	return []byte(b.String()), nil
}

// auditString writes a string as the kernel's audit_log_untrustedstring
// does: in quotes when every byte is printable ASCII other than the quote and
// a space, else as upper-case hex.
func auditString(s string) string { return auditBytes([]byte(s)) }

func auditBytes(b []byte) string {
	for _, c := range b {
		if c <= 0x20 || c >= 0x7f || c == '"' {
			return strings.ToUpper(hex.EncodeToString(b))
		}
	}
	return `"` + string(b) + `"`
}
