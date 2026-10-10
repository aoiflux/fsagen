package libgen

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// The login records Linux keeps: utmp (who is logged in now), wtmp (every
// login, logout, boot and shutdown) and btmp (failed logins). All three are
// arrays of glibc's struct utmp, 384 bytes on every 64-bit Linux, amd64 and
// arm64 alike, because glibc keeps its times there as 32-bit seconds and
// microseconds for compatibility with 32-bit programs. That is also why a
// record cannot hold a time after January 2038.

// UtmpSize is the size of one record.
const UtmpSize = 384

// The ut_type values the records here use.
const (
	utRunLevel     = 1
	utBootTime     = 2
	utLoginProcess = 6
	utUserProcess  = 7
	utDeadProcess  = 8
)

// UtmpKinds is the closed set of records: a boot, a shutdown, a login and
// its logout, and a failed login (which only btmp keeps).
var UtmpKinds = []string{"boot", "shutdown", "login", "logout", "failed"}

// Field sizes of struct utmp.
const (
	utLineSize = 32
	utIDSize   = 4
	utUserSize = 32
	utHostSize = 256
)

// UtmpRecord is one record as a scenario describes it.
type UtmpRecord struct {
	Kind string
	// User is who logged in, or tried to; a boot and a shutdown name
	// themselves ("reboot", "shutdown") as Linux does.
	User string
	// Line is the terminal, pts/0 or tty1; a failed SSH login's is
	// ssh:notty, and a boot's is ~.
	Line string
	// Host is where the login came from, a name or an address; for a boot,
	// the kernel release, which last shows beside it.
	Host string
	// PID is the login process; a logout without one takes its login's.
	PID     int32
	Session int32
	Time    time.Time
}

// MaxUtmpTime is the last time a record can hold, 2038-01-19T03:14:07Z.
var MaxUtmpTime = time.Unix(math.MaxInt32, 999999000).UTC()

// CheckUtmpRecord reports what a record cannot hold: a time outside
// 1970-2038, or a field longer than its slot.
func CheckUtmpRecord(r UtmpRecord) error {
	if !slices.Contains(UtmpKinds, r.Kind) {
		return fmt.Errorf("record kind %q (want one of: %s)", r.Kind, strings.Join(UtmpKinds, ", "))
	}
	if r.Time.Before(time.Unix(0, 0)) || r.Time.After(MaxUtmpTime) {
		return fmt.Errorf("time %s is outside what a utmp record holds (1970 to 2038-01-19T03:14:07Z)", r.Time.Format(time.RFC3339))
	}
	for _, f := range []struct {
		name, val string
		size      int
	}{{"user", r.User, utUserSize}, {"line", r.Line, utLineSize}, {"host", r.Host, utHostSize}} {
		if len(f.val) > f.size {
			return fmt.Errorf("%s %q is %d bytes; a utmp record holds %d", f.name, f.val, len(f.val), f.size)
		}
		if strings.ContainsRune(f.val, 0) {
			return fmt.Errorf("%s %q holds a NUL", f.name, f.val)
		}
	}
	return nil
}

// BuildUtmp writes the records in order. A login's ut_id is the last four
// characters of its line, as login and sshd make it; a logout takes the
// line's id and, when it gives no pid, the pid of the login it ends.
func BuildUtmp(records []UtmpRecord) ([]byte, error) {
	le := binary.LittleEndian
	out := make([]byte, 0, UtmpSize*len(records))
	logins := map[string]int32{}
	for i, r := range records {
		if err := CheckUtmpRecord(r); err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		b := make([]byte, UtmpSize)
		typ, line, id, user, host := 0, r.Line, "", r.User, r.Host
		switch r.Kind {
		case "boot":
			typ, line, id, user = utBootTime, "~", "~~", "reboot"
		case "shutdown":
			typ, line, id, user = utRunLevel, "~", "~~", "shutdown"
		case "login":
			typ, id = utUserProcess, lastN(line, utIDSize)
			logins[line] = r.PID
		case "logout":
			typ, id, user, host = utDeadProcess, lastN(line, utIDSize), "", ""
			if r.PID == 0 {
				r.PID = logins[line]
			}
		case "failed":
			typ, id = utLoginProcess, lastN(line, utIDSize)
		}
		le.PutUint16(b[0:], uint16(typ))
		le.PutUint32(b[4:], uint32(r.PID))
		copy(b[8:8+utLineSize], line)
		copy(b[40:40+utIDSize], id)
		copy(b[44:44+utUserSize], user)
		copy(b[76:76+utHostSize], host)
		le.PutUint32(b[336:], uint32(r.Session))
		le.PutUint32(b[340:], uint32(r.Time.Unix()))
		le.PutUint32(b[344:], uint32(r.Time.Nanosecond()/1000))
		if addr, err := netip.ParseAddr(host); err == nil {
			if addr.Is4() {
				a := addr.As4()
				copy(b[348:], a[:])
			} else {
				a := addr.As16()
				copy(b[348:], a[:])
			}
		}
		out = append(out, b...)
	}
	return out, nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
