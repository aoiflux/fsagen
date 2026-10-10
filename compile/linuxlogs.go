package compile

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// UtmpFiles names the login record each well-known file is.
var UtmpFiles = []string{"utmp", "wtmp", "btmp"}

// recordUsers are the utmp records that name a user; a boot and a shutdown
// name themselves, and a logout names none.
var recordUsers = []string{"login", "failed"}

// checkUtmp validates a utmp block: each record a kind the file keeps, a
// user where one is needed, and fields and times a struct utmp can hold.
func checkUtmp(op *Op, at func(string, string, ...any)) {
	file := ""
	if op.Path != "" {
		file = path.Base(op.Path)
	}
	for i, r := range op.Utmp.Records {
		where := "records[" + strconv.Itoa(i) + "]"
		if !slices.Contains(libgen.UtmpKinds, r.Type) {
			at("utmp", "%s: type %q (want one of: %s)", where, r.Type, strings.Join(libgen.UtmpKinds, ", "))
			continue
		}
		switch {
		case file == "btmp" && r.Type != "failed":
			at("utmp", "%s: btmp keeps failed logins only, not a %s", where, r.Type)
		case (file == "utmp" || file == "wtmp") && r.Type == "failed":
			at("utmp", "%s: a failed login is kept in btmp, not %s", where, file)
		}
		if slices.Contains(recordUsers, r.Type) && strings.TrimSpace(r.User) == "" {
			at("utmp", "%s: a %s names its user (in a playbook it defaults to the actor)", where, r.Type)
		}
		if r.PID < 0 || int64(r.PID) > 0x7FFFFFFF || r.Session < 0 || int64(r.Session) > 0x7FFFFFFF {
			at("utmp", "%s: pid and session are 32-bit and not negative", where)
		}
		when, err := blockTime(r.Time)
		if err != nil {
			at("utmp", "%s.time: %v", where, err)
			continue
		}
		rec := libgen.UtmpRecord{Kind: r.Type, User: r.User, Line: r.Line, Host: r.Host, Time: when}
		if when.IsZero() {
			rec.Time = time.Unix(0, 0)
		}
		if err := libgen.CheckUtmpRecord(rec); err != nil {
			at("utmp", "%s: %v", where, err)
		}
	}
}

// checkAuditd validates an auditd block: each event a kind auditd records,
// with the user and program it needs, ids that fit, and a time.
func checkAuditd(op *Op, at func(string, string, ...any)) {
	a := op.Auditd
	if len(a.Events) == 0 {
		at("auditd", "needs at least one event")
	}
	if a.FirstSerial < 0 {
		at("auditd", "first_serial %d is negative", a.FirstSerial)
	}
	for i, e := range a.Events {
		where := "events[" + strconv.Itoa(i) + "]"
		if !slices.Contains(libgen.AuditKinds, e.Type) {
			at("auditd", "%s: type %q (want one of: %s)", where, e.Type, strings.Join(libgen.AuditKinds, ", "))
		}
		if strings.TrimSpace(e.User) == "" {
			at("auditd", "%s: names its user (in a playbook it defaults to the actor)", where)
		}
		if e.Type == "execve" && e.Exe == "" && len(e.Argv) == 0 {
			at("auditd", "%s: an execve needs the program, exe or argv", where)
		}
		if e.Exe != "" && !strings.HasPrefix(e.Exe, "/") {
			at("auditd", "%s: exe %q must be an absolute path", where, e.Exe)
		}
		for _, n := range []struct {
			key string
			val *int
		}{{"uid", e.UID}, {"auid", e.AUID}, {"session", &e.Session}, {"pid", &e.PID}, {"ppid", &e.PPID}} {
			if n.val != nil && (*n.val < 0 || int64(*n.val) > 0xFFFFFFFF) {
				at("auditd", "%s: %s %d does not fit 32 bits", where, n.key, *n.val)
			}
		}
		if _, err := blockTime(e.Time); err != nil {
			at("auditd", "%s.time: %v", where, err)
		}
	}
}

// blockTime reads an optional RFC 3339 time; zero when not given.
func blockTime(v string) (time.Time, error) {
	if strings.TrimSpace(v) == "" {
		return time.Time{}, nil
	}
	if err := checkTime(v); err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(v))
}

// defaultActorUsers gives the records and events of a playbook action that
// name no user the actor's name, which ties them to who the playbook says
// did it.
func defaultActorUsers(op *spec.Operation, actor string) {
	if op.Utmp != nil {
		for i := range op.Utmp.Records {
			r := &op.Utmp.Records[i]
			if r.User == "" && slices.Contains(recordUsers, r.Type) {
				r.User = actor
			}
		}
	}
	if op.Auditd != nil {
		for i := range op.Auditd.Events {
			if op.Auditd.Events[i].User == "" {
				op.Auditd.Events[i].User = actor
			}
		}
	}
}

// cloneUtmp and cloneAuditd copy the blocks, so a repeated action gets its
// own.
func cloneUtmp(u *spec.UtmpSpec) *spec.UtmpSpec {
	v := *u
	v.Records = append([]spec.UtmpRecord(nil), u.Records...)
	return &v
}

func cloneAuditd(a *spec.AuditdSpec) *spec.AuditdSpec {
	v := *a
	v.Events = append([]spec.AuditdEvent(nil), a.Events...)
	for i := range v.Events {
		e := &v.Events[i]
		e.Argv = append([]string(nil), e.Argv...)
		for _, p := range []**int{&e.UID, &e.AUID} {
			if *p != nil {
				n := **p
				*p = &n
			}
		}
		if e.Success != nil {
			b := *e.Success
			e.Success = &b
		}
	}
	return &v
}
