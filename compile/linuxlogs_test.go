package compile

import (
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestLinuxLogBlockRules: wtmp, utmp and btmp are login records by name and
// audit.log an audit log; each needs its block and takes no filler; btmp
// holds failed logins only; a record names its user where it needs one;
// and what a struct utmp or an audit record cannot hold is refused.
func TestLinuxLogBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+
		"    path: var/log/wtmp\n    utmp: { records: [ { type: boot }, { type: login, user: alice, host: 203.0.113.7 } ] }\n"+
		"  - action: create\n    path: var/log/btmp\n    utmp: { records: [ { type: failed, user: root } ] }\n"+
		"  - action: create\n    path: var/log/audit/audit.log\n    auditd: { events: [ { type: execve, user: alice, argv: [curl, -o, /tmp/x] } ] }\n")
	for i, want := range []spec.Format{spec.FormatUtmp, spec.FormatUtmp, spec.FormatAuditd} {
		if got := p.Ops[i].Format; got != want {
			t.Errorf("op %d (%s): format %q, want %q", i, p.Ops[i].Path, got, want)
		}
	}

	for _, tc := range []struct{ name, body, want string }{
		{"no utmp block", "    path: var/log/wtmp\n", "needs a utmp block"},
		{"no auditd block", "    path: audit.log\n", "needs an auditd block"},
		{"filler", "    path: wtmp\n    content_len: 384\n    utmp: { records: [ { type: boot } ] }\n", "no region for filler"},
		{"login in btmp", "    path: btmp\n    utmp: { records: [ { type: login, user: a } ] }\n", "btmp keeps failed logins only"},
		{"failed in wtmp", "    path: wtmp\n    utmp: { records: [ { type: failed, user: a } ] }\n", "kept in btmp"},
		{"no user", "    path: wtmp\n    utmp: { records: [ { type: login } ] }\n", "names its user"},
		{"kind", "    path: wtmp\n    utmp: { records: [ { type: reboot } ] }\n", "type \"reboot\""},
		{"2038", "    path: wtmp\n    utmp: { records: [ { type: boot, time: '2038-01-19T03:14:08Z' } ] }\n", "2038"},
		{"long user", "    path: wtmp\n    utmp: { records: [ { type: login, user: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa } ] }\n", "a utmp record holds 32"},
		{"negative pid", "    path: wtmp\n    utmp: { records: [ { type: login, user: a, pid: -1 } ] }\n", "not negative"},
		{"no events", "    path: audit.log\n    auditd: { first_serial: 5 }\n", "at least one event"},
		{"audit kind", "    path: audit.log\n    auditd: { events: [ { type: open, user: a } ] }\n", "type \"open\""},
		{"no program", "    path: audit.log\n    auditd: { events: [ { type: execve, user: a } ] }\n", "needs the program"},
		{"relative exe", "    path: audit.log\n    auditd: { events: [ { type: execve, user: a, exe: curl } ] }\n", "absolute path"},
		{"audit no user", "    path: audit.log\n    auditd: { events: [ { type: login } ] }\n", "names its user"},
		{"big uid", "    path: audit.log\n    auditd: { events: [ { type: login, user: a, uid: 4294967296 } ] }\n", "uid"},
		{"audit time", "    path: audit.log\n    auditd: { events: [ { type: login, user: a, time: then } ] }\n", "events[0].time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
