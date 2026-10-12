package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestEvtxThroughManifest: a log built from a manifest is a well-formed
// event log holding each event, with the block's values in its records and
// the seed's computer name where the block names none. libgen's tests,
// Windows itself and the conformance suite read the records in full.
func TestEvtxThroughManifest(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
variables:
  user: user1
operations:
  - action: create
    path: Windows/System32/winevt/Logs/Security.evtx
    evtx:
      computer: WS01
      first_record_id: 7000
      events:
        - event_id: 4624
          time: 2024-03-15T08:59:00Z
          data: { TargetUserName: '${VAR:user}', LogonType: 10, IpAddress: 203.0.113.7 }
        - event_id: 1102
          data: { SubjectUserName: '${VAR:user}' }
  - action: create
    path: logs/app.evtx
    evtx:
      events:
        - event_id: 1000
          provider: Application Error
          level: 2
          data: { AppName: dropper.exe }
`, nil)

	sec := readOut(t, root, "Windows/System32/winevt/Logs/Security.evtx")
	le := binary.LittleEndian
	if string(sec[:8]) != "ElfFile\x00" || le.Uint16(sec[42:]) != 1 || le.Uint64(sec[24:]) != 7002 {
		t.Fatalf("header: % x, %d chunks, next record id %d; want one chunk and 7002", sec[:8], le.Uint16(sec[42:]), le.Uint64(sec[24:]))
	}
	chunk := sec[4096:]
	if first, last := le.Uint64(chunk[24:]), le.Uint64(chunk[32:]); first != 7000 || last != 7001 {
		t.Errorf("chunk records %d to %d, want 7000 to 7001", first, last)
	}
	for _, s := range []string{"WS01", "user1", "203.0.113.7", "Security", "LogFileCleared"} {
		if !bytes.Contains(sec, utf16le(s)) {
			t.Errorf("%q is not in the log", s)
		}
	}

	app := readOut(t, root, "logs/app.evtx")
	for _, s := range []string{"Application Error", "dropper.exe", "AppName", "Application", "DESKTOP-"} {
		if !bytes.Contains(app, utf16le(s)) {
			t.Errorf("%q is not in the application log", s)
		}
	}
}

// TestEvtxRepeatedRendersEachTime: an action a step repeats renders its
// event data afresh each time, into a map of its own, so ${ITER} differs from
// log to log rather than the first rendering being shared.
func TestEvtxRepeatedRendersEachTime(t *testing.T) {
	root, _ := runRes(t, `
start: 2024-03-15T09:00:00Z
actors:
  - name: system
    base: Windows
steps:
  - actor: system
    offset: 0s
    repeat: 2
    every: 1m
    actions:
      - action: create
        path: logs/run-${ITER}.evtx
        evtx:
          events:
            - event_id: 7045
              data: { ServiceName: 'svc-${ITER}', ImagePath: 'C:\Temp\svc-${ITER}.exe' }
`)
	for _, iter := range []string{"0", "1"} {
		log := readOut(t, root, "Windows/logs/run-"+iter+".evtx")
		if !bytes.Contains(log, utf16le("svc-"+iter)) {
			t.Errorf("run-%s.evtx does not name svc-%s", iter, iter)
		}
		other := map[string]string{"0": "svc-1", "1": "svc-0"}[iter]
		if bytes.Contains(log, utf16le(other)) {
			t.Errorf("run-%s.evtx names %s, another iteration's service", iter, other)
		}
	}
}
