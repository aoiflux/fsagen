package libgen

import (
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/prng"
)

// The bulk kinds a forensic examiner looks for first: a shortcut, a prefetch
// file, an event log, a user's registry hive, a login record, an audit log,
// and two Office documents with an inert macro. Each is built by the same
// builder its format uses, from the file's own stream, so a bulk corpus has
// the artefacts a scenario can write, with values a run of them could have.

// bulkUser is the account a bulk artefact names, drawn from its stream.
func bulkUser(s *prng.Stream) string { return "user" + strings.ToLower(s.Text(4)) }

// bulkComputer is the machine name a bulk artefact records.
func bulkComputer(s *prng.Stream) string { return "DESKTOP-" + s.Text(7) }

func genLnk(s *prng.Stream, start time.Time) ([]byte, error) {
	user := bulkUser(s)
	when := start.Add(-time.Duration(1+s.IntN(30*24)) * time.Hour)
	return BuildLNK(LNKSpec{
		Target:       `C:\Users\` + user + `\Documents\` + s.Text(8) + `.docx`,
		WorkingDir:   `C:\Users\` + user + `\Documents`,
		VolumeSerial: uint32(s.Uint64()),
		MachineID:    bulkComputer(s),
		Created:      when, Accessed: start, Modified: when.Add(time.Hour),
		Size: int64(1024 + s.IntN(1<<20)),
	}, s)
}

// prefetchDir is where a bulk prefetch file's program lives. The name of
// the file carries the program's own, and the directory is fixed, so the
// file's content can be built from its name alone.
const prefetchDir = `C:\Users\Public\Downloads\`

// bulkPrefetchName is a prefetch file's name as Windows gives it: the
// program's name and its path hash.
func bulkPrefetchName(s *prng.Stream) string {
	name, err := PrefetchFileName(prefetchDir+s.Text(8)+".EXE", DefaultHarddiskVolume)
	if err != nil {
		return ""
	}
	return name
}

func genPrefetch(s *prng.Stream, start time.Time, file string) ([]byte, error) {
	exe, _, ok := strings.Cut(file, "-")
	if !ok {
		return nil, fmt.Errorf("%q is not named as a prefetch file", file)
	}
	runs := make([]time.Time, 1+s.IntN(3))
	for i := range runs {
		runs[i] = start.Add(-time.Duration(i*24+s.IntN(24)) * time.Hour)
	}
	version := PrefetchVersions[s.IntN(len(PrefetchVersions))]
	return BuildPrefetch(PrefetchSpec{
		Version:    version,
		Executable: prefetchDir + exe,
		RunCount:   uint32(len(runs) + s.IntN(10)),
		LastRuns:   runs,
		Volumes:    map[byte]PrefetchVolume{'C': {Serial: uint32(s.Uint64()), Created: start.AddDate(-2, 0, 0)}},
	}, s)
}

func genEvtx(s *prng.Stream, start time.Time) ([]byte, error) {
	logon, _ := EvtxBuiltins(4624)
	process, _ := EvtxBuiltins(4688)
	user, computer := bulkUser(s), bulkComputer(s)
	set := func(ev EvtxEvent, values map[string]string) EvtxEvent {
		for i, f := range ev.Fields {
			if v, ok := values[f.Name]; ok {
				ev.Fields[i].Value = v
			}
		}
		return ev
	}
	var events []EvtxEvent
	at := start
	for i := range 4 + s.IntN(8) {
		at = at.Add(time.Duration(1+s.IntN(600)) * time.Second)
		var ev EvtxEvent
		if i == 0 {
			ev = set(logon.Event, map[string]string{"TargetUserName": user, "TargetDomainName": computer, "LogonType": "2", "IpAddress": "127.0.0.1"})
		} else {
			fresh, _ := EvtxBuiltins(4688)
			ev = set(fresh.Event, map[string]string{"SubjectUserName": user, "SubjectDomainName": computer, "NewProcessName": `C:\Windows\System32\` + strings.ToLower(s.Text(6)) + `.exe`})
		}
		ev.Time, ev.ProcessID, ev.ThreadID = at, 4*uint32(100+s.IntN(1000)), 4*uint32(1+s.IntN(4000))
		events = append(events, ev)
	}
	return BuildEvtx(EvtxSpec{Channel: process.Channel, Computer: computer, FirstRecordID: uint64(1 + s.IntN(10000)), Events: events})
}

func genNTUser(s *prng.Stream, start time.Time) ([]byte, error) {
	user := bulkUser(s)
	run, err := RunKey("ntuser", []RunEntry{{Name: s.Text(8), Command: `C:\Users\` + user + `\AppData\Local\` + s.Text(6) + `.exe /background`}}, start)
	if err != nil {
		return nil, err
	}
	assist := UserAssistKeys([]UserAssist{
		{Path: `C:\Windows\System32\cmd.exe`, RunCount: uint32(1 + s.IntN(20)), FocusCount: uint32(s.IntN(20)), FocusTimeMs: uint32(s.IntN(600000)), LastRun: start.Add(-time.Hour)},
		{Path: `C:\Windows\notepad.exe`, RunCount: uint32(1 + s.IntN(20)), LastRun: start.Add(-2 * time.Hour)},
	}, start)
	return BuildHive(HiveSpec{FileName: `\??\C:\Users\` + user + `\ntuser.dat`, Modified: start, Keys: append([]RegKey{run}, assist...)})
}

func genWtmp(s *prng.Stream, start time.Time) ([]byte, error) {
	user, host := bulkUser(s), fmt.Sprintf("10.%d.%d.%d", s.IntN(256), s.IntN(256), 1+s.IntN(254))
	boot := start.Add(-time.Duration(1+s.IntN(48)) * time.Hour)
	login := boot.Add(time.Duration(1+s.IntN(60)) * time.Minute)
	records := []UtmpRecord{
		{Kind: "boot", User: "reboot", Line: "~", Host: "6.8.0-31-generic", Time: boot},
		{Kind: "login", User: user, Line: "pts/0", Host: host, PID: int32(1000 + s.IntN(30000)), Session: int32(1 + s.IntN(100)), Time: login},
		{Kind: "logout", Line: "pts/0", Time: login.Add(time.Duration(1+s.IntN(240)) * time.Minute)},
	}
	return BuildUtmp(records)
}

func genAudit(s *prng.Stream, start time.Time) ([]byte, error) {
	user := bulkUser(s)
	uid, session := uint32(1000+s.IntN(100)), uint32(1+s.IntN(100))
	at := start
	next := func() time.Time { at = at.Add(time.Duration(1+s.IntN(120)) * time.Second); return at }
	log := AuditLog{FirstSerial: uint64(100 + s.IntN(100000)), Events: []AuditEvent{
		{Kind: "auth", Time: next(), User: user, UID: 0, AUID: uid, Session: session, PID: uint32(1000 + s.IntN(30000)), Exe: "/usr/sbin/sshd", Addr: "10.0.0.5", Terminal: "ssh", Success: true},
		{Kind: "login", Time: next(), User: user, UID: 0, AUID: uid, Session: session, PID: uint32(1000 + s.IntN(30000)), Exe: "/usr/sbin/sshd", Addr: "10.0.0.5", Terminal: "/dev/pts/0", Success: true},
	}}
	for range 2 + s.IntN(4) {
		log.Events = append(log.Events, AuditEvent{
			Kind: "execve", Time: next(), User: user, UID: uid, AUID: uid, Session: session,
			PID: uint32(1000 + s.IntN(30000)), PPID: uint32(1000 + s.IntN(30000)),
			Exe: "/usr/bin/ls", Argv: []string{"ls", "-la", "/home/" + user}, Cwd: "/home/" + user, TTY: "pts0", Success: true,
		})
	}
	return BuildAuditLog(log, s)
}

// bulkMarker is the marker a bulk document's macro assigns: letters that are
// not hex digits, as a scenario's default marker is.
func bulkMarker(s *prng.Stream) string {
	b := s.Bytes(16)
	for i := range b {
		b[i] = "ghijklmnopqrstuv"[b[i]&15]
	}
	return "FSAGEN-VBA:" + string(b)
}

func genDocm(s *prng.Stream, start time.Time) ([]byte, error) {
	entries := VBAEntryPoints[VBAWord]
	vba, err := BuildVBAProject(VBASpec{Host: VBAWord, EntryPoint: entries[s.IntN(len(entries))], Marker: bulkMarker(s)}, s)
	if err != nil {
		return nil, err
	}
	return Docm(s.Text(constant.ContentLen), DocxMeta{Author: "fsagen", Created: start, Modified: start}, vba)
}

func genXlsm(s *prng.Stream, start time.Time) ([]byte, error) {
	entries := VBAEntryPoints[VBAExcel]
	vba, err := BuildVBAProject(VBASpec{Host: VBAExcel, EntryPoint: entries[s.IntN(len(entries))], Marker: bulkMarker(s)}, s)
	if err != nil {
		return nil, err
	}
	rows := make([]string, bulkLogLines)
	for i := range rows {
		rows[i] = s.Text(bulkTextLen)
	}
	return Xlsx(strings.Join(rows, "\n"), DocxMeta{Author: "fsagen", Created: start, Modified: start}, vba)
}
