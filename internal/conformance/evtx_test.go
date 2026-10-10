package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	evtx "www.velocidex.com/golang/evtx"

	"github.com/aoiflux/fsagen/libgen"
)

// readVelocidex parses a log with Velocidex's evtx, the parser Velociraptor
// uses, and returns each record's event as JSON-shaped maps.
func readVelocidex(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	chunks, err := evtx.GetChunks(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("velocidex evtx: %v", err)
	}
	var out []map[string]any
	for _, c := range chunks {
		records, err := c.Parse(0)
		if err != nil {
			t.Fatalf("velocidex evtx, chunk at %d: %v", c.Offset, err)
		}
		for _, r := range records {
			b, err := json.Marshal(r.Event)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m["Event"].(map[string]any))
		}
	}
	return out
}

// at walks a path of keys through nested maps.
func at(m map[string]any, path ...string) any {
	var v any = m
	for _, k := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

// TestEvtxReadByVelocidex: Velocidex's evtx reads a generated log and finds
// each event's provider, id, record id, time, process, channel and computer,
// and every data value under its name, EventData and UserData alike.
func TestEvtxReadByVelocidex(t *testing.T) {
	when := time.Date(2024, 3, 15, 9, 30, 12, 0, time.UTC)
	logon, _ := libgen.EvtxBuiltins(4624)
	logon.Event.Time, logon.Event.ProcessID, logon.Event.ThreadID = when, 724, 1408
	for i, f := range logon.Event.Fields {
		switch f.Name {
		case "TargetUserName":
			logon.Event.Fields[i].Value = "alice"
		case "LogonType":
			logon.Event.Fields[i].Value = "10"
		case "TargetLogonId":
			logon.Event.Fields[i].Value = "0x3e7"
		}
	}
	cleared, _ := libgen.EvtxBuiltins(1102)
	cleared.Event.Time, cleared.Event.ProcessID, cleared.Event.ThreadID = when.Add(time.Hour), 1180, 4412
	cleared.Event.Fields[1].Value = "alice"
	data, err := libgen.BuildEvtx(libgen.EvtxSpec{Channel: "Security", Computer: "WS01", FirstRecordID: 40,
		Events: []libgen.EvtxEvent{logon.Event, cleared.Event}})
	if err != nil {
		t.Fatal(err)
	}
	events := readVelocidex(t, data)
	if len(events) != 2 {
		t.Fatalf("velocidex read %d events, want 2", len(events))
	}

	for i, want := range []struct {
		provider        string
		id, record, pid float64
		time            time.Time
	}{
		{"Microsoft-Windows-Security-Auditing", 4624, 40, 724, when},
		{"Microsoft-Windows-Eventlog", 1102, 41, 1180, when.Add(time.Hour)},
	} {
		e := events[i]
		got := fmt.Sprint(at(e, "System", "Provider", "Name"), at(e, "System", "EventID"), at(e, "System", "EventRecordID"),
			at(e, "System", "Execution", "ProcessID"), at(e, "System", "Channel"), at(e, "System", "Computer"))
		wantS := fmt.Sprint(want.provider, want.id, want.record, want.pid, "Security", "WS01")
		if got != wantS {
			t.Errorf("event %d: %s, want %s", i, got, wantS)
		}
		if ts, _ := at(e, "System", "TimeCreated", "SystemTime").(float64); int64(ts) != want.time.Unix() {
			t.Errorf("event %d: time %v, want %v", i, ts, want.time.Unix())
		}
	}

	values := map[string]any{}
	for _, d := range at(events[0], "EventData", "Data").([]any) {
		d := d.(map[string]any)
		values[d["Name"].(string)] = d["Value"]
	}
	if len(values) != len(logon.Event.Fields) || values["TargetUserName"] != "alice" || values["LogonType"] != 10.0 || values["TargetLogonId"] != 999.0 || values["SubjectUserSid"] != "S-1-0-0" {
		t.Errorf("4624 data %v", values)
	}
	if got := at(events[1], "UserData", "LogFileCleared", "SubjectUserName"); got != "alice" {
		t.Errorf("1102 SubjectUserName %v, want alice", got)
	}
}

// TestEvtxChunksReadByVelocidex: a log spanning several chunks, each
// defining its names and templates afresh, reads back whole and in order.
func TestEvtxChunksReadByVelocidex(t *testing.T) {
	proc, _ := libgen.EvtxBuiltins(4688)
	var events []libgen.EvtxEvent
	for i := range 600 {
		ev := proc.Event
		ev.Fields = append([]libgen.EvtxField(nil), proc.Event.Fields...)
		ev.Time = time.Date(2024, 3, 15, 9, 0, i, 0, time.UTC)
		ev.Fields[8].Value = "powershell.exe -enc " + strings.Repeat("QQBCAEMA", 1+i%40) // CommandLine
		events = append(events, ev)
	}
	data, err := libgen.BuildEvtx(libgen.EvtxSpec{Channel: "Security", Computer: "WS01", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	got := readVelocidex(t, data)
	if len(got) != len(events) {
		t.Fatalf("velocidex read %d of %d events", len(got), len(events))
	}
	for i, e := range got {
		if id := at(e, "System", "EventRecordID"); id != float64(i+1) {
			t.Fatalf("event %d has record id %v", i, id)
		}
	}
}
