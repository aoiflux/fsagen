package ledger

import (
	"encoding/json"
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// The difference between two times is written exactly, whichever is
// earlier, down to the nanosecond, decades apart: a float would round away
// the ticks a FILETIME keeps.
func TestSecondsBetween(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"2026-03-11T09:00:00Z", "2026-03-11T09:00:00Z", "0"},
		{"2026-03-11T09:00:01Z", "2026-03-11T09:00:00Z", "1"},
		{"2026-03-11T09:00:00Z", "2026-03-11T09:00:01Z", "-1"},
		{"2026-03-11T09:00:00.5Z", "2026-03-11T09:00:01Z", "-0.5"},
		{"2026-03-11T09:00:01.25Z", "2026-03-11T09:00:00.5Z", "0.75"},
		{"2026-03-11T09:00:00.25Z", "2026-03-11T09:00:01.5Z", "-1.25"},
		{"1601-01-01T00:00:00.0000001Z", "2026-03-11T09:00:00Z", "-13417693199.9999999"},
		{"", "2026-03-11T09:00:00Z", ""},
	} {
		if got := secondsBetween(tc.a, tc.b); got != json.Number(tc.want) {
			t.Errorf("%s minus %s = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// A timestomp's fact carries both sets of times, how far apart they are,
// whether the creation times give it away, and whether the $FILE_NAME times
// are on disk at all; a mace's fact is what it always was.
func TestTimestompFact(t *testing.T) {
	si := Times{Atime: "2026-03-11T09:02:00Z", Mtime: "2018-01-01T00:00:00Z", Crtime: "2018-01-01T00:00:00Z"}
	fn := Times{Atime: "2026-03-11T09:01:00Z", Mtime: "2026-03-11T09:01:00Z", Ctime: "2026-03-11T09:01:00Z", Crtime: "2026-03-11T09:01:00Z"}
	e := Entry{
		N: 2, Action: spec.ActionTimestomp, Object: 1, Kind: "file", Path: "a.txt", Outcome: Done,
		Times: &si, FnTimes: &fn, Explicit: []string{"mtime", "crtime"},
		Uncontrolled: []string{"ctime", "fn_atime", "fn_mtime", "fn_ctime", "fn_crtime"},
	}
	facts := AnswerKey([]Entry{e}, nil)
	if len(facts) != 1 {
		t.Fatalf("facts = %+v", facts)
	}
	got := string(FactBytes(facts))
	want := `{"event":"stomped","n":2,"object":1,"kind":"file","path":"a.txt","times":{"atime":"2026-03-11T09:02:00Z","mtime":"2018-01-01T00:00:00Z","crtime":"2018-01-01T00:00:00Z"},"fields":["mtime","crtime"],"fn_times":{"atime":"2026-03-11T09:01:00Z","mtime":"2026-03-11T09:01:00Z","ctime":"2026-03-11T09:01:00Z","crtime":"2026-03-11T09:01:00Z"},"fn_controlled":false,"delta":{"atime":60,"mtime":-258454860,"crtime":-258454860},"timestomp_detected":true}` + "\n"
	if got != want {
		t.Errorf("fact =\n%s\nwant\n%s", got, want)
	}

	// Where the target sets them, the same stomp seen from a $FILE_NAME
	// that agrees is not detected.
	e.Uncontrolled = []string{"ctime"}
	e.FnTimes = &si
	f := AnswerKey([]Entry{e}, nil)[0]
	if f.FnControlled == nil || !*f.FnControlled || f.TimestompDetected == nil || *f.TimestompDetected {
		t.Errorf("controlled %v, detected %v", f.FnControlled, f.TimestompDetected)
	}

	e.Action, e.FnTimes = spec.ActionMACE, nil
	f = AnswerKey([]Entry{e}, nil)[0]
	if f.FnControlled != nil || f.Delta != nil || f.TimestompDetected != nil {
		t.Errorf("a mace's fact carries $FILE_NAME facts: %+v", f)
	}
}
