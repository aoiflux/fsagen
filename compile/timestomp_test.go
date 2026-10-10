package compile

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/model"
)

// The $FILE_NAME times follow NTFS: born with the object, left alone by
// writes, by explicit times and by mace, copied from the object's own times
// when it is renamed, and set otherwise only by a timestomp's fn_ times.
// The rename rule is what makes the double-rename trick work: stomp, then
// rename, and both sets agree.
func TestFileNameTimeRules(t *testing.T) {
	p, err := load(t, ModePlaybook, pbHead+`  - { actor: u, offset: 1m, actions: [ { action: create, path: a.txt, content: x, crtime: "2019-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 2m, actions: [ { action: update, path: a.txt, content: y } ] }
  - { actor: u, offset: 3m, actions: [ { action: mace, path: a.txt, crtime: "2018-01-01T00:00:00Z", mtime: "2018-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 4m, actions: [ { action: timestomp, path: a.txt, fn_crtime: "2017-01-01T00:00:00Z" } ] }
  - { actor: u, offset: 5m, actions: [ { action: rename, path: a.txt, new_path: b.txt } ] }
  - { actor: u, offset: 6m, actions: [ { action: copy, path: b.txt, new_path: c.txt } ] }
`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	at := func(min int) time.Time { return time.Date(2026, 3, 11, 9, min, 0, 0, time.UTC) }
	y2017 := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	y2018 := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)

	stomp := p.Ops[3]
	if want := (model.Times{Atime: at(1), Mtime: at(1), Ctime: at(1), Btime: y2017}); stomp.FN != want {
		t.Errorf("$FILE_NAME times after the timestomp = %+v, want %+v (born at 09:01, only fn_crtime set)", stomp.FN, want)
	}
	if want := (model.Times{Atime: at(2), Mtime: y2018, Ctime: at(2), Btime: y2018}); stomp.Times != want {
		t.Errorf("times after a timestomp with no $STANDARD_INFORMATION fields = %+v, want %+v", stomp.Times, want)
	}

	renamed := p.Model.Name("home/b.txt")
	if want := (model.Times{Atime: at(2), Mtime: y2018, Ctime: at(5), Btime: y2018}); renamed.Obj.Times != want || renamed.FN != want {
		t.Errorf("after the rename: times %+v, $FILE_NAME %+v, want both %+v", renamed.Obj.Times, renamed.FN, want)
	}
	if c := p.Model.Name("home/c.txt"); c.FN != model.All(at(6)) {
		t.Errorf("a copy's $FILE_NAME times = %+v, want all 09:06", c.FN)
	}
}

// A timestomp names the times it sets, every one of them a valid time, on a
// file that exists; mace takes no $FILE_NAME times.
func TestTimestompFields(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"  - { action: timestomp, path: a.txt }\n", "timestomp needs at least one of atime, mtime, ctime, crtime, fn_atime"},
		{"  - { action: timestomp, path: a.txt, fn_crtime: yesterday }\n", `"yesterday" is not an RFC 3339 time`},
		{"  - { action: mace, path: a.txt, fn_crtime: 2020-01-01T00:00:00Z }\n", "does not apply to mace"},
		{"  - { action: timestomp, path: b.txt, fn_crtime: 2020-01-01T00:00:00Z }\n", "timestomp: b.txt does not exist"},
	} {
		mustFail(t, ModeManifest, "operations:\n  - { action: create, path: a.txt, content: x }\n"+tc.body, tc.want)
	}
}

// No live volume lets a program set a $FILE_NAME time, so one is a
// pre-flight error naming the field, or with skip is dropped and recorded;
// the $STANDARD_INFORMATION half of the same timestomp still runs.
func TestFileNameTimesPreflight(t *testing.T) {
	body := "operations:\n  - { action: create, path: a.txt, content: x }\n  - action: timestomp\n    path: a.txt\n    mtime: 2020-01-01T00:00:00Z\n    fn_mtime: 2020-01-01T00:00:00Z\n    fn_crtime: 2020-01-01T00:00:00Z\n"
	windows := Caps{NamedStreams: true, BirthTime: true, ChangeTime: true}

	p, err := load(t, ModeManifest, body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = Preflight(p, windows, false)
	if err == nil {
		t.Fatal("a $FILE_NAME time passed pre-flight on a live volume")
	}
	for _, want := range []string{"input.yaml:6:5", "fn_mtime", "$FILE_NAME modification time cannot be set on a live volume", "input.yaml:7:5", "$FILE_NAME creation time"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "input.yaml:5:5") {
		t.Errorf("the $STANDARD_INFORMATION mtime was refused too:\n%v", err)
	}

	p, _ = load(t, ModeManifest, body, Options{})
	if err := Preflight(p, windows, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Ops[1].Dropped, ","); got != "fn_mtime,fn_crtime" || p.Ops[1].Skip != "" {
		t.Errorf("dropped %q, skip %q", got, p.Ops[1].Skip)
	}

	p, _ = load(t, ModeManifest, body, Options{})
	windows.FilenameTimes = true
	if err := Preflight(p, windows, false); err != nil {
		t.Errorf("a target that sets $FILE_NAME times: %v", err)
	}
}

// The dry-run listing shows the $FILE_NAME times a timestomp intends, and
// only a timestomp's line has them.
func TestDryRunListsFileNameTimes(t *testing.T) {
	p, err := load(t, ModeManifest, "start: 2026-03-11T09:00:00Z\noperations:\n  - { action: create, path: a.txt, content: x }\n  - { action: timestomp, path: a.txt, fn_crtime: 2017-01-01T00:00:00Z }\n", Options{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := WriteDryRun(&b, p); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	want := `"fn_times":{"atime":"2026-03-11T09:00:00Z","mtime":"2026-03-11T09:00:00Z","ctime":"2026-03-11T09:00:00Z","crtime":"2017-01-01T00:00:00Z"}`
	if len(lines) != 2 || strings.Contains(lines[0], "fn_times") || !strings.Contains(lines[1], want) {
		t.Errorf("listing:\n%s\nwant the second line to carry %s", b.String(), want)
	}
}
