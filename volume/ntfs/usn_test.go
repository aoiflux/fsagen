package ntfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/libntfs"
)

// newJournaled is newVolume with the change journal on.
func newJournaled(t *testing.T, size int64, clusterSize int) testVolume {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "ntfs.img"))
	must(t, err)
	t.Cleanup(func() { f.Close() })
	must(t, f.Truncate(size))
	res := &volume.Tracker{}
	fsys, err := Format(volume.NewDevice(f, 0, size), Options{ClusterSize: clusterSize, Label: "test", Serial: 0x0123456789ABCDEF, Clock: clock, Alloc: volume.NextFit, Journal: true}, res)
	must(t, err)
	return testVolume{volume.New(fsys, res, f), fsys, f}
}

// journalOf reads the finished volume's change journal through libntfs,
// strict, as one line per record: the time, the name and the reasons.
func journalOf(t *testing.T, v testVolume) (*libntfs.Volume, []*libntfs.USNRecord, []string) {
	t.Helper()
	vol, err := libntfs.OpenWithOptions(v.file, libntfs.Options{ReadOnly: true, Strict: true})
	must(t, err)
	t.Cleanup(func() { vol.Close() })
	var recs []*libntfs.USNRecord
	var lines []string
	must(t, vol.EachUSNRecord(func(r *libntfs.USNRecord) error {
		recs = append(recs, r)
		lines = append(lines, fmt.Sprintf("%s %s %s", r.Timestamp.Format("15:04:05.000"), r.Name, strings.Join(r.ReasonNames(), "|")))
		return nil
	}))
	return vol, recs, lines
}

// The journal records each operation as Windows journals a handle: a record
// the first time each reason appears, then one that closes it, stamped with
// when the operation ran, whatever times it set. A delete shows only on
// close, and fsagen's own stamping, which brings a time to the scenario's,
// shows nowhere.
func TestChangeJournal(t *testing.T) {
	v := newJournaled(t, 8<<20, 0)
	at := func(m int) time.Time { return time.Date(2026, 3, 11, 9, m, 0, 500_000_000, time.UTC) }
	stomp := time.Date(2025, 11, 4, 10, 12, 0, 0, time.UTC)
	steps := []func() error{
		func() error { return v.WriteFile("d/a.exe", make([]byte, 5000), 0o644) },
		func() error { return v.SetTimes("d/a.exe", target.Times{Btime: stomp, Mtime: stomp}) },
		func() error {
			return v.WriteStream("d/a.exe", "Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n"))
		},
		func() error { return v.Rename("d/a.exe", "d/b.exe") },
		func() error {
			if err := v.WriteFile("d/tmp.txt", []byte("x"), 0o644); err != nil {
				return err
			}
			// The scenario's own times, stamped as fsagen stamps them.
			return v.SetTimes("d/tmp.txt", target.Times{Atime: at(5), Mtime: at(5), Ctime: at(5), Btime: at(5)})
		},
		func() error { return v.Remove("d/tmp.txt") },
		func() error { return v.WriteFile("d/b.exe", []byte("MZ"), 0o644) },
	}
	for i, step := range steps {
		v.BeginOp(i+1, at(i+1))
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i+1, err)
		}
	}
	v.BeginOp(0, time.Time{})
	// The settle pass after the last operation is not journaled.
	must(t, v.SetTimes("d/b.exe", target.Times{Atime: stomp}))
	_, err := v.Finish()
	must(t, err)

	vol, recs, got := journalOf(t, v)
	want := []string{
		"09:01:00.500 d FileCreate",
		"09:01:00.500 a.exe FileCreate",
		"09:01:00.500 a.exe FileCreate|DataExtend",
		"09:01:00.500 d FileCreate|Close",
		"09:01:00.500 a.exe FileCreate|DataExtend|Close",
		"09:02:00.500 a.exe BasicInfoChange",
		"09:02:00.500 a.exe BasicInfoChange|Close",
		"09:03:00.500 a.exe StreamChange",
		"09:03:00.500 a.exe NamedDataExtend|StreamChange",
		"09:03:00.500 a.exe NamedDataExtend|StreamChange|Close",
		"09:04:00.500 a.exe RenameOldName",
		"09:04:00.500 b.exe RenameOldName|RenameNewName",
		"09:04:00.500 b.exe RenameOldName|RenameNewName|Close",
		"09:05:00.500 tmp.txt FileCreate",
		"09:05:00.500 tmp.txt FileCreate|DataExtend",
		"09:05:00.500 tmp.txt FileCreate|DataExtend|Close",
		"09:06:00.500 tmp.txt FileDelete|Close",
		"09:07:00.500 b.exe DataTruncation",
		"09:07:00.500 b.exe DataExtend|DataTruncation",
		"09:07:00.500 b.exe DataExtend|DataTruncation|Close",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the journal:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Every record names its file and directory by reference, sequence
	// number and all; the deleted file's is the one it had.
	d, b := v.num(t, "d"), v.num(t, "d/b.exe")
	for _, r := range recs {
		if r.Name != "d" && r.ParentReference != uint64(d) {
			t.Errorf("%s: parent record %d, want %d", r.Name, r.ParentReference, d)
		}
		if r.MajorVersion != 2 || r.USN%8 != 0 || r.USN/usnPage != (r.USN+int64(usnHeader))/usnPage {
			t.Errorf("record at %d: version %d, or it is unaligned or crosses a page", r.USN, r.MajorVersion)
		}
	}
	if gone := recs[16]; gone.FileSequence != 1 || gone.IsDirectory() {
		t.Errorf("the delete names sequence %d (directory %v), want the file's 1", gone.FileSequence, gone.IsDirectory())
	}

	// A file's $STANDARD_INFORMATION keeps the USN of its last record.
	e, err := vol.GetMFTEntry(uint64(b))
	must(t, err)
	si, err := e.GetStandardInformation()
	must(t, err)
	if last := recs[len(recs)-1]; si.UpdateSequenceNum != uint64(last.USN) {
		t.Errorf("b.exe's $STANDARD_INFORMATION USN is %d, want its last record's %d", si.UpdateSequenceNum, last.USN)
	}

	// $Max holds the limits and the journal's ID, the time it was made.
	ext, err := vol.OpenPath("/$Extend/$UsnJrnl")
	must(t, err)
	mx, err := ext.OpenStream("$Max")
	must(t, err)
	limits, err := mx.ReadAll()
	must(t, err)
	if len(limits) != 32 || le.Uint64(limits) != usnMaxSize || le.Uint64(limits[8:]) != usnDelta || !libntfs.FiletimeToTime(le.Uint64(limits[16:])).Equal(clock) {
		t.Errorf("$Max = % x", limits)
	}
}

// Records fill $J page by page: one that would cross into the next 4 KiB
// starts it, and every record reads back.
func TestChangeJournalPages(t *testing.T) {
	v := newJournaled(t, 8<<20, 512)
	for i := range 120 {
		v.BeginOp(i+1, clock.Add(time.Duration(i)*time.Second))
		must(t, v.WriteFile(fmt.Sprintf("a-file-with-a-long-name-%03d.txt", i), []byte("x"), 0o644))
	}
	v.BeginOp(0, time.Time{})
	_, err := v.Finish()
	must(t, err)
	_, recs, _ := journalOf(t, v)
	if len(recs) != 3*120 {
		t.Fatalf("%d records, want 3 for each of 120 files", len(recs))
	}
	crossed := false
	for _, r := range recs {
		end := r.USN + int64(align8(usnHeader+2*len(r.Name)))
		if r.USN/usnPage != (end-1)/usnPage {
			t.Errorf("the record at %d crosses a page", r.USN)
		}
		crossed = crossed || r.USN >= usnPage
	}
	if !crossed {
		t.Error("the records fit one page, so the test proves nothing")
	}
}

// Without the journal, the volume has none, as one where it is off.
func TestNoChangeJournal(t *testing.T) {
	v := newVolume(t, 8<<20, 0, volume.NextFit)
	v.BeginOp(1, clock)
	must(t, v.WriteFile("a.txt", []byte("x"), 0o644))
	v.BeginOp(0, time.Time{})
	_, err := v.Finish()
	must(t, err)
	vol, err := libntfs.OpenWithOptions(v.file, libntfs.Options{ReadOnly: true, Strict: true})
	must(t, err)
	defer vol.Close()
	if _, err := vol.OpenUSNJournal(); !errors.Is(err, libntfs.ErrFileNotFound) {
		t.Errorf("OpenUSNJournal = %v, want no journal", err)
	}
}
