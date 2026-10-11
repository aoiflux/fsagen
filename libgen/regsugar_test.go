package libgen

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libntfs"
)

// TestUserAssistEncoding: a UserAssist entry is named as Explorer names it,
// the known folder as its GUID and every Latin letter ROT13'd, and its data
// is the 72-byte record RegRipper and Registry Explorer decode, with the run
// count at 4 and the last run at 60.
func TestUserAssistEncoding(t *testing.T) {
	when := time.Date(2024, 3, 15, 9, 30, 12, 0, time.UTC)
	keys := UserAssistKeys([]UserAssist{
		{Path: `C:\Windows\System32\cmd.exe`, RunCount: 4, FocusCount: 2, FocusTimeMs: 61000, LastRun: when},
		{Path: `C:\Users\alice\Desktop\tool.lnk`, RunCount: 1, LastRun: when},
		{Path: `E:\payload.exe`, RunCount: 1, LastRun: when},
	}, when)
	if len(keys) != 4 {
		t.Fatalf("%d keys, want a GUID key and a Count key for programs and for shortcuts", len(keys))
	}
	programs, shortcuts := keys[1], keys[3]
	if !strings.HasSuffix(programs.Path, userAssistPrograms+`\Count`) || !strings.HasSuffix(shortcuts.Path, userAssistShortcuts+`\Count`) {
		t.Errorf("Count keys %q and %q", programs.Path, shortcuts.Path)
	}
	if got := programs.Values[0].Name; got != `{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr` {
		t.Errorf("cmd.exe is named %q", got)
	}
	if got := programs.Values[1].Name; got != `R:\cnlybnq.rkr` {
		t.Errorf("a program outside a known folder is named %q", got)
	}
	if got := rot13(rot13(`C:\Users\alice`)); got != `C:\Users\alice` {
		t.Errorf("rot13 is not its own inverse: %q", got)
	}
	d := programs.Values[0].Data
	le := binary.LittleEndian
	if len(d) != 72 || le.Uint32(d[4:]) != 4 || le.Uint32(d[8:]) != 2 || le.Uint32(d[12:]) != 61000 ||
		math.Float32frombits(le.Uint32(d[16:])) != -1 || le.Uint64(d[60:]) != libntfs.TimeToFiletime(when) {
		t.Errorf("UserAssist data % x", d)
	}
}

// TestUSBStorKeys: a USB stick's keys sit where USBSTOR parsers look —
// Select, then ControlSet001\Enum\USBSTOR\Disk&Ven_&Prod_&Rev_\<serial>&0 —
// with its hardware ids padded as the driver writes them and its times as
// FILETIME device properties.
func TestUSBStorKeys(t *testing.T) {
	when := time.Date(2024, 3, 15, 9, 30, 12, 0, time.UTC)
	keys, err := USBStorKeys([]USBDevice{{Vendor: "SanDisk", Product: "Cruzer Blade", Revision: "1.00", Serial: "4C530001231117116491", FirstInstall: when, LastArrival: when}}, when)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Path != "Select" {
		t.Errorf("first key %q, want Select", keys[0].Path)
	}
	inst := keys[1]
	if inst.Path != `ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231117116491&0` {
		t.Errorf("instance key %q", inst.Path)
	}
	var hwid []byte
	for _, v := range inst.Values {
		if v.Name == "HardwareID" {
			hwid = v.Data
		}
	}
	if !strings.Contains(string(hwid), string(utf16le(`USBSTOR\DiskSanDisk_Cruzer_Blade____1.00`))) {
		t.Errorf("HardwareID lacks the padded id")
	}
	props := keys[2:]
	if len(props) != 3 || !strings.HasSuffix(props[0].Path, devpropKey+`\0064`) || props[2].Values[0].Type != 0xFFFF0010 ||
		binary.LittleEndian.Uint64(props[2].Values[0].Data) != libntfs.TimeToFiletime(when) {
		t.Errorf("properties %+v (a device still connected has no removal time)", props)
	}
	for _, bad := range []USBDevice{
		{Vendor: "TooLongVendor", Product: "P", Revision: "1", Serial: "S"},
		{Vendor: "V", Product: "P", Revision: "1", Serial: `A\B`},
		{Vendor: "V", Product: "P&Q", Revision: "1", Serial: "S"},
	} {
		if CheckUSBDevice(bad) == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

// TestMergeRegKeys: keys of one path in any case become one, with all their
// values and the latest time.
func TestMergeRegKeys(t *testing.T) {
	a := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	got := MergeRegKeys([]RegKey{
		{Path: `Software\Run`, LastWritten: a, Values: []RegValue{{Name: "x"}}},
		{Path: `Software\Other`},
		{Path: `software\RUN`, LastWritten: a.Add(time.Hour), Values: []RegValue{{Name: "y"}}},
	})
	if len(got) != 2 || len(got[0].Values) != 2 || !got[0].LastWritten.Equal(a.Add(time.Hour)) {
		t.Errorf("merged %+v", got)
	}
}
