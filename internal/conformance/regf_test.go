package conformance

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/aoiflux/fsagen/libgen"
)

// TestHiveReadByRegparser: Velocidex's regparser, the parser Velociraptor
// uses, opens a generated hive, finds each key by path with its last-write
// time, reads every value's type and data, inline, in a cell and in
// big-data segments, and lists a key's subkeys through an index of hash
// leaves.
func TestHiveReadByRegparser(t *testing.T) {
	when := time.Date(2024, 3, 15, 9, 30, 12, 0, time.UTC)
	val := func(name, typ, data string, strs ...string) libgen.RegValue {
		code, b, err := libgen.ParseRegValue(typ, data, strs)
		if err != nil {
			t.Fatal(err)
		}
		return libgen.RegValue{Name: name, Type: code, Data: b}
	}
	large := make([]byte, 40000)
	for i := range large {
		large[i] = byte(i * 7)
	}
	run := libgen.RegKey{Path: `Software\Microsoft\Windows\CurrentVersion\Run`, LastWritten: when.Add(time.Hour), Values: []libgen.RegValue{
		val("Updater", "REG_SZ", `C:\Users\user1\AppData\Local\Temp\wupdmgr32.exe /silent`),
		val("Count", "REG_DWORD", "7"),
		val("Big", "REG_QWORD", "0x1122334455667788"),
		val("Five", "REG_BINARY", "0102030405"),
		val("Multi", "REG_MULTI_SZ", "", "a", "bc"),
		{Name: "Large", Type: 3, Data: large},
	}}
	keys := []libgen.RegKey{run}
	for i := range 600 {
		keys = append(keys, libgen.RegKey{Path: fmt.Sprintf(`Software\Many\K%03d`, i)})
	}
	keys = append(keys, libgen.UserAssistKeys([]libgen.UserAssist{{Path: `C:\Windows\System32\cmd.exe`, RunCount: 4, LastRun: when}}, when)...)
	data, err := libgen.BuildHive(libgen.HiveSpec{FileName: "NTUSER.DAT", Modified: when, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}

	reg, err := regparser.NewRegistry(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("regparser: %v", err)
	}
	key := reg.OpenKey(run.Path)
	if key == nil {
		t.Fatalf("regparser cannot open %s", run.Path)
	}
	if got := key.LastWriteTime().Time; !got.Equal(run.LastWritten) {
		t.Errorf("Run last written %v, want %v", got, run.LastWritten)
	}
	values := key.Values()
	if len(values) != len(run.Values) {
		t.Fatalf("regparser lists %d values, want %d", len(values), len(run.Values))
	}
	for i, v := range values {
		w := run.Values[i]
		d := v.ValueData()
		if v.ValueName() != w.Name || v.Type() != w.Type || d.Error != nil {
			t.Errorf("value %d: %q type %d (%v); want %q type %d", i, v.ValueName(), v.Type(), d.Error, w.Name, w.Type)
			continue
		}
		// regparser hands back all four bytes of an inline value, whatever
		// its size says.
		if !bytes.HasPrefix(d.Data, w.Data) || (len(w.Data) > 4 && len(d.Data) != len(w.Data)) {
			t.Errorf("value %q: %d bytes read, %d written", w.Name, len(d.Data), len(w.Data))
		}
	}
	// regparser keeps the NUL a REG_SZ is stored with, as Windows stores it.
	if d := values[0].ValueData(); strings.TrimSuffix(d.String, "\x00") != `C:\Users\user1\AppData\Local\Temp\wupdmgr32.exe /silent` {
		t.Errorf("Updater reads as %q", d.String)
	}
	if d := values[1].ValueData(); d.Uint64 != 7 {
		t.Errorf("Count reads as %d", d.Uint64)
	}
	if d := values[4].ValueData(); !slices.Equal(d.MultiSz, []string{"a", "bc"}) {
		t.Errorf("Multi reads as %q", d.MultiSz)
	}

	many := reg.OpenKey(`Software\Many`)
	if many == nil {
		t.Fatal(`regparser cannot open Software\Many`)
	}
	subs := many.Subkeys()
	if len(subs) != 600 || subs[0].Name() != "K000" || subs[599].Name() != "K599" {
		t.Errorf("Many lists %d subkeys", len(subs))
	}
	count := reg.OpenKey(`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`)
	if count == nil || len(count.Values()) != 1 || count.Values()[0].ValueName() != `{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr` {
		t.Error("the UserAssist entry for cmd.exe is not where RegRipper looks")
	}
}
