package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestRegistryThroughManifest: hives built from a manifest are named for
// the file the base block says they were saved to, and hold what their
// blocks and artefacts say where each belongs: a Run entry and UserAssist in
// NTUSER.DAT, a USB stick under ControlSet001 in SYSTEM. libgen's tests,
// Windows itself and the conformance suite walk the hives in full.
func TestRegistryThroughManifest(t *testing.T) {
	root, _ := runManifest(t, `
start: 2024-03-15T09:00:00Z
variables:
  dropper: wupdmgr32
operations:
  - action: create
    path: C/Users/user1/NTUSER.DAT
    registry:
      run:
        - { name: SystemUpdate, command: 'C:\Users\user1\AppData\Local\Temp\${VAR:dropper}.exe' }
      userassist:
        - { path: 'C:\Windows\System32\cmd.exe', run_count: 3 }
      keys:
        - path: 'Software\Sysinternals\PsExec'
          values: [ { name: EulaAccepted, type: REG_DWORD, data: 1 } ]
  - action: create
    path: C/Windows/System32/config/SYSTEM
    registry:
      usbstor:
        - { vendor: Generic, product: Storage Unit, revision: '1.00', serial: 4C530001231117116491, last_removal: 2024-03-15T10:00:00Z }
`, nil)

	user := readOut(t, root, "C/Users/user1/NTUSER.DAT")
	le := binary.LittleEndian
	if string(user[:4]) != "regf" || le.Uint32(user[20:]) != 1 || le.Uint32(user[24:]) != 5 {
		t.Fatalf("not a version 1.5 hive: % x", user[:28])
	}
	if !bytes.Contains(user[48:112], utf16le(`Users\user1\NTUSER.DAT`)) {
		t.Errorf("the base block names %q", user[48:112])
	}
	for _, s := range [][]byte{
		[]byte("SystemUpdate"), utf16le(`C:\Users\user1\AppData\Local\Temp\wupdmgr32.exe`),
		[]byte(`{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr`), []byte("EulaAccepted"), []byte("Sysinternals"),
	} {
		if !bytes.Contains(user, s) {
			t.Errorf("NTUSER.DAT lacks %q", s)
		}
	}

	system := readOut(t, root, "C/Windows/System32/config/SYSTEM")
	for _, s := range [][]byte{
		[]byte("Select"), []byte("USBSTOR"), []byte("Disk&Ven_Generic&Prod_Storage_Unit&Rev_1.00"),
		[]byte("4C530001231117116491&0"), []byte("{83da6326-97a6-4088-9453-a1923f573b29}"), []byte("0067"),
	} {
		if !bytes.Contains(system, s) {
			t.Errorf("SYSTEM lacks %q", s)
		}
	}
}
