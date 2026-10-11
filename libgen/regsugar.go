package libgen

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/libntfs"
)

// The registry artefacts a scenario most often wants, each as the keys and
// values Windows itself writes for it: autostart entries, Explorer's record
// of the programs a user started, and the trail a USB stick leaves in the
// SYSTEM hive.

// HiveKinds names the hive each well-known file name is, which decides where
// the artefacts above live in it.
var HiveKinds = map[string]string{
	"NTUSER.DAT": "ntuser", "USRCLASS.DAT": "usrclass", "SYSTEM": "system", "SOFTWARE": "software",
	"SAM": "sam", "SECURITY": "security", "DEFAULT": "default",
}

// HiveKind is the kind of hive a file name says it is, or "" for a name
// that says none.
func HiveKind(base string) string { return HiveKinds[strings.ToUpper(base)] }

// RunKeys is where each kind of hive keeps the programs Windows starts at
// logon.
var RunKeys = map[string]string{
	"ntuser":   `Software\Microsoft\Windows\CurrentVersion\Run`,
	"software": `Microsoft\Windows\CurrentVersion\Run`,
}

// RunEntry is one program started at logon.
type RunEntry struct{ Name, Command string }

// RunKey is the Run key of a hive of kind, holding the entries.
func RunKey(kind string, entries []RunEntry, written time.Time) (RegKey, error) {
	path, ok := RunKeys[kind]
	if !ok {
		return RegKey{}, fmt.Errorf("a Run key belongs in NTUSER.DAT or SOFTWARE, not a %s hive", or(kind, "generic"))
	}
	k := RegKey{Path: path, LastWritten: written}
	for _, e := range entries {
		k.Values = append(k.Values, RegValue{Name: e.Name, Type: 1, Data: utf16z(e.Command)})
	}
	return k, nil
}

// UserAssist is Explorer's record of one program or shortcut a user started.
type UserAssist struct {
	// Path is what was started: a program's Windows path, or a shortcut's
	// (.lnk) path, which Explorer records under its own GUID.
	Path                              string
	RunCount, FocusCount, FocusTimeMs uint32
	LastRun                           time.Time
}

// The UserAssist GUIDs of Windows 7 and later: programs, and shortcuts.
const (
	userAssistPrograms  = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
	userAssistShortcuts = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
)

// userAssistFolders are the known folders Explorer writes as their GUID at
// the start of a UserAssist name, longest prefix first.
var userAssistFolders = []struct{ prefix, guid string }{
	{`C:\Windows\System32\`, "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"},
	{`C:\Windows\SysWOW64\`, "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"},
	{`C:\Program Files (x86)\`, "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"},
	{`C:\Program Files\`, "{6D809377-6AF0-444B-8957-A3773F02200E}"},
	{`C:\Windows\`, "{F38BF404-1D43-42F2-9305-67DE0B28FC23}"},
}

// UserAssistKeys are the Count keys holding the entries, and the version
// value of each UserAssist GUID they are under.
func UserAssistKeys(entries []UserAssist, written time.Time) []RegKey {
	base := `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`
	byGUID := map[string]*RegKey{}
	var order []string
	for _, e := range entries {
		guid := userAssistPrograms
		if strings.HasSuffix(strings.ToLower(e.Path), ".lnk") {
			guid = userAssistShortcuts
		}
		k, ok := byGUID[guid]
		if !ok {
			k = &RegKey{Path: base + guid + `\Count`, LastWritten: written}
			byGUID[guid] = k
			order = append(order, guid)
		}
		k.Values = append(k.Values, RegValue{Name: rot13(userAssistName(e.Path)), Type: 3, Data: userAssistData(e)})
	}
	var out []RegKey
	for _, guid := range order {
		out = append(out, RegKey{Path: base + guid, LastWritten: written, Values: []RegValue{{Name: "Version", Type: 4, Data: []byte{5, 0, 0, 0}}}})
		out = append(out, *byGUID[guid])
	}
	return out
}

func userAssistName(p string) string {
	for _, f := range userAssistFolders {
		if len(p) > len(f.prefix) && strings.EqualFold(p[:len(f.prefix)], f.prefix) {
			return f.guid + `\` + p[len(f.prefix):]
		}
	}
	return p
}

// userAssistData is a UserAssist value as Windows 7 and later write it,
// 72 bytes: the run count at 4, focus count at 8, focus time at 12, ten
// unused ratios of -1, an unused -1, then the last run as a FILETIME at 60.
func userAssistData(e UserAssist) []byte {
	le := binary.LittleEndian
	b := make([]byte, 0, 72)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint32(b, e.RunCount)
	b = le.AppendUint32(b, e.FocusCount)
	b = le.AppendUint32(b, e.FocusTimeMs)
	for range 10 {
		b = le.AppendUint32(b, math.Float32bits(-1))
	}
	b = le.AppendUint32(b, 0xFFFFFFFF)
	b = le.AppendUint64(b, libntfs.TimeToFiletime(e.LastRun))
	return le.AppendUint32(b, 0)
}

// rot13 is how Explorer obscures UserAssist names: each Latin letter turned
// thirteen places.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// USBDevice is a USB mass-storage device as the SYSTEM hive remembers it.
type USBDevice struct {
	// Vendor, Product and Revision are the device's SCSI inquiry strings;
	// at most 8, 16 and 4 characters.
	Vendor, Product, Revision string
	// Serial is the device's serial number, which names its instance key.
	Serial string
	// FirstInstall, LastArrival and LastRemoval are the device's install,
	// connection and removal times; a zero LastRemoval is a device still
	// connected.
	FirstInstall, LastArrival, LastRemoval time.Time
}

// USBLimits are the longest vendor, product and revision a device reports.
var USBLimits = [3]int{8, 16, 4}

// CheckUSBDevice reports whether a device's strings fit the inquiry fields
// and the key names they become.
func CheckUSBDevice(d USBDevice) error {
	for i, f := range []struct{ name, val string }{{"vendor", d.Vendor}, {"product", d.Product}, {"revision", d.Revision}} {
		if f.val == "" || len(f.val) > USBLimits[i] || strings.ContainsAny(f.val, `\&`) || !isPrintableASCII(f.val) {
			return fmt.Errorf("%s %q: 1 to %d printable ASCII characters, no \\ or &", f.name, f.val, USBLimits[i])
		}
	}
	if d.Serial == "" || len(d.Serial) > 126 || strings.ContainsAny(d.Serial, `\& `) || !isPrintableASCII(d.Serial) {
		return fmt.Errorf("serial %q: printable ASCII with no space, \\ or &", d.Serial)
	}
	return nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// devpropKey is the property set Windows 8 and later keep a device's
// install, arrival and removal times in.
const devpropKey = "{83da6326-97a6-4088-9453-a1923f573b29}"

// USBStorKeys are a device's keys under the first control set's
// Enum\USBSTOR, as the disk driver's installation writes them, with its
// times as FILETIME device properties; and the Select key that tells a
// reader which control set is current.
func USBStorKeys(devs []USBDevice, written time.Time) ([]RegKey, error) {
	sz := func(name, v string) RegValue { return RegValue{Name: name, Type: 1, Data: utf16z(v)} }
	multi := func(name string, vs ...string) RegValue {
		var b []byte
		for _, v := range vs {
			b = append(b, utf16z(v)...)
		}
		return RegValue{Name: name, Type: 7, Data: append(b, 0, 0)}
	}
	dword := func(name string, v uint32) RegValue {
		return RegValue{Name: name, Type: 4, Data: binary.LittleEndian.AppendUint32(nil, v)}
	}
	keys := []RegKey{{Path: "Select", LastWritten: written, Values: []RegValue{
		dword("Current", 1), dword("Default", 1), dword("Failed", 0), dword("LastKnownGood", 1),
	}}}
	for i, d := range devs {
		if err := CheckUSBDevice(d); err != nil {
			return nil, err
		}
		pad := func(s string, n int) string { return s + strings.Repeat("_", n-len(s)) }
		under := func(s string) string { return strings.ReplaceAll(s, " ", "_") }
		v8, p16, r4 := pad(under(d.Vendor), 8), pad(under(d.Product), 16), pad(under(d.Revision), 4)
		device := fmt.Sprintf(`ControlSet001\Enum\USBSTOR\Disk&Ven_%s&Prod_%s&Rev_%s`, under(d.Vendor), under(d.Product), under(d.Revision))
		instance := device + `\` + d.Serial + "&0"
		sum := sha256.Sum256([]byte("container " + d.Serial))
		sum[6], sum[8] = sum[6]&0x0F|0x40, sum[8]&0x3F|0x80
		var container GUID
		copy(container[:], sum[:16])
		keys = append(keys, RegKey{Path: instance, LastWritten: d.LastArrival, Values: []RegValue{
			sz("DeviceDesc", "@disk.inf,%disk_devdesc%;Disk drive"),
			dword("Capabilities", 0x10),
			multi("HardwareID", `USBSTOR\Disk`+v8+p16+r4, `USBSTOR\Disk`+v8+p16, `USBSTOR\Disk`+v8, `USBSTOR\`+v8+p16+r4[:1], v8+p16+r4[:1], `USBSTOR\GenDisk`, "GenDisk"),
			multi("CompatibleIDs", `USBSTOR\Disk`, `USBSTOR\RAW`, "GenDisk"),
			sz("ContainerID", strings.ToLower(container.String())),
			dword("ConfigFlags", 0),
			sz("ClassGUID", "{4d36e967-e325-11ce-bfc1-08002be10318}"),
			sz("Driver", fmt.Sprintf(`{4d36e967-e325-11ce-bfc1-08002be10318}\%04d`, i+1)),
			sz("Class", "DiskDrive"),
			sz("Mfg", "@disk.inf,%genmanufacturer%;(Standard disk drives)"),
			sz("Service", "disk"),
			sz("FriendlyName", d.Vendor+" "+d.Product+" USB Device"),
		}})
		props := []struct {
			id   string
			when time.Time
		}{{"0064", d.FirstInstall}, {"0065", d.FirstInstall}, {"0066", d.LastArrival}, {"0067", d.LastRemoval}}
		for _, p := range props {
			if p.when.IsZero() {
				continue
			}
			keys = append(keys, RegKey{Path: instance + `\Properties\` + devpropKey + `\` + p.id, LastWritten: p.when, Values: []RegValue{
				// A device property's type is DEVPROP_TYPE_FILETIME (0x10) in
				// the high-word form the registry stores properties with.
				{Name: "", Type: 0xFFFF0010, Data: binary.LittleEndian.AppendUint64(nil, libntfs.TimeToFiletime(p.when))},
			}})
		}
	}
	return keys, nil
}

// MergeRegKeys joins keys that name the same path, in any case: their
// values in the order given, the latest of their times. Two values of one
// name are left for BuildHive to refuse.
func MergeRegKeys(keys []RegKey) []RegKey {
	var out []RegKey
	for _, k := range keys {
		i := slices.IndexFunc(out, func(o RegKey) bool {
			return regCompare(strings.Trim(o.Path, `\`), strings.Trim(k.Path, `\`)) == 0
		})
		if i < 0 {
			out = append(out, k)
			continue
		}
		out[i].Values = append(slices.Clone(out[i].Values), k.Values...)
		if k.LastWritten.After(out[i].LastWritten) {
			out[i].LastWritten = k.LastWritten
		}
	}
	return out
}
