package compile

import (
	"cmp"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// RegistryKeys turns a registry block into the keys of the hive it
// describes: the keys it lists and the ones its artefacts expand to, merged
// where they share a path. kind is the hive the file is (libgen.HiveKind of
// its name); the artefacts each need the hive they live in. Times the block
// leaves out are when. Compile runs it to check a block, the executor to
// build the hive, so the two cannot disagree.
func RegistryKeys(r *spec.RegistrySpec, kind string, when time.Time) ([]libgen.RegKey, error) {
	at := func(field, value string) (time.Time, error) {
		if strings.TrimSpace(value) == "" {
			return when, nil
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
		if err != nil {
			return time.Time{}, fmt.Errorf("%s: %q is not an RFC 3339 time", field, value)
		}
		if t.Before(libgen.MinFiletime) || t.After(libgen.MaxFiletime) {
			return time.Time{}, fmt.Errorf("%s: %s is outside what a FILETIME holds", field, value)
		}
		return t, nil
	}
	var keys []libgen.RegKey
	for i, k := range r.Keys {
		where := fmt.Sprintf("keys[%d]", i)
		if _, err := libgen.SplitRegPath(k.Path); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		written, err := at(where+".last_written", k.LastWritten)
		if err != nil {
			return nil, err
		}
		key := libgen.RegKey{Path: k.Path, LastWritten: written}
		for j, v := range k.Values {
			code, data, err := libgen.ParseRegValue(cmp.Or(v.Type, "REG_SZ"), v.Data, v.Strings)
			if err != nil {
				return nil, fmt.Errorf("%s.values[%d] (%q): %w", where, j, v.Name, err)
			}
			key.Values = append(key.Values, libgen.RegValue{Name: v.Name, Type: code, Data: data})
		}
		keys = append(keys, key)
	}
	if len(r.Run) > 0 {
		var entries []libgen.RunEntry
		for i, e := range r.Run {
			if strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Command) == "" {
				return nil, fmt.Errorf("run[%d] needs a name and a command", i)
			}
			entries = append(entries, libgen.RunEntry{Name: e.Name, Command: e.Command})
		}
		k, err := libgen.RunKey(kind, entries, when)
		if err != nil {
			return nil, fmt.Errorf("run: %w", err)
		}
		keys = append(keys, k)
	}
	if len(r.UserAssist) > 0 {
		if kind != "ntuser" {
			return nil, fmt.Errorf("userassist belongs in NTUSER.DAT, not a %s hive", hiveName(kind))
		}
		var entries []libgen.UserAssist
		for i, e := range r.UserAssist {
			where := fmt.Sprintf("userassist[%d]", i)
			if err := libgen.CheckWindowsPath(e.Path); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			for _, n := range []struct {
				key string
				val int
			}{{"run_count", e.RunCount}, {"focus_count", e.FocusCount}, {"focus_time_ms", e.FocusTimeMs}} {
				if n.val < 0 || int64(n.val) > 0xFFFFFFFF {
					return nil, fmt.Errorf("%s: %s %d does not fit 32 bits", where, n.key, n.val)
				}
			}
			last, err := at(where+".last_run", e.LastRun)
			if err != nil {
				return nil, err
			}
			runs := e.RunCount
			if runs == 0 {
				runs = 1
			}
			entries = append(entries, libgen.UserAssist{Path: e.Path, RunCount: uint32(runs), FocusCount: uint32(e.FocusCount), FocusTimeMs: uint32(e.FocusTimeMs), LastRun: last})
		}
		keys = append(keys, libgen.UserAssistKeys(entries, when)...)
	}
	if len(r.USBStor) > 0 {
		if kind != "system" {
			return nil, fmt.Errorf("usbstor belongs in SYSTEM, not a %s hive", hiveName(kind))
		}
		var devs []libgen.USBDevice
		for i, d := range r.USBStor {
			where := fmt.Sprintf("usbstor[%d]", i)
			dev := libgen.USBDevice{Vendor: d.Vendor, Product: d.Product, Revision: d.Revision, Serial: d.Serial}
			var err error
			if dev.FirstInstall, err = at(where+".first_install", d.FirstInstall); err != nil {
				return nil, err
			}
			if dev.LastArrival, err = at(where+".last_arrival", d.LastArrival); err != nil {
				return nil, err
			}
			if strings.TrimSpace(d.LastRemoval) != "" {
				if dev.LastRemoval, err = at(where+".last_removal", d.LastRemoval); err != nil {
					return nil, err
				}
			}
			if err := libgen.CheckUSBDevice(dev); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			devs = append(devs, dev)
		}
		usb, err := libgen.USBStorKeys(devs, when)
		if err != nil {
			return nil, err
		}
		keys = append(keys, usb...)
	}
	return libgen.MergeRegKeys(keys), nil
}

func hiveName(kind string) string {
	if kind == "" {
		return "generic"
	}
	return kind
}

// checkRegistry validates a registry block by building the hive it
// describes, so every key, value and artefact is checked as it will be
// written. Which hive the file is comes from its name; an update by ref has
// no name yet, and its artefacts are checked when it runs.
func checkRegistry(op *Op, at func(string, string, ...any)) {
	kind := ""
	if op.Path != "" {
		kind = libgen.HiveKind(path.Base(op.Path))
	} else if hasRegistryArtefacts(op.Registry) {
		return
	}
	keys, err := RegistryKeys(op.Registry, kind, time.Time{})
	if err != nil {
		at("registry", "%v", err)
		return
	}
	if _, err := libgen.BuildHive(libgen.HiveSpec{Keys: keys}); err != nil {
		at("registry", "%v", err)
	}
}

func hasRegistryArtefacts(r *spec.RegistrySpec) bool {
	return len(r.Run) > 0 || len(r.UserAssist) > 0 || len(r.USBStor) > 0
}

// cloneRegistry copies a registry block down to each key's values and each
// value's strings.
func cloneRegistry(r *spec.RegistrySpec) *spec.RegistrySpec {
	v := *r
	v.Keys = make([]spec.RegistryKey, len(r.Keys))
	for i, k := range r.Keys {
		k.Values = append([]spec.RegistryValue(nil), k.Values...)
		for j := range k.Values {
			k.Values[j].Strings = append([]string(nil), k.Values[j].Strings...)
		}
		v.Keys[i] = k
	}
	v.Run = append([]spec.RegistryRun(nil), r.Run...)
	v.UserAssist = append([]spec.RegistryUserAssist(nil), r.UserAssist...)
	v.USBStor = append([]spec.RegistryUSB(nil), r.USBStor...)
	return &v
}
