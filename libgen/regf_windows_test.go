//go:build windows

package libgen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestHiveLoadedByWindows: Windows' own registry loads a generated hive as
// an application hive, which any user may do, and finds every key with its
// last-write time and every value with its type and data. Loading checks the
// base block, the bins and the cells, so a hive Windows considers damaged is
// refused here rather than read.
func TestHiveLoadedByWindows(t *testing.T) {
	load := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegLoadAppKeyW")
	if load.Find() != nil {
		t.Skip("advapi32 has no RegLoadAppKeyW")
	}
	spec := sampleHiveSpec()
	data, err := BuildHive(spec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "NTUSER.DAT")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := syscall.UTF16PtrFromString(path)
	var h syscall.Handle
	if r, _, _ := load.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&h)), uintptr(registry.READ), 0, 0); r != 0 {
		t.Fatalf("Windows refused the hive: %v", syscall.Errno(r))
	}
	root := registry.Key(h)
	defer root.Close()

	for _, k := range spec.Keys {
		key, err := registry.OpenKey(root, k.Path, registry.READ)
		if err != nil {
			t.Errorf("open %s: %v", k.Path, err)
			continue
		}
		info, err := key.Stat()
		if err != nil {
			t.Fatal(err)
		}
		want := k.LastWritten
		if want.IsZero() {
			want = spec.Modified
		}
		if !info.ModTime().Equal(want) {
			t.Errorf("%s last written %v, want %v", k.Path, info.ModTime().UTC(), want)
		}
		names, err := key.ReadValueNames(-1)
		if err != nil {
			t.Fatal(err)
		}
		if len(names) != len(k.Values) {
			t.Errorf("%s: Windows lists %d values, want %d", k.Path, len(names), len(k.Values))
		}
		for _, v := range k.Values {
			buf := make([]byte, len(v.Data)+16)
			n, typ, err := key.GetValue(v.Name, buf)
			if errors.Is(err, windows.ERROR_MORE_DATA) {
				t.Errorf("%s\\%s: %d bytes, more than the %d written", k.Path, v.Name, n, len(v.Data))
				continue
			}
			if err != nil {
				t.Errorf("%s\\%s: %v", k.Path, v.Name, err)
				continue
			}
			if typ != v.Type || !bytes.Equal(buf[:n], v.Data) {
				t.Errorf("%s\\%s: type %d, %d bytes; want type %d, %d bytes", k.Path, v.Name, typ, n, v.Type, len(v.Data))
			}
		}
		key.Close()
	}
	sw, err := registry.OpenKey(root, `Software`, registry.READ)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	subs, _ := sw.ReadSubKeyNames(-1)
	if len(subs) != 7 {
		t.Errorf("Software has subkeys %q, want 7", subs)
	}
}
