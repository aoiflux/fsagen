//go:build windows && (amd64 || arm64)

package libgen

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/aoiflux/fsagen/prng"
)

// Windows' own structured storage (ole32's StgOpenStorageEx, which needs no
// privilege) is the ground truth for a compound file: the code every Office
// release reads one with.

var procStgOpenStorageEx = windows.NewLazySystemDLL("ole32.dll").NewProc("StgOpenStorageEx")

const (
	stgmReadShareExclusive = 0x00000010 // STGM_READ | STGM_SHARE_EXCLUSIVE
	stgfmtDocfile          = 5
	stgtyStorage           = 1
	stgtyStream            = 2
)

var iidIStorage = windows.GUID{Data1: 0x0000000B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}

// statstg is STATSTG, laid out as on 64-bit Windows.
type statstg struct {
	name                *uint16
	kind                uint32
	size                uint64
	mtime, ctime, atime windows.Filetime
	mode, locks         uint32
	clsid               windows.GUID
	state, reserved     uint32
}

// comCall calls method number m of the COM object obj.
func comCall(obj unsafe.Pointer, m int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, m*int(unsafe.Sizeof(uintptr(0)))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

// IStorage, IEnumSTATSTG and IStream methods, by vtable slot.
const (
	comRelease          = 2
	storageOpenStream   = 4
	storageOpenStorage  = 6
	storageEnumElements = 11
	enumNext            = 3
	streamRead          = 3
)

// readStorage reads every stream under stg by its path.
func readStorage(stg unsafe.Pointer, dir string, out map[string][]byte) error {
	var enum unsafe.Pointer
	if hr := comCall(stg, storageEnumElements, 0, 0, 0, uintptr(unsafe.Pointer(&enum))); hr != 0 {
		return fmt.Errorf("EnumElements %s: %#x", dir, hr)
	}
	defer comCall(enum, comRelease)
	for {
		var st statstg
		var fetched uint32
		if hr := comCall(enum, enumNext, 1, uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&fetched))); hr != 0 || fetched == 0 {
			return nil
		}
		name := windows.UTF16PtrToString(st.name)
		p := name
		if dir != "" {
			p = dir + "/" + name
		}
		var err error
		switch st.kind {
		case stgtyStorage:
			err = withChild(stg, storageOpenStorage, st.name, func(child unsafe.Pointer) error { return readStorage(child, p, out) })
		case stgtyStream:
			err = withChild(stg, storageOpenStream, st.name, func(s unsafe.Pointer) error {
				data, err := readStream(s, st.size)
				out[p] = data
				return err
			})
		}
		windows.CoTaskMemFree(unsafe.Pointer(st.name))
		if err != nil {
			return err
		}
	}
}

// withChild opens the storage or stream name under stg and hands it to use.
func withChild(stg unsafe.Pointer, method int, name *uint16, use func(unsafe.Pointer) error) error {
	var child unsafe.Pointer
	var hr uintptr
	if method == storageOpenStorage {
		hr = comCall(stg, method, uintptr(unsafe.Pointer(name)), 0, stgmReadShareExclusive, 0, 0, uintptr(unsafe.Pointer(&child)))
	} else {
		hr = comCall(stg, method, uintptr(unsafe.Pointer(name)), 0, stgmReadShareExclusive, 0, uintptr(unsafe.Pointer(&child)))
	}
	if hr != 0 {
		return fmt.Errorf("open %s: %#x", windows.UTF16PtrToString(name), hr)
	}
	defer comCall(child, comRelease)
	return use(child)
}

func readStream(s unsafe.Pointer, size uint64) ([]byte, error) {
	buf := make([]byte, size+1)
	var n uint32
	if size == 0 {
		return nil, nil
	}
	if hr := comCall(s, streamRead, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n))); hr != 0 && hr != 1 {
		return nil, fmt.Errorf("Read: %#x", hr)
	}
	return buf[:n], nil
}

// openWithWindows reads the compound file at path with Windows' structured
// storage.
func openWithWindows(t *testing.T, path string) map[string][]byte {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(path)
	var stg unsafe.Pointer
	hr, _, _ := procStgOpenStorageEx.Call(uintptr(unsafe.Pointer(name)), stgmReadShareExclusive, stgfmtDocfile, 0, 0, 0,
		uintptr(unsafe.Pointer(&iidIStorage)), uintptr(unsafe.Pointer(&stg)))
	if hr != 0 {
		t.Fatalf("StgOpenStorageEx: %#x", hr)
	}
	defer comCall(stg, comRelease)
	out := map[string][]byte{}
	if err := readStorage(stg, "", out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCFBReadByWindows: Windows opens what BuildCFB writes, a VBA project
// and a file with streams of every size class, and reads back every stream
// byte for byte, and no other.
func TestCFBReadByWindows(t *testing.T) {
	s := prng.Root(5).Derive("cfb").Stream()
	vba, err := BuildVBAProject(VBASpec{Host: VBAWord, EntryPoint: "AutoOpen", Marker: "m"}, s)
	if err != nil {
		t.Fatal(err)
	}
	big := []CFBEntry{
		{Name: "Storage", Storage: true, Children: []CFBEntry{
			{Name: "mini", Data: s.Bytes(100)},
			{Name: "cutoff", Data: s.Bytes(4096)},
			{Name: "large", Data: s.Bytes(300000)},
			{Name: "empty"},
		}},
		{Name: "top", Data: s.Bytes(4095)},
	}
	bigFile, err := BuildCFB(big)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"vbaProject.bin": vba, "big.cfb": bigFile} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		got := openWithWindows(t, path)
		want, err := readCFB(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want.streams) {
			t.Errorf("%s: Windows lists %d streams, the file holds %d", name, len(got), len(want.streams))
		}
		for p, w := range want.streams {
			if g, ok := got[p]; !ok || !bytes.Equal(g, w) {
				t.Errorf("%s: %s: Windows read %d bytes, want %d", name, p, len(g), len(w))
			}
		}
	}
}
