//go:build windows

package sandbox

import (
	"os"
	"path/filepath"
	"unsafe"

	"github.com/aoiflux/fsagen/internal/reparse"
	"golang.org/x/sys/windows"
)

// A Windows symlink or junction is a reparse point: an empty file or
// directory carrying data that tells the file system where the name leads.
// fsagen writes the data itself, on an entry it creates relative to its
// parent directory opened through the root, so it decides whether a symlink
// is a file or a directory link whatever the target is, and a junction can
// be made with the same code. Go's os.Root.Symlink chooses by looking at the
// target, which for a target that is not there yet is always a file link.

const maxReparseDataBuffer = 16 * 1024

func linkCaps(v volume) LinkCaps {
	return LinkCaps{Hard: v.hardlinks, Sym: v.reparse && SymlinksAllowed(), Junction: v.reparse}
}

// symlink writes the reparse data CreateSymbolicLinkW writes (see
// reparse.Symlink).
func symlink(r *os.Root, name, target string, dir bool) error {
	data, err := reparse.Symlink(target)
	if err != nil {
		return err
	}
	return createReparse(r, name, dir, data)
}

func junction(r *os.Root, name, target string) error {
	data, err := reparse.Junction(target)
	if err != nil {
		return err
	}
	return createReparse(r, name, true, data)
}

// createReparse creates name, a new empty file or directory, relative to
// its parent opened through the root, and sets data as its reparse point.
// If the data cannot be set, the entry is deleted again.
func createReparse(r *os.Root, name string, dir bool, data []byte) error {
	parentName, leaf := filepath.Split(name)
	if parentName == "" {
		parentName = "."
	}
	parent, err := r.Open(parentName)
	if err != nil {
		return err
	}
	defer parent.Close()
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if dir {
		options = windows.FILE_DIRECTORY_FILE
	}
	h, err := ntOpen{
		parent:      windows.Handle(parent.Fd()),
		name:        leaf,
		access:      windows.FILE_WRITE_ATTRIBUTES | windows.DELETE,
		attributes:  windows.FILE_ATTRIBUTE_NORMAL,
		disposition: windows.FILE_CREATE,
		options:     windows.FILE_OPEN_REPARSE_POINT | options,
	}.open()
	if err != nil {
		return &os.PathError{Op: "create link", Path: name, Err: err}
	}
	defer windows.CloseHandle(h)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &n, nil); err != nil {
		del := struct{ DeleteFile bool }{true}
		windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&del)), uint32(unsafe.Sizeof(del)))
		return &os.PathError{Op: "set reparse point", Path: name, Err: err}
	}
	return nil
}

// fileStandardInfo mirrors FILE_STANDARD_INFO.
type fileStandardInfo struct {
	AllocationSize, EndOfFile int64
	NumberOfLinks             uint32
	DeletePending, Directory  bool
}

// fileAttributeTagInfo mirrors FILE_ATTRIBUTE_TAG_INFO.
type fileAttributeTagInfo struct {
	FileAttributes, ReparseTag uint32
}

// linkMeta adds to m what the handle h says about links: how many names
// the object has, and for a symlink or junction what it points at, as its
// print name records it.
func linkMeta(h windows.Handle, m *Meta) {
	var std fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&std)), uint32(unsafe.Sizeof(std))); err == nil {
		m.Links = int(std.NumberOfLinks)
	}
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil || tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return
	}
	switch tag.ReparseTag {
	case windows.IO_REPARSE_TAG_SYMLINK:
		m.Link = LinkSymlink
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
		m.Link = LinkJunction
	default:
		return
	}
	target, err := reparseTarget(h)
	if err == nil {
		m.Target = target
	}
}

// reparseTarget reads a symlink's or junction's print name.
func reparseTarget(h windows.Handle) (string, error) {
	buf := make([]byte, maxReparseDataBuffer)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return "", err
	}
	_, name, err := reparse.PrintName(buf[:n])
	return name, err
}
