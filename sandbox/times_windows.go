//go:build windows

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func timeCaps(fsName string) TimeCaps {
	switch strings.ToUpper(fsName) {
	case "NTFS", "REFS":
		return TimeCaps{Birth: true, Change: true}
	}
	return TimeCaps{Birth: true}
}

// volumeGranularity is the resolution of the volume by its name, or two
// seconds (FAT's, the coarsest) for one Windows does not name.
func volumeGranularity(_ *os.Root, fsName string) Granularity {
	if g, ok := namedGranularity(fsName); ok {
		return g
	}
	return Granularity{2 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}
}

// fileBasicInfo mirrors FILE_BASIC_INFO: four FILETIMEs as 100 ns ticks
// since 1601, then the attributes (0 leaves them unchanged). A zero time
// leaves that time unchanged.
type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// epochDelta is 1970-01-01 in 100 ns ticks since 1601-01-01.
const epochDelta = 116444736000000000

func toFiletime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()*1e7 + int64(t.Nanosecond())/100 + epochDelta
}

func fromFiletime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	v -= epochDelta
	return time.Unix(v/1e7, (v%1e7)*100).UTC()
}

// openRel opens name itself (never what a final reparse point names)
// relative to a handle on its parent directory, which was opened through the
// root, so the object can only be one inside the root.
func openRel(r *os.Root, name string, access, options uint32) (windows.Handle, error) {
	dir, leaf := filepath.Split(name)
	if dir == "" {
		dir = "."
	}
	parent, err := r.Open(dir)
	if err != nil {
		return 0, err
	}
	defer parent.Close()

	objName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return 0, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    objName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|options,
		0, 0)
	if err != nil {
		if st, ok := errors.AsType[windows.NTStatus](err); ok {
			switch st {
			case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND, windows.STATUS_NO_SUCH_FILE:
				return 0, os.ErrNotExist
			}
		}
		return 0, err
	}
	return h, nil
}

func setTimes(r *os.Root, name string, t Times, caps TimeCaps) error {
	h, err := openRel(r, name, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	info := fileBasicInfo{
		LastAccessTime: toFiletime(t.Atime),
		LastWriteTime:  toFiletime(t.Mtime),
	}
	if caps.Birth {
		info.CreationTime = toFiletime(t.Btime)
	}
	if caps.Change {
		info.ChangeTime = toFiletime(t.Ctime)
	}
	return windows.SetFileInformationByHandle(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
}

// fileIDInfo mirrors FILE_ID_INFO: the volume serial number and a 128-bit
// file ID. On NTFS the low 64 bits are the file reference: the MFT record
// number in the low 48 bits and a sequence number above them.
type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func getMeta(r *os.Root, name, fsName string) (Meta, error) {
	h, err := openRel(r, name, windows.FILE_READ_ATTRIBUTES, 0)
	if err != nil {
		return Meta{}, err
	}
	defer windows.CloseHandle(h)
	var info fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return Meta{}, err
	}
	m := Meta{Times: Times{
		Atime: fromFiletime(info.LastAccessTime),
		Mtime: fromFiletime(info.LastWriteTime),
		Ctime: fromFiletime(info.ChangeTime),
		Btime: fromFiletime(info.CreationTime),
	}}
	var id fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err == nil {
		m.ID = fileID(id.FileID, fsName)
	}
	return m, nil
}

// fileID writes a file ID the way forensic tools name the object: the MFT
// record number on NTFS, else the ID in decimal (or hex when it needs more
// than 64 bits, as on ReFS).
func fileID(id [16]byte, fsName string) string {
	lo := binary.LittleEndian.Uint64(id[:8])
	hi := binary.LittleEndian.Uint64(id[8:])
	switch {
	case strings.EqualFold(fsName, "NTFS") && hi == 0:
		return strconv.FormatUint(lo&(1<<48-1), 10)
	case hi == 0:
		return strconv.FormatUint(lo, 10)
	}
	return fmt.Sprintf("0x%016x%016x", hi, lo)
}

// openQuiet opens name for reading and tells NTFS not to update its last
// access time for anything done through this handle (SetFileTime with an
// access time of all ones), which needs FILE_WRITE_ATTRIBUTES.
func openQuiet(r *os.Root, name string) (*os.File, error) {
	h, err := openRel(r, name, windows.FILE_GENERIC_READ|windows.FILE_WRITE_ATTRIBUTES, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	suspend := windows.Filetime{LowDateTime: 0xFFFFFFFF, HighDateTime: 0xFFFFFFFF}
	if err := windows.SetFileTime(h, nil, &suspend, nil); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "suspend access time", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// openStreamQuiet opens a named stream for reading with access-time updates
// suspended on the handle, as openQuiet does for a file.
func openStreamQuiet(r *os.Root, name, stream string) (*os.File, error) {
	f, err := openStream(r, name, stream, windows.FILE_GENERIC_READ|windows.FILE_WRITE_ATTRIBUTES, windows.FILE_OPEN)
	if err != nil {
		return nil, err
	}
	suspend := windows.Filetime{LowDateTime: 0xFFFFFFFF, HighDateTime: 0xFFFFFFFF}
	if err := windows.SetFileTime(windows.Handle(f.Fd()), nil, &suspend, nil); err != nil {
		f.Close()
		return nil, &os.PathError{Op: "suspend access time", Path: name + ":" + stream, Err: err}
	}
	return f, nil
}
