//go:build windows

package sandbox

import (
	"errors"
	"io"
	"os"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// probeVolume asks the volume holding the root whether it stores named
// streams (FAT and exFAT do not) and what it is called.
func probeVolume(r *os.Root) (bool, string) {
	d, err := r.Open(".")
	if err != nil {
		return false, ""
	}
	defer d.Close()

	var flags uint32
	name := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeInformationByHandle(windows.Handle(d.Fd()), nil, 0, nil, nil, &flags, &name[0], uint32(len(name))); err != nil {
		return false, ""
	}
	return flags&windows.FILE_NAMED_STREAMS != 0, windows.UTF16ToString(name)
}

// openStream opens ":stream:$DATA" relative to a handle on the base object,
// which was itself opened through the root. NtCreateFile resolves a name that
// starts with ':' as a stream of the object RootDirectory refers to, so the
// stream can only ever belong to a file inside the root.
func openStream(r *os.Root, name, stream string, access, disposition uint32) (*os.File, error) {
	base, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer base.Close()

	objName, err := windows.NewNTUnicodeString(":" + stream + ":$DATA")
	if err != nil {
		return nil, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(base.Fd()),
		ObjectName:    objName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))

	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		disposition,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0)
	if err != nil {
		full := name + ":" + stream
		if st, ok := errors.AsType[windows.NTStatus](err); ok {
			switch st {
			case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND, windows.STATUS_NO_SUCH_FILE:
				return nil, &os.PathError{Op: "open", Path: full, Err: os.ErrNotExist}
			}
		}
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return os.NewFile(uintptr(h), name+":"+stream), nil
}

func writeStream(r *os.Root, name, stream string, data []byte) error {
	f, err := openStream(r, name, stream, windows.FILE_GENERIC_WRITE, windows.FILE_OVERWRITE_IF)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readStream(r *os.Root, name, stream string) ([]byte, error) {
	f, err := openStream(r, name, stream, windows.FILE_GENERIC_READ, windows.FILE_OPEN)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// fileStreamInfoHeader mirrors the fixed part of FILE_STREAM_INFO, which
// x/sys/windows does not export; the UTF-16 name follows it.
type fileStreamInfoHeader struct {
	NextEntryOffset      uint32
	StreamNameLength     uint32
	StreamSize           int64
	StreamAllocationSize int64
}

// listStreams enumerates streams on a handle opened through the root, rather
// than with FindFirstStreamW, which takes a path and so cannot be confined.
func listStreams(r *os.Root, name string) ([]Stream, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	for {
		err = windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileStreamInfo, &buf[0], uint32(len(buf)))
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil, nil // no streams at all (for example a directory)
		}
		if errors.Is(err, windows.ERROR_MORE_DATA) && len(buf) < 1<<24 {
			buf = make([]byte, len(buf)*4)
			continue
		}
		return nil, &os.PathError{Op: "list streams", Path: name, Err: err}
	}

	const nameOffset = int(unsafe.Sizeof(fileStreamInfoHeader{}))
	var out []Stream
	for off := 0; ; {
		hdr := (*fileStreamInfoHeader)(unsafe.Pointer(&buf[off]))
		n := int(hdr.StreamNameLength) / 2
		raw := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off+nameOffset])), n)
		full := string(utf16.Decode(raw)) // ":name:$DATA", or "::$DATA" for the default stream
		if s := trimStreamName(full); s != "" {
			out = append(out, Stream{Name: s, Size: hdr.StreamSize})
		}
		if hdr.NextEntryOffset == 0 {
			break
		}
		off += int(hdr.NextEntryOffset)
	}
	return out, nil
}

func trimStreamName(full string) string {
	const suffix = ":$DATA"
	if len(full) < len(suffix)+1 || full[0] != ':' || full[len(full)-len(suffix):] != suffix {
		return ""
	}
	return full[1 : len(full)-len(suffix)]
}
