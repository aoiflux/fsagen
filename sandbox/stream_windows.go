//go:build windows

package sandbox

import (
	"errors"
	"io"
	"os"
	"runtime"
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

	h, err := ntOpen{
		parent:      windows.Handle(base.Fd()),
		name:        ":" + stream + ":$DATA",
		access:      access,
		attributes:  windows.FILE_ATTRIBUTE_NORMAL,
		disposition: disposition,
		options:     windows.FILE_NON_DIRECTORY_FILE,
	}.open()
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name + ":" + stream, Err: err}
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

	buf := make([]byte, streamBufferSize)
	for {
		err = readStreamInfo(windows.Handle(f.Fd()), buf)
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

	// GetFileInformationByHandleEx does not report how many bytes it wrote, so
	// every entry is checked against the buffer before it is read: a header or a
	// name claiming to run past the end would otherwise be read out of bounds.
	const nameOffset = int(unsafe.Sizeof(fileStreamInfoHeader{}))
	var out []Stream
	for off := 0; off+nameOffset <= len(buf); {
		hdr := (*fileStreamInfoHeader)(unsafe.Pointer(&buf[off]))
		nameBytes := int(hdr.StreamNameLength)
		if off+nameOffset+nameBytes > len(buf) {
			return nil, &os.PathError{Op: "list streams", Path: name, Err: errStreamList}
		}
		raw := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off+nameOffset])), nameBytes/2)
		full := string(utf16.Decode(raw)) // ":name:$DATA", or "::$DATA" for the default stream
		if s := trimStreamName(full); s != "" {
			out = append(out, Stream{Name: s, Size: hdr.StreamSize})
		}
		if hdr.NextEntryOffset == 0 {
			break
		}
		// A non-advancing offset would read the same entry for ever.
		next := off + int(hdr.NextEntryOffset)
		if next <= off {
			return nil, &os.PathError{Op: "list streams", Path: name, Err: errStreamList}
		}
		off = next
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

// streamBufferSize is the first buffer tried for a file's stream list; a file
// with more streams than fit is retried with a larger one.
const streamBufferSize = 4096

// readStreamInfo fills buf with the file's stream list.
//
// The buffer is pinned for the call. The kernel is handed its address and writes
// into it, and an unpinned Go pointer may be to a goroutine stack, which the
// runtime is free to move: the write would then land on memory that is no longer
// the buffer. Pinning also keeps the allocation off the stack in the first
// place, so the call does not depend on what escape analysis happens to decide
// about the code around it.
func readStreamInfo(h windows.Handle, buf []byte) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&buf[0])
	return windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &buf[0], uint32(len(buf)))
}

// errStreamList says the stream list Windows returned does not fit the buffer it
// was written into, or does not move forward through it.
var errStreamList = errors.New("stream list is malformed")
