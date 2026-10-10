//go:build windows

package sandbox

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetDiskFreeSpaceW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDiskFreeSpaceW")

// probeCluster is the cluster size of the volume holding dir, or 0 if it
// cannot be read.
func probeCluster(dir string) int {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0
	}
	vol := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(p, &vol[0], uint32(len(vol))); err != nil {
		return 0
	}
	var sectorsPerCluster, bytesPerSector, free, total uint32
	r, _, _ := procGetDiskFreeSpaceW.Call(uintptr(unsafe.Pointer(&vol[0])),
		uintptr(unsafe.Pointer(&sectorsPerCluster)), uintptr(unsafe.Pointer(&bytesPerSector)),
		uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)))
	if r == 0 {
		return 0
	}
	return int(sectorsPerCluster * bytesPerSector)
}

// slackBestEffort reports whether slack can be written on this volume at all:
// NTFS leaves the rest of a file's last cluster alone when the file shrinks.
func slackBestEffort(fsName string) bool { return fsName == "NTFS" }

// writeSlack puts data just past the end of name's content, then shrinks the
// file back to that end, so the bytes stay in the cluster but outside the
// file. Each step is flushed: the bytes must reach the disk before the file
// shrinks, or the cache would drop them instead of writing them.
func writeSlack(r *os.Root, name string, at int64, data []byte) error {
	f, err := r.OpenFile(native(name), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(data, at); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Truncate(at); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
