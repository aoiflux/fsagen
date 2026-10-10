// Package volume builds a file-system image byte by byte. A Volume is a
// target: the executor writes a scenario into it exactly as it writes a live
// directory, and a Driver lays each change out the way its file system
// would, on a Device that is the image itself. Nothing is written by an
// operating system, so every byte is fsagen's and the same seed gives the
// same image.
//
// The Volume keeps the tree as the scenario sees it, which is what reads
// before Finish are served from. The Driver keeps the on-disk structures,
// writes content and directories through to the Device as they change, and
// once finished reads the image back with its own parser: what the run is
// verified and digested against is what is on disk.
package volume

import (
	"fmt"
	"io"
	"os"
)

// SectorSize is the unit every image is addressed in.
const SectorSize = 512

// Device is the part of the image file one file system lives in: the
// whole file, or a partition of it. Offsets are relative to its start.
type Device struct {
	f    *os.File
	base int64
	size int64
}

// NewDevice is the size bytes of f starting at base.
func NewDevice(f *os.File, base, size int64) *Device {
	return &Device{f: f, base: base, size: size}
}

// Size is the device's length in bytes.
func (d *Device) Size() int64 { return d.size }

// Abs is where off lies in the image file.
func (d *Device) Abs(off int64) int64 { return d.base + off }

func (d *Device) check(n int, off int64) error {
	if off < 0 || off+int64(n) > d.size {
		return fmt.Errorf("device: %d bytes at %d are outside the %d-byte volume", n, off, d.size)
	}
	return nil
}

// ReadAt reads len(p) bytes at off.
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if err := d.check(len(p), off); err != nil {
		return 0, err
	}
	n, err := d.f.ReadAt(p, d.base+off)
	if err == io.EOF && n == len(p) {
		err = nil
	}
	return n, err
}

// WriteAt writes p at off.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	if err := d.check(len(p), off); err != nil {
		return 0, err
	}
	return d.f.WriteAt(p, d.base+off)
}

// Zero writes n zero bytes at off.
func (d *Device) Zero(off, n int64) error {
	buf := make([]byte, min(n, 1<<20))
	for n > 0 {
		k := min(n, int64(len(buf)))
		if _, err := d.WriteAt(buf[:k], off); err != nil {
			return err
		}
		off, n = off+k, n-k
	}
	return nil
}
