//go:build windows

package libgen

import (
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"
)

// TestPEChecksumMatchesWindows: the checksum fsagen stores is the one Windows
// itself computes. peChecksum is a reimplementation of an algorithm nothing
// else in the standard library knows, so a test that only compares it with
// itself proves nothing; this one asks imagehlp for the answer.
func TestPEChecksumMatchesWindows(t *testing.T) {
	for _, machine := range PEMachines {
		t.Run(machine, func(t *testing.T) {
			data, err := BuildPE(samplePE(t, machine, false))
			if err != nil {
				t.Fatal(err)
			}
			headerSum, checkSum := windowsChecksum(t, data)

			lfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
			at := lfanew + 4 + 20 + 64
			stored := binary.LittleEndian.Uint32(data[at:])

			if headerSum != stored {
				t.Errorf("imagehlp read %#x from the header, fsagen wrote %#x", headerSum, stored)
			}
			if checkSum != stored {
				t.Errorf("checksum %#x, Windows computes %#x", stored, checkSum)
			}
		})
	}
}

// windowsChecksum returns what CheckSumMappedFile reads from the image's
// header and what it says the header should hold.
func windowsChecksum(t *testing.T, image []byte) (headerSum, checkSum uint32) {
	t.Helper()
	// CheckSumMappedFile reads 16-bit words, so give it an even length to
	// walk even if a future change makes an image an odd number of bytes.
	buf := make([]byte, len(image), len(image)+1)
	copy(buf, image)

	proc := syscall.NewLazyDLL("imagehlp.dll").NewProc("CheckSumMappedFile")
	if err := proc.Find(); err != nil {
		t.Skipf("imagehlp!CheckSumMappedFile is not available: %v", err)
	}
	nt, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&headerSum)),
		uintptr(unsafe.Pointer(&checkSum)),
	)
	if nt == 0 {
		t.Fatalf("CheckSumMappedFile rejected the image: %v", err)
	}
	return headerSum, checkSum
}
