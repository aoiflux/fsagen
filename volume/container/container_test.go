package container

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// The VHD specification's geometry for a 512 MiB disk, and the disk rounded
// to it.
func TestVHDGeometry(t *testing.T) {
	l, err := Plan(FormatVHD, PartitionMBR, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	if l.Geometry != [3]int{1040, 16, 63} || l.Disk != 1040*16*63*512 || l.File() != l.Disk+512 {
		t.Errorf("layout %+v", l)
	}
	if l.Offset != 1<<20 || l.Size != l.Disk-l.Offset {
		t.Errorf("partition at %d, %d bytes", l.Offset, l.Size)
	}
}

// The MBR entry for a partition 1 MiB in: CHS 0/32/33 as fdisk writes it,
// type 0x0C, the LBA and count, and the signature.
func TestMBR(t *testing.T) {
	l, _ := Plan(FormatRaw, PartitionMBR, 64<<20)
	f, err := os.Create(filepath.Join(t.TempDir(), "d.img"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := WriteMBR(f, l, 0x0C, prng.Root(1)); err != nil {
		t.Fatal(err)
	}
	mbr := make([]byte, 512)
	f.ReadAt(mbr, 0)
	p := mbr[0x1BE:]
	if !bytes.Equal(p[1:4], []byte{0x20, 0x21, 0x00}) || p[4] != 0x0C || binary.LittleEndian.Uint32(p[8:]) != 2048 ||
		binary.LittleEndian.Uint32(p[12:]) != uint32(64<<20/512-2048) || mbr[510] != 0x55 || mbr[511] != 0xAA {
		t.Errorf("partition entry % x", p[:16])
	}
}

// A footer's checksum makes the one's complement of its bytes' sum come
// out, and the footer says what the disk is.
func TestVHDFooter(t *testing.T) {
	l, _ := Plan(FormatVHD, PartitionNone, 64<<20)
	f, err := os.Create(filepath.Join(t.TempDir(), "d.vhd"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := WriteFooter(f, l, time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), prng.Root(1)); err != nil {
		t.Fatal(err)
	}
	foot := make([]byte, 512)
	f.ReadAt(foot, l.Disk)
	be := binary.BigEndian
	if string(foot[:8]) != "conectix" || be.Uint32(foot[60:]) != 2 || be.Uint64(foot[48:]) != uint64(l.Disk) || be.Uint32(foot[24:]) != 662774400 {
		t.Errorf("footer % x", foot[:64])
	}
	if be.Uint32(foot[64:]) != Checksum(foot) {
		t.Error("checksum does not match")
	}
}

func TestFormatFor(t *testing.T) {
	for name, want := range map[string]string{"a.raw": FormatRaw, "B.DD": FormatRaw, "c.img": FormatRaw, "d.vhd": FormatVHD} {
		if got, err := FormatFor(name); got != want || err != nil {
			t.Errorf("%s: %s %v", name, got, err)
		}
	}
	if _, err := FormatFor("e.vhdx"); err == nil {
		t.Error(".vhdx was accepted")
	}
}
