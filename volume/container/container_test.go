package container

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libtable"
	"github.com/aoiflux/libvhdi"
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

// The MBR entry for a partition 1 MiB in, as libtable reads it: CHS 0/32/33
// as fdisk writes it, type 0x0C, the LBA and count, and the disk signature.
func TestMBR(t *testing.T) {
	l, _ := Plan(FormatRaw, PartitionMBR, 64<<20)
	f, err := os.Create(filepath.Join(t.TempDir(), "d.img"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(l.File()); err != nil {
		t.Fatal(err)
	}
	if err := WriteMBR(f, l, libtable.MBRTypeFAT32LBA, prng.Root(1)); err != nil {
		t.Fatal(err)
	}
	tab, err := libtable.Parse(f, uint64(l.File()), libtable.Options{Type: libtable.TypeMBR})
	if err != nil {
		t.Fatal(err)
	}
	var parts []libtable.Partition
	for _, p := range tab.Partitions {
		if p.SlotNumber >= 0 {
			parts = append(parts, p)
		}
	}
	if len(parts) != 1 {
		t.Fatalf("%d partitions: %+v", len(parts), tab.Partitions)
	}
	p := parts[0]
	if p.FirstCHS != [3]byte{0x20, 0x21, 0x00} || p.TypeCode != uint64(libtable.MBRTypeFAT32LBA) ||
		tab.ByteOffset(p) != uint64(l.Offset) || tab.ByteSize(p) != uint64(l.Size) || p.Bootable {
		t.Errorf("partition %+v", p)
	}
	sig := binary.LittleEndian.Uint32(prng.Root(1).Derive("disk-signature").Stream().Bytes(4))
	if tab.DiskSignature != sig || len(tab.Warnings) != 0 {
		t.Errorf("disk signature %#x, want %#x; warnings %v", tab.DiskSignature, sig, tab.Warnings)
	}
}

// libvhdi opens the disk, which it does only when the footer's checksum
// holds, and reads back what the footer says the disk is.
func TestVHDFooter(t *testing.T) {
	l, _ := Plan(FormatVHD, PartitionNone, 64<<20)
	f, err := os.Create(filepath.Join(t.TempDir(), "d.vhd"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(l.File()); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := WriteFooter(f, l, when, prng.Root(1)); err != nil {
		t.Fatal(err)
	}
	d, err := libvhdi.OpenVHD(f, l.File())
	if err != nil {
		t.Fatal(err)
	}
	g, pv := d.Geometry(), d.Provenance()
	if pv.DiskType != libvhdi.DiskTypeFixed || g.VirtualSize != uint64(l.Disk) || d.FooterRecovered() || len(d.Warnings()) != 0 {
		t.Errorf("disk %+v %+v, warnings %v", g, pv, d.Warnings())
	}
	if [3]int{int(g.Cylinders), int(g.Heads), int(g.SectorsPerTrack)} != l.Geometry || !pv.Created.Equal(when) || pv.CreatorOS != "Wi2k" {
		t.Errorf("geometry %+v, created %v, OS %q", g, pv.Created, pv.CreatorOS)
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

// A GPT disk as Windows Setup lays one out, read back by libtable: the
// protective MBR, both headers and both entry arrays with their CRCs, a
// backup that agrees, and the four partitions in Windows' order, each on a
// MiB, the Windows partition the file system's.
func TestGPT(t *testing.T) {
	for _, tc := range []struct {
		disk          int64
		esp, msr, rec int64
		formatVHD     bool
	}{
		{64 << 20, 33 << 20, 1 << 20, 4 << 20, true},
		{1 << 30, 33 << 20, 1 << 20, 8 << 20, false},
	} {
		format := FormatRaw
		if tc.formatVHD {
			format = FormatVHD
		}
		l, err := Plan(format, PartitionGPT, tc.disk)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(filepath.Join(t.TempDir(), "d.img"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Truncate(l.File()); err != nil {
			t.Fatal(err)
		}
		if err := WriteGPT(f, l, prng.Root(1)); err != nil {
			t.Fatal(err)
		}
		tab, err := libtable.Parse(f, uint64(l.Disk), libtable.Options{Type: libtable.TypeGPT})
		if err != nil {
			t.Fatal(err)
		}
		if tab.GPTBackup != libtable.GPTBackupOK || len(tab.Warnings) != 0 {
			t.Errorf("%d bytes: backup %v, warnings %v", tc.disk, tab.GPTBackup, tab.Warnings)
		}
		var got []string
		for _, p := range tab.Partitions {
			if p.SlotNumber < 0 {
				continue
			}
			off, size := int64(tab.ByteOffset(p)), int64(tab.ByteSize(p))
			got = append(got, fmt.Sprintf("%s %q %#x", p.GUIDType, p.Name, p.Attributes))
			if off%(1<<20) != 0 || size%(1<<20) != 0 || p.GUIDUnique == "" || p.GUIDUnique[14] != '4' {
				t.Errorf("%d bytes: %q at %d, %d bytes, GUID %s: want a MiB boundary and a random GUID", tc.disk, p.Name, off, size, p.GUIDUnique)
			}
			want := map[string]int64{TypeEFISystem: tc.esp, TypeMSReserved: tc.msr, TypeWinRecovery: tc.rec, TypeBasicData: l.Size}[p.GUIDType]
			if size != want || p.GUIDType == TypeBasicData && off != l.Offset {
				t.Errorf("%d bytes: %q at %d, %d bytes; want %d bytes (the file system's partition at %d)", tc.disk, p.Name, off, size, want, l.Offset)
			}
		}
		want := []string{
			TypeEFISystem + ` "EFI system partition" 0x8000000000000000`,
			TypeMSReserved + ` "Microsoft reserved partition" 0x8000000000000000`,
			TypeBasicData + ` "Basic data partition" 0x0`,
			TypeWinRecovery + ` "Basic data partition" 0x8000000000000001`,
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%d bytes: partitions\n%s\nwant\n%s", tc.disk, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	// From 64 GiB on, the partitions are Windows Setup's own size.
	l, err := Plan(FormatRaw, PartitionGPT, 80<<30)
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int64
	for _, p := range l.Parts {
		sizes = append(sizes, p.Size>>20)
	}
	if fmt.Sprint(sizes) != fmt.Sprint([]int64{100, 16, 80<<10 - 1 - 100 - 16 - 512 - 1, 512}) {
		t.Errorf("an 80 GiB disk's partitions are %v MiB", sizes)
	}
	if _, err := Plan(FormatRaw, PartitionGPT, 40<<20); err == nil || !strings.Contains(err.Error(), "too small for Windows' GPT layout") {
		t.Errorf("a 40 MiB GPT disk: %v", err)
	}
}
