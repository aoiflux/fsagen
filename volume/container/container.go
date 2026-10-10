// Package container wraps a file system in what holds it on disk: nothing
// (a raw volume image), an MBR partition table, and optionally a fixed VHD
// footer, which is a raw disk with 512 bytes after it.
package container

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// The image formats, chosen by the image file's extension.
const (
	FormatRaw = "raw"
	FormatVHD = "vhd"
)

// Extensions maps each image extension to its format.
var Extensions = map[string]string{".raw": FormatRaw, ".dd": FormatRaw, ".img": FormatRaw, ".vhd": FormatVHD}

// FormatFor is the format of an image file named name.
func FormatFor(name string) (string, error) {
	i := strings.LastIndexByte(name, '.')
	if i >= 0 {
		if f, ok := Extensions[strings.ToLower(name[i:])]; ok {
			return f, nil
		}
	}
	exts := make([]string, 0, len(Extensions))
	for e := range Extensions {
		exts = append(exts, e)
	}
	slices.Sort(exts)
	return "", fmt.Errorf("cannot tell the image format from %q; name it %s", name, strings.Join(exts, ", "))
}

// The partitioning schemes.
const (
	PartitionMBR  = "mbr"
	PartitionNone = "none"
)

// Partitions lists the partitioning schemes.
var Partitions = []string{PartitionMBR, PartitionNone}

const sector = 512

// MBRStart is where the one partition of an MBR disk starts, in sectors:
// 1 MiB in, as every partitioning tool since Windows Vista aligns it.
const MBRStart = 2048

// Layout is where everything lies in the image file.
type Layout struct {
	Format, Partition string
	// Disk is the disk's size: the file's, less a VHD's footer.
	Disk int64
	// Offset and Size are the file system's partition.
	Offset, Size int64
	// Geometry is the VHD's cylinders, heads and sectors per track.
	Geometry [3]int
}

// Plan lays out a disk of about size bytes. A VHD's disk is rounded down
// to a whole number of its cylinders, so the size its footer gives and the
// size its geometry gives agree.
func Plan(format, partition string, size int64) (Layout, error) {
	l := Layout{Format: format, Partition: partition, Disk: size / sector * sector}
	switch format {
	case FormatRaw:
	case FormatVHD:
		c, h, s := vhdGeometry(l.Disk / sector)
		l.Geometry = [3]int{c, h, s}
		l.Disk = int64(c) * int64(h) * int64(s) * sector
	default:
		return Layout{}, fmt.Errorf("unknown image format %q", format)
	}
	switch partition {
	case PartitionMBR:
		l.Offset = MBRStart * sector
		if l.Disk/sector-MBRStart > 0xFFFFFFFF {
			return Layout{}, fmt.Errorf("an MBR partition holds at most 2 TiB")
		}
	case PartitionNone:
	default:
		return Layout{}, fmt.Errorf("unknown partitioning %q (want %s)", partition, strings.Join(Partitions, " or "))
	}
	l.Size = l.Disk - l.Offset
	if l.Size <= 0 {
		return Layout{}, fmt.Errorf("a %d-byte disk has no room for a partition", l.Disk)
	}
	return l, nil
}

// File is the length of the image file.
func (l Layout) File() int64 {
	if l.Format == FormatVHD {
		return l.Disk + sector
	}
	return l.Disk
}

// WriteMBR writes the partition table, with one partition of type kind
// (0x0C for FAT32 with LBA, 0x83 for Linux, 0x07 for NTFS) and a disk
// signature drawn from key.
func WriteMBR(w io.WriterAt, l Layout, kind byte, key prng.Key) error {
	if l.Partition != PartitionMBR {
		return nil
	}
	mbr := make([]byte, sector)
	copy(mbr[0x1B8:], key.Derive("disk-signature").Stream().Bytes(4))
	p := mbr[0x1BE:]
	start, count := uint32(MBRStart), uint32(l.Size/sector)
	copy(p[1:4], chs(int64(start)))
	p[4] = kind
	copy(p[5:8], chs(int64(start)+int64(count)-1))
	binary.LittleEndian.PutUint32(p[8:], start)
	binary.LittleEndian.PutUint32(p[12:], count)
	mbr[510], mbr[511] = 0x55, 0xAA
	_, err := w.WriteAt(mbr, 0)
	return err
}

// chs is a sector's cylinder-head-sector address as an MBR entry stores it,
// for the 255-head, 63-sector geometry every tool assumes; past what CHS
// can address it is the maximum, as fdisk writes it.
func chs(lba int64) []byte {
	c, h, s := lba/(255*63), (lba/63)%255, lba%63+1
	if c > 1023 {
		return []byte{0xFE, 0xFF, 0xFF}
	}
	return []byte{byte(h), byte(s) | byte(c>>2)&0xC0, byte(c)}
}

// vhdGeometry is the CHS geometry the VHD specification derives from a
// disk's sector count.
func vhdGeometry(total int64) (cyl, heads, spt int) {
	total = min(total, 65535*16*255)
	var cth int64
	if total >= 65535*16*63 {
		spt, heads = 255, 16
		cth = total / int64(spt)
	} else {
		spt = 17
		cth = total / int64(spt)
		heads = max(int((cth+1023)/1024), 4)
		if cth >= int64(heads)*1024 || heads > 16 {
			spt, heads = 31, 16
			cth = total / int64(spt)
		}
		if cth >= int64(heads)*1024 {
			spt, heads = 63, 16
			cth = total / int64(spt)
		}
	}
	return int(cth / int64(heads)), heads, spt
}

// vhdEpoch is where a VHD's timestamp counts from.
var vhdEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// WriteFooter writes a fixed VHD's footer after the disk, stamped when and
// identified by an ID drawn from key.
func WriteFooter(w io.WriterAt, l Layout, when time.Time, key prng.Key) error {
	if l.Format != FormatVHD {
		return nil
	}
	f := make([]byte, sector)
	be := binary.BigEndian
	copy(f, "conectix")
	be.PutUint32(f[8:], 2)           // features: reserved bit, always set
	be.PutUint32(f[12:], 0x00010000) // format version 1.0
	be.PutUint64(f[16:], ^uint64(0)) // data offset: none, for a fixed disk
	be.PutUint32(f[24:], uint32(max(when.Sub(vhdEpoch)/time.Second, 0)))
	copy(f[28:], "fsag")
	be.PutUint32(f[32:], 0x00010000)
	copy(f[36:], "Wi2k")
	be.PutUint64(f[40:], uint64(l.Disk))
	be.PutUint64(f[48:], uint64(l.Disk))
	be.PutUint16(f[56:], uint16(l.Geometry[0]))
	f[58], f[59] = byte(l.Geometry[1]), byte(l.Geometry[2])
	be.PutUint32(f[60:], 2) // fixed
	copy(f[68:84], key.Derive("vhd-id").Stream().Bytes(16))
	be.PutUint32(f[64:], Checksum(f))
	_, err := w.WriteAt(f, l.Disk)
	return err
}

// Checksum is the one's complement of the sum of a footer's bytes, its
// checksum field read as zero.
func Checksum(footer []byte) uint32 {
	var sum uint32
	for i, b := range footer {
		if i < 64 || i >= 68 {
			sum += uint32(b)
		}
	}
	return ^sum
}
