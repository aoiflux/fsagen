// Package container wraps a file system in what holds it on disk: nothing
// (a raw volume image), an MBR partition table, or a GPT laid out as
// Windows Setup lays out a system disk; and optionally a fixed VHD footer,
// which is a raw disk with 512 bytes after it.
package container

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libtable"
	vhd "github.com/aoiflux/libvhdi/types"
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
	PartitionGPT  = "gpt"
)

// Partitions lists the partitioning schemes.
var Partitions = []string{PartitionMBR, PartitionGPT, PartitionNone}

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
	// Parts are a GPT disk's partitions, in table order.
	Parts []Part
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
		c, h, s := vhd.CHSGeometry(uint64(l.Disk / sector))
		l.Geometry = [3]int{int(c), int(h), int(s)}
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
	case PartitionGPT:
		parts, data, err := gptParts(l.Disk)
		if err != nil {
			return Layout{}, err
		}
		l.Parts = parts
		l.Offset, l.Size = parts[data].Offset, parts[data].Size
		return l, nil
	case PartitionNone:
	default:
		return Layout{}, fmt.Errorf("unknown partitioning %q (want %s)", partition, strings.Join(Partitions, ", "))
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
// (libtable.MBRTypeFAT32LBA, MBRTypeLinux or MBRTypeNTFS) and a disk
// signature drawn from key.
func WriteMBR(w io.WriterAt, l Layout, kind byte, key prng.Key) error {
	if l.Partition != PartitionMBR {
		return nil
	}
	mbr := make([]byte, sector)
	copy(mbr[libtable.MBRDiskSignatureOffset:], key.Derive("disk-signature").Stream().Bytes(4))
	start, count := uint64(MBRStart), uint64(l.Size/sector)
	e := libtable.MBREntry{
		FirstCHS: libtable.CHS(start, 255, 63),
		Type:     kind,
		LastCHS:  libtable.CHS(start+count-1, 255, 63),
		StartLBA: uint32(start),
		SizeLBA:  uint32(count),
	}.Marshal()
	copy(mbr[libtable.MBREntryOffset:], e[:])
	binary.LittleEndian.PutUint16(mbr[libtable.MBRSignatureOffset:], libtable.MBRSignature)
	_, err := w.WriteAt(mbr, 0)
	return err
}

// WriteFooter writes a fixed VHD's footer after the disk, stamped when and
// identified by an ID drawn from key.
func WriteFooter(w io.WriterAt, l Layout, when time.Time, key prng.Key) error {
	if l.Format != FormatVHD {
		return nil
	}
	f := vhd.FileFooter{
		Features:           vhd.FeatureReserved,
		FormatVersion:      vhd.FormatVersion1,
		NextOffset:         vhd.FixedDataOffset,
		ModificationTime:   vhd.Timestamp(when),
		CreatorApplication: binary.BigEndian.Uint32([]byte("fsag")),
		CreatorVersion:     0x00010000,
		CreatorOS:          vhd.CreatorOSWindows,
		OriginalSize:       uint64(l.Disk),
		CurrentSize:        uint64(l.Disk),
		DiskGeometry:       vhd.PackGeometry(uint16(l.Geometry[0]), uint8(l.Geometry[1]), uint8(l.Geometry[2])),
		DiskType:           uint32(vhd.DiskTypeFixed),
	}
	copy(f.Signature[:], vhd.VHDFooterSignature)
	copy(f.Identifier[:], key.Derive("vhd-id").Stream().Bytes(16))
	f.Checksum = vhd.FooterChecksum(&f)
	b, _ := f.MarshalBinary()
	_, err := w.WriteAt(b, l.Disk)
	return err
}
