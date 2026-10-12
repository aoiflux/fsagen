package container

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libtable"
)

// The partition types of the GPT layout Windows Setup makes, as their GUIDs
// are written.
const (
	TypeEFISystem   = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	TypeMSReserved  = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
	TypeBasicData   = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
	TypeWinRecovery = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
)

// Partition attributes: required by the platform, and no drive letter.
const (
	attrRequired      = 1 << 0
	attrNoDriveLetter = 1 << 63
)

// The sizes of the Windows layout's partitions on a disk of fullDisk or
// more: the EFI system partition and the Microsoft reserved partition as
// Windows Setup makes them, and a recovery partition. On a smaller disk
// each shrinks in proportion, to no less than its least size: the EFI
// system partition must hold FAT32's 65,525 clusters of 512 bytes, and the
// recovery partition the smallest NTFS volume worth formatting.
const (
	fullDisk    = 64 << 30
	espFull     = 100 << 20
	msrFull     = 16 << 20
	recFull     = 512 << 20
	espLeast    = 33 << 20
	msrLeast    = 1 << 20
	recLeast    = 4 << 20
	gptEntries  = 128
	gptEntryLen = 128
	// gptTableLBAs is how many sectors 128 entries of 128 bytes take.
	gptTableLBAs = gptEntries * gptEntryLen / sector
	// align is where every partition starts and how it is sized: on a MiB,
	// as Windows aligns them.
	align = 1 << 20
)

// Part is one partition of a GPT disk.
type Part struct {
	// Type is the partition type GUID, Name its label and Attrs its
	// attribute bits.
	Type  string
	Name  string
	Attrs uint64
	// Offset and Size are where it is on the disk, in bytes.
	Offset, Size int64
}

// gptParts lays out the partitions of a GPT disk of disk bytes as Windows
// Setup lays a system disk out: the EFI system partition, the Microsoft
// reserved partition, the Windows partition (basic data, which holds the
// file system), and the recovery partition at the end, each named as
// diskpart names it. It returns the index of the basic data partition.
func gptParts(disk int64) ([]Part, int, error) {
	scale := func(full, least int64) int64 {
		n := full
		if disk < fullDisk {
			n = full / (fullDisk / align) * (disk / align)
		}
		return max(n/align*align, least)
	}
	esp, msr, rec := scale(espFull, espLeast), scale(msrFull, msrLeast), scale(recFull, recLeast)
	// The last sector a partition may use, then the start of the recovery
	// partition: as close to it as a MiB boundary allows.
	lastUsable := disk/sector - 1 - 1 - gptTableLBAs
	recStart := ((lastUsable+1)*sector - rec) / align * align
	parts := []Part{
		{Type: TypeEFISystem, Name: "EFI system partition", Attrs: attrNoDriveLetter, Offset: align, Size: esp},
		{Type: TypeMSReserved, Name: "Microsoft reserved partition", Attrs: attrNoDriveLetter, Offset: align + esp, Size: msr},
		{Type: TypeBasicData, Name: "Basic data partition", Offset: align + esp + msr},
		{Type: TypeWinRecovery, Name: "Basic data partition", Attrs: attrRequired | attrNoDriveLetter, Offset: recStart, Size: rec},
	}
	parts[2].Size = recStart - parts[2].Offset
	if parts[2].Size < align {
		return nil, 0, fmt.Errorf("a %d-byte disk is too small for Windows' GPT layout, which takes %d MiB before the Windows partition and %d MiB after it", disk, (align+esp+msr)>>20, rec>>20)
	}
	return parts, 2, nil
}

// WriteGPT writes a GPT disk's tables: the protective MBR, the primary
// header and entries after it, and their backups at the end of the disk,
// with the disk's and each partition's GUID drawn from key.
func WriteGPT(w io.WriterAt, l Layout, key prng.Key) error {
	if l.Partition != PartitionGPT {
		return nil
	}
	le := binary.LittleEndian
	last := uint64(l.Disk/sector - 1)

	mbr := make([]byte, sector)
	e := libtable.MBREntry{
		FirstCHS: [3]byte{0x00, 0x02, 0x00},
		Type:     libtable.MBRTypeGPTProtective,
		LastCHS:  [3]byte{0xFF, 0xFF, 0xFF},
		StartLBA: 1,
		SizeLBA:  uint32(min(last, 0xFFFFFFFF)),
	}.Marshal()
	copy(mbr[libtable.MBREntryOffset:], e[:])
	le.PutUint16(mbr[libtable.MBRSignatureOffset:], libtable.MBRSignature)
	if _, err := w.WriteAt(mbr, 0); err != nil {
		return err
	}

	table := make([]byte, gptEntries*gptEntryLen)
	for i, p := range l.Parts {
		b := table[i*gptEntryLen:]
		copy(b[0:], guidBytes(p.Type))
		copy(b[16:], randomGUID(key.Derive("partition-guid", strconv.Itoa(i))))
		le.PutUint64(b[32:], uint64(p.Offset/sector))
		le.PutUint64(b[40:], uint64((p.Offset+p.Size)/sector-1))
		le.PutUint64(b[48:], p.Attrs)
		for j, c := range utf16.Encode([]rune(p.Name)) {
			le.PutUint16(b[56+2*j:], c)
		}
	}
	tableCRC := crc32.ChecksumIEEE(table)
	disk := randomGUID(key.Derive("disk-guid"))
	header := func(self, alt, entries uint64) []byte {
		h := make([]byte, sector)
		copy(h, "EFI PART")
		le.PutUint32(h[8:], 0x00010000)
		le.PutUint32(h[12:], 92)
		le.PutUint64(h[24:], self)
		le.PutUint64(h[32:], alt)
		le.PutUint64(h[40:], 2+gptTableLBAs)
		le.PutUint64(h[48:], last-1-gptTableLBAs)
		copy(h[56:], disk)
		le.PutUint64(h[72:], entries)
		le.PutUint32(h[80:], gptEntries)
		le.PutUint32(h[84:], gptEntryLen)
		le.PutUint32(h[88:], tableCRC)
		le.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
		return h
	}
	backupTable := last - gptTableLBAs
	for _, x := range []struct {
		at   uint64
		data []byte
	}{
		{1, header(1, last, 2)},
		{2, table},
		{backupTable, table},
		{last, header(last, 1, backupTable)},
	} {
		if _, err := w.WriteAt(x.data, int64(x.at)*sector); err != nil {
			return err
		}
	}
	return nil
}

// guidBytes is a GUID as GPT stores it: its first three fields little
// endian, the rest as written.
func guidBytes(s string) []byte {
	raw, _ := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], binary.BigEndian.Uint32(raw[0:]))
	binary.LittleEndian.PutUint16(b[4:], binary.BigEndian.Uint16(raw[4:]))
	binary.LittleEndian.PutUint16(b[6:], binary.BigEndian.Uint16(raw[6:]))
	copy(b[8:], raw[8:])
	return b
}

// randomGUID is a random (version 4) GUID drawn from k, as GPT stores it.
func randomGUID(k prng.Key) []byte {
	b := k.Stream().Bytes(16)
	b[7] = b[7]&0x0F | 0x40
	b[8] = b[8]&0x3F | 0x80
	return b
}
