// Package fat lays out FAT32 the way Windows formats and writes it: a
// 32-sector reserved area with the boot sector, FSInfo and their backups,
// two FATs, the root directory in cluster 2, long names with the short
// names Windows would generate, and times in UTC.
//
// Deleting marks the name's entries 0xE5 and frees the cluster chain; the
// bytes stay where they were until something is written over them.
package fat

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aoiflux/libfat"
)

const (
	sectorSize      = 512
	reservedSectors = 32
	numFATs         = 2
	fsInfoSector    = 1
	backupBoot      = 6
	// maxClusters is the most whose numbers fit in a FAT32 entry.
	maxClusters = 0x0FFFFFF5 - 2
)

// Geometry is where a FAT32 volume keeps what.
type Geometry struct {
	Sectors     uint32 // the volume's sectors
	SecPerClus  int
	ClusterSize int
	FATSectors  uint32 // sectors in each FAT
	Clusters    int    // data clusters, numbered from 2
}

// DefaultClusterSize is the cluster size Windows formats a FAT32 volume of
// size bytes with.
func DefaultClusterSize(size int64) int {
	const mib = 1 << 20
	switch {
	case size <= 64*mib:
		return 512
	case size <= 128*mib:
		return 1024
	case size <= 256*mib:
		return 2048
	case size <= 8192*mib:
		return 4096
	case size <= 16384*mib:
		return 8192
	case size <= 32768*mib:
		return 16384
	}
	return 32768
}

// Plan works out the geometry of a FAT32 volume of size bytes with
// clusters of clusterSize bytes (0 for Windows' default), as Microsoft's
// specification sizes the FATs.
func Plan(size int64, clusterSize int) (Geometry, error) {
	if clusterSize == 0 {
		clusterSize = DefaultClusterSize(size)
	}
	if clusterSize < sectorSize || clusterSize > 32768 || clusterSize&(clusterSize-1) != 0 {
		return Geometry{}, fmt.Errorf("a FAT32 cluster is a power of two from 512 to 32768 bytes, not %d", clusterSize)
	}
	sectors := min(size/sectorSize, 0xFFFFFFFF)
	spc := int64(clusterSize / sectorSize)
	per := (256*spc + numFATs) / 2
	fatSz := (sectors - reservedSectors + per - 1) / per
	clusters := (sectors - reservedSectors - numFATs*fatSz) / spc
	g := Geometry{Sectors: uint32(sectors), SecPerClus: int(spc), ClusterSize: clusterSize, FATSectors: uint32(fatSz), Clusters: int(clusters)}
	switch {
	case clusters < libfat.FAT32MinClusters:
		need := (libfat.FAT32MinClusters*spc + reservedSectors + numFATs*((libfat.FAT32MinClusters+2)*4+sectorSize-1)/sectorSize) * sectorSize
		return Geometry{}, fmt.Errorf("a FAT32 volume needs at least %d clusters, and %d bytes of %d-byte clusters make %d: give the volume at least %d MiB, or smaller clusters", libfat.FAT32MinClusters, size, clusterSize, clusters, (need+1<<20-1)>>20)
	case clusters > maxClusters:
		return Geometry{}, fmt.Errorf("%d clusters are more than FAT32 can number; use larger clusters", clusters)
	}
	return g, nil
}

// fatOffset is where FAT number i (0 or 1) starts.
func (g Geometry) fatOffset(i int) int64 {
	return int64(reservedSectors+uint32(i)*g.FATSectors) * sectorSize
}

// dataSector is the first sector of cluster 2.
func (g Geometry) dataSector() int64 {
	return reservedSectors + numFATs*int64(g.FATSectors)
}

// clusterOffset is where cluster c starts.
func (g Geometry) clusterOffset(c uint32) int64 {
	return g.dataSector()*sectorSize + int64(c-2)*int64(g.ClusterSize)
}

// address is The Sleuth Kit's number for the directory entry at off: the
// entries of the data area counted from 3, root being 2.
func (g Geometry) address(off int64) int64 {
	return off/libfat.DirEntrySize - g.dataSector()*(sectorSize/libfat.DirEntrySize) + 3
}

// bootSector is the volume's first sector, and its backup's.
func bootSector(g Geometry, hidden uint32, serial uint32, label string) []byte {
	b := make([]byte, sectorSize)
	le := binary.LittleEndian
	copy(b, []byte{0xEB, 0x58, 0x90})
	copy(b[3:], "MSDOS5.0")
	le.PutUint16(b[11:], sectorSize)
	b[13] = byte(g.SecPerClus)
	le.PutUint16(b[14:], reservedSectors)
	b[16] = numFATs
	b[21] = libfat.MediaFixed
	le.PutUint16(b[24:], 63)  // sectors per track
	le.PutUint16(b[26:], 255) // heads
	le.PutUint32(b[28:], hidden)
	le.PutUint32(b[32:], g.Sectors)
	le.PutUint32(b[36:], g.FATSectors)
	le.PutUint32(b[44:], libfat.DefaultRootCluster)
	le.PutUint16(b[48:], fsInfoSector)
	le.PutUint16(b[50:], backupBoot)
	b[64] = 0x80 // drive number
	b[66] = 0x29 // extended boot signature
	le.PutUint32(b[67:], serial)
	copy(b[71:82], padLabel(label))
	copy(b[82:90], libfat.FAT32Signature)
	le.PutUint16(b[510:], libfat.BootSectorMagic)
	return b
}

// fsInfo is the FSInfo sector: the free cluster count and where to look
// for the next free cluster.
func fsInfo(free, next int) []byte {
	b := make([]byte, sectorSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], libfat.FSInfoLeadSig)
	le.PutUint32(b[484:], libfat.FSInfoStructSig)
	le.PutUint32(b[488:], uint32(free))
	le.PutUint32(b[492:], uint32(next))
	le.PutUint32(b[508:], libfat.FSInfoTrailSig)
	return b
}

// noLabel is what the boot sector holds for a volume with no label.
const noLabel = "NO NAME"

func padLabel(label string) []byte {
	if label == "" {
		label = noLabel
	}
	b := []byte("           ")
	copy(b, label)
	return b
}

// ValidLabel refuses a label FAT cannot hold: more than 11 characters, or
// any a short name cannot hold. Windows stores a label upper case.
func ValidLabel(label string) error {
	if len(label) > 11 {
		return fmt.Errorf("a FAT label has at most 11 characters, and %q has %d", label, len(label))
	}
	for _, c := range label {
		if _, ok := shortChar(c); !ok && c != ' ' {
			return fmt.Errorf("a FAT label cannot hold %q", c)
		}
	}
	return nil
}

// Times as a directory entry keeps them: dates count days from 1980 in
// local time, which an image built here keeps in UTC.

// MinTime and MaxTime are the first and last instants FAT can store.
var (
	MinTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	MaxTime = time.Date(2107, 12, 31, 23, 59, 59, 990_000_000, time.UTC)
)

// stamp writes the times into a short entry: the creation time to 10 ms,
// the write time to 2 s, the access date to the day. Zero times are left.
func stamp(e []byte, atime, mtime, btime time.Time) {
	le := binary.LittleEndian
	if !btime.IsZero() {
		date, clock, tenths := libfat.EncodeDateTime(btime)
		e[13] = tenths
		le.PutUint16(e[14:], clock)
		le.PutUint16(e[16:], date)
	}
	if !atime.IsZero() {
		date, _, _ := libfat.EncodeDateTime(atime)
		le.PutUint16(e[18:], date)
	}
	if !mtime.IsZero() {
		date, clock, _ := libfat.EncodeDateTime(mtime)
		le.PutUint16(e[22:], clock)
		le.PutUint16(e[24:], date)
	}
}

// firstCluster reads and setFirst writes the cluster a short entry starts
// at.
func firstCluster(e []byte) uint32 {
	le := binary.LittleEndian
	return uint32(le.Uint16(e[20:]))<<16 | uint32(le.Uint16(e[26:]))
}

func setFirst(e []byte, c uint32) {
	le := binary.LittleEndian
	le.PutUint16(e[20:], uint16(c>>16))
	le.PutUint16(e[26:], uint16(c))
}
