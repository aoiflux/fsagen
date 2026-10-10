// Package ntfs lays out NTFS the way mkntfs formats it and Windows writes
// it. An empty volume is mkntfs's, byte for byte but for the boot code: its
// boot sector and backup, $MFT at 16 KiB with its bitmap before it, $MFTMirr
// and $LogFile (all 0xFF) in the middle of the volume, the root's security
// descriptor, index block, $AttrDef, $Bitmap, $Secure's $SDS and $UpCase
// packed after the MFT zone, and records 0 to 26 as mkntfs fills them.
//
// Files and directories the scenario makes are written as Windows writes
// them on NTFS 3.1: a record with a 72-byte $STANDARD_INFORMATION pointing
// at a security descriptor in $Secure, one $FILE_NAME in the Win32
// namespace (Win32 and DOS when the name is a valid upper-case 8.3 name,
// as Windows with short names off leaves it), and $DATA kept in the record
// until it no longer fits, then in clusters for good. A directory keeps its
// entries in $INDEX_ROOT until the record is full, then in one 4 KiB index
// block. Times are to 100 ns, and every record and index block is
// protected by its update sequence array.
//
// Deleting does what Windows does: the record loses its in-use flag and
// its sequence number goes up, but keeps its attributes, names and
// runlist; its clusters are freed with their bytes in place; the entry
// leaves its parent's index, and what was after it moves up over it.
package ntfs

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	sectorSize = 512
	// recordSize and indexSize are the MFT record and index block sizes
	// mkntfs and Windows use whatever the cluster size.
	recordSize = 1024
	indexSize  = 4096
	// systemRecords are the records mkntfs fills: 0 to 15, the unused 16 to
	// 23, and $Extend's $Quota, $ObjId and $Reparse.
	systemRecords = 27
	// firstUser is the first record a file or directory the scenario makes
	// can have; libntfs-3g, too, keeps the records below it for the system.
	firstUser = 64
	// mftGrowth is how many records $MFT grows by when it is full, as
	// libntfs-3g extends it.
	mftGrowth = 16
	// maxName is the longest name, in UTF-16 code units.
	maxName = 255
	// maxLabel is the longest volume label Windows accepts.
	maxLabel = 32
	// defaultCluster is the cluster size mkntfs and Windows give every
	// volume up to 16 TiB.
	defaultCluster = 4096
	maxCluster     = 2 << 20
)

// The system records.
const (
	recMFT     = 0
	recMFTMirr = 1
	recLogFile = 2
	recVolume  = 3
	recAttrDef = 4
	recRoot    = 5
	recBitmap  = 6
	recBoot    = 7
	recBadClus = 8
	recSecure  = 9
	recUpCase  = 10
	recExtend  = 11
	recQuota   = 24
	recObjID   = 25
	recReparse = 26
)

// Attribute types.
const (
	atStdInfo    = 0x10
	atFileName   = 0x30
	atObjectID   = 0x40
	atSecurity   = 0x50
	atVolName    = 0x60
	atVolInfo    = 0x70
	atData       = 0x80
	atIndexRoot  = 0x90
	atIndexAlloc = 0xA0
	atBitmap     = 0xB0
	atEnd        = 0xFFFFFFFF
)

// Record flags.
const (
	recInUse     = 0x0001
	recDir       = 0x0002
	recIs4       = 0x0004
	recViewIndex = 0x0008
)

// File attribute flags, in $STANDARD_INFORMATION and $FILE_NAME.
const (
	faReadOnly   = 0x00000001
	faHidden     = 0x00000002
	faSystem     = 0x00000004
	faArchive    = 0x00000020
	faI30Index   = 0x10000000
	faViewIndex  = 0x20000000
	faSysHidden  = faHidden | faSystem
	faExtendView = faSysHidden | faArchive | faViewIndex
)

// $FILE_NAME namespaces.
const (
	nsWin32    = 1
	nsWin32DOS = 3
)

// Collation rules.
const (
	collFileName = 0x01
	collULong    = 0x10
	collSID      = 0x11
	collSecHash  = 0x12
	collULongs   = 0x13
)

// Index entry flags, and index header flags.
const (
	ieNode  = 0x01
	ieEnd   = 0x02
	ihLarge = 0x01
)

// MinTime and MaxTime are the first and last instants NTFS can store: 100 ns
// ticks from 1601, in a signed 64-bit number.
var (
	MinTime = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	MaxTime = fromFiletime(1<<63 - 1)
)

// filetime is t in NTFS's 100 ns ticks from 1601.
func filetime(t time.Time) uint64 {
	s, ns := t.Unix(), int64(t.Nanosecond())
	return uint64((s+11644473600)*10_000_000 + ns/100)
}

func fromFiletime(v uint64) time.Time {
	t := int64(v)
	return time.Unix(t/10_000_000-11644473600, t%10_000_000*100).UTC()
}

// Geometry is where an NTFS volume keeps what, as mkntfs lays it out.
type Geometry struct {
	ClusterSize int
	// Sectors is the volume's length in sectors, less the last one, which
	// holds the backup boot sector; Clusters is how many clusters fit.
	Sectors  int64
	Clusters int64
	// BootClusters hold $Boot from cluster 0; MFTBitmap is $MFT's bitmap,
	// right after it, and MFT where $MFT starts, at 16 KiB at least.
	BootClusters int64
	MFTBitmap    int64
	MFT          int64
	// MFTRecords is how many records $MFT starts with: 27, or a cluster's
	// worth when a cluster holds more.
	MFTRecords int64
	// ZoneEnd is where the MFT zone ends, an eighth of the volume after
	// $MFT; mkntfs puts its other files from there.
	ZoneEnd int64
	// Mirror is $MFTMirr's first cluster, in the middle of the volume, and
	// MirrorClusters how many it has: four records' worth, or a cluster.
	Mirror, MirrorClusters int64
	// Log is $LogFile's first cluster, right after the mirror, and LogSize
	// its length in bytes.
	Log, LogSize int64
	// BitmapBytes is $Bitmap's length: a bit a cluster, in whole 8 bytes.
	BitmapBytes int64
}

// Plan works out the geometry mkntfs gives a volume of size bytes with
// clusters of clusterSize bytes (0 for its default).
func Plan(size int64, clusterSize int) (Geometry, error) {
	sectors := size/sectorSize - 1
	volSize := sectors * sectorSize
	if volSize < 1<<20 {
		return Geometry{}, fmt.Errorf("%d bytes are too small for NTFS, which needs 1 MiB", size)
	}
	if clusterSize == 0 {
		clusterSize = defaultCluster
		for volSize>>(bits.TrailingZeros(uint(clusterSize))+32) != 0 {
			clusterSize <<= 1
		}
	}
	if clusterSize&(clusterSize-1) != 0 || clusterSize < sectorSize || clusterSize > maxCluster {
		return Geometry{}, fmt.Errorf("an NTFS cluster is a power of two from %d bytes to 2 MiB, not %d", sectorSize, clusterSize)
	}
	cs := int64(clusterSize)
	g := Geometry{ClusterSize: clusterSize, Sectors: sectors, Clusters: volSize / cs}
	if g.Clusters>>32 != 0 {
		return Geometry{}, fmt.Errorf("NTFS numbers at most 2^32 clusters; %d bytes of %d-byte clusters are %d", size, cs, g.Clusters)
	}
	g.BitmapBytes = ((g.Clusters+7)/8 + 7) &^ 7
	g.BootClusters = ceil(8192, cs)
	g.MFTBitmap = g.BootClusters
	g.MFT = max(g.MFTBitmap+1, ceil(16384, cs))
	g.MFTRecords = max(systemRecords*recordSize, cs) / recordSize
	g.ZoneEnd = g.MFT + g.Clusters/8
	g.Mirror = sectors * sectorSize / 2 / cs
	g.MirrorClusters = ceil(4*recordSize, cs)
	g.Log = g.Mirror + g.MirrorClusters
	clusterBytes := g.Clusters * cs
	switch {
	case clusterBytes < 2<<20:
		g.LogSize = 256 << 10
	case clusterBytes < 4_000_000:
		g.LogSize = 512 << 10
	case clusterBytes <= 200<<20:
		g.LogSize = 2 << 20
	case clusterBytes >= 12<<30:
		g.LogSize = 64 << 20
	default:
		g.LogSize = clusterBytes / 200 &^ (cs - 1)
	}
	for g.Log+g.LogSize/cs >= g.Clusters {
		g.LogSize >>= 1
	}
	g.LogSize = (g.LogSize + cs - 1) &^ (cs - 1)
	if g.LogSize < 256<<10 {
		return Geometry{}, fmt.Errorf("%d bytes leave no room for the 256 KiB $LogFile NTFS needs", size)
	}
	return g, nil
}

func ceil(n, d int64) int64 { return (n + d - 1) / d }

// mftClusters is how many clusters $MFT starts with.
func (g Geometry) mftClusters() int64 { return ceil(g.MFTRecords*recordSize, int64(g.ClusterSize)) }

// offset is where cluster c starts on the volume.
func (g Geometry) offset(c int64) int64 { return c * int64(g.ClusterSize) }

// indexClusters is how many clusters an index block takes, and indexVCN
// how many VCNs one index block is apart from the next: clusters, or
// 512-byte blocks when a cluster is bigger than an index block.
func (g Geometry) indexClusters() int64 { return ceil(indexSize, int64(g.ClusterSize)) }

func (g Geometry) perIndexBlock() byte {
	if indexSize >= g.ClusterSize {
		return byte(indexSize / g.ClusterSize)
	}
	return indexSize / sectorSize
}

// sizeByte is how the boot sector gives a record of n bytes: in clusters,
// or as minus the power of two of its bytes when it is smaller than one.
func (g Geometry) sizeByte(n int) byte {
	if n >= g.ClusterSize {
		return byte(n / g.ClusterSize)
	}
	return byte(-bits.TrailingZeros(uint(n)))
}

// bootSector is the volume's first sector, and its last's: mkntfs's, for a
// partition hidden sectors into its disk, but with no boot code.
func bootSector(g Geometry, hidden uint32, serial uint64) []byte {
	b := make([]byte, sectorSize)
	le := binary.LittleEndian
	copy(b, []byte{0xEB, 0x52, 0x90})
	copy(b[3:], "NTFS    ")
	le.PutUint16(b[0x0B:], sectorSize)
	spc := g.ClusterSize / sectorSize
	if spc > 128 {
		b[0x0D] = byte(257 - (bits.TrailingZeros(uint(spc)) + 1))
	} else {
		b[0x0D] = byte(spc)
	}
	b[0x15] = 0xF8              // a fixed disk
	le.PutUint16(b[0x18:], 63)  // sectors per track
	le.PutUint16(b[0x1A:], 255) // heads
	le.PutUint32(b[0x1C:], hidden)
	b[0x24] = 0x80 // drive number
	b[0x26] = 0x80 // extended boot signature, as everyone sets it
	le.PutUint64(b[0x28:], uint64(g.Sectors))
	le.PutUint64(b[0x30:], uint64(g.MFT))
	le.PutUint64(b[0x38:], uint64(g.Mirror))
	b[0x40] = g.sizeByte(recordSize)
	b[0x44] = g.sizeByte(indexSize)
	le.PutUint64(b[0x48:], serial)
	b[0x1FE], b[0x1FF] = 0x55, 0xAA
	return b
}

// run is length clusters from lcn, or a hole when lcn is -1.
type run struct{ lcn, length int64 }

// significant is how many bytes n takes as a signed number.
func significant(n int64) int {
	l := uint64(n)
	if n < 0 {
		l = ^l
	}
	i := 1
	if l >= 128 {
		l >>= 7
		for {
			i++
			l >>= 8
			if l == 0 {
				break
			}
		}
	}
	return i
}

// mappingPairs encodes runs as a runlist: each run's length and its start
// relative to the last run's, in as few bytes as they take, and a 0.
func mappingPairs(runs []run) []byte {
	var out []byte
	last := int64(0)
	for _, r := range runs {
		lb := significant(r.length)
		ob := 0
		if r.lcn >= 0 {
			ob = significant(r.lcn - last)
		}
		out = append(out, byte(ob<<4|lb))
		for i := range lb {
			out = append(out, byte(r.length>>(8*i)))
		}
		if r.lcn >= 0 {
			d := r.lcn - last
			for i := range ob {
				out = append(out, byte(d>>(8*i)))
			}
			last = r.lcn
		}
	}
	return append(out, 0)
}

// decodeRuns reads a runlist.
func decodeRuns(b []byte) ([]run, error) {
	var out []run
	last := int64(0)
	for i := 0; i < len(b) && b[i] != 0; {
		lb, ob := int(b[i]&0x0F), int(b[i]>>4)
		i++
		if lb == 0 || lb > 8 || ob > 8 || i+lb+ob > len(b) {
			return nil, fmt.Errorf("a malformed runlist")
		}
		length := signed(b[i : i+lb])
		i += lb
		r := run{lcn: -1, length: length}
		if ob > 0 {
			last += signed(b[i : i+ob])
			i += ob
			r.lcn = last
		}
		if length <= 0 || r.lcn < -1 {
			return nil, fmt.Errorf("a malformed runlist")
		}
		out = append(out, r)
	}
	return out, nil
}

// signed reads b as a little-endian signed number.
func signed(b []byte) int64 {
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	if s := 64 - 8*len(b); s > 0 {
		v = v << s >> s
	}
	return v
}

// protect fills b's update sequence array: the last two bytes of every
// sector go into it and are replaced by the update sequence number usn.
func protect(b []byte, usn uint16) {
	le := binary.LittleEndian
	ofs, n := int(le.Uint16(b[4:])), int(le.Uint16(b[6:]))
	le.PutUint16(b[ofs:], usn)
	for i := 1; i < n; i++ {
		end := i*sectorSize - 2
		copy(b[ofs+2*i:], b[end:end+2])
		le.PutUint16(b[end:], usn)
	}
}

// unprotect checks and undoes protect.
func unprotect(b []byte) error {
	le := binary.LittleEndian
	ofs, n := int(le.Uint16(b[4:])), int(le.Uint16(b[6:]))
	if ofs+2*n > len(b) || n == 0 || (n-1)*sectorSize > len(b) {
		return fmt.Errorf("a malformed update sequence array")
	}
	usn := le.Uint16(b[ofs:])
	for i := 1; i < n; i++ {
		end := i*sectorSize - 2
		if le.Uint16(b[end:]) != usn {
			return fmt.Errorf("sector %d was torn: its update sequence number is wrong", i-1)
		}
		copy(b[end:end+2], b[ofs+2*i:])
	}
	return nil
}

// utf16le is s as NTFS stores a name.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func fromUTF16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// attrDefs is $AttrDef: every attribute type NTFS 3.1 knows, with its
// flags and its least and greatest size, as Windows and mkntfs write it.
var attrDefs = []struct {
	name     string
	typ      uint32
	flags    uint32
	min, max int64
}{
	{"$STANDARD_INFORMATION", atStdInfo, 0x40, 0x30, 0x48},
	{"$ATTRIBUTE_LIST", 0x20, 0x80, 0, -1},
	{"$FILE_NAME", atFileName, 0x42, 0x44, 0x242},
	{"$OBJECT_ID", atObjectID, 0x40, 0, 0x100},
	{"$SECURITY_DESCRIPTOR", atSecurity, 0x80, 0, -1},
	{"$VOLUME_NAME", atVolName, 0x40, 2, 0x100},
	{"$VOLUME_INFORMATION", atVolInfo, 0x40, 0x0C, 0x0C},
	{"$DATA", atData, 0, 0, -1},
	{"$INDEX_ROOT", atIndexRoot, 0x40, 0, -1},
	{"$INDEX_ALLOCATION", atIndexAlloc, 0x80, 0, -1},
	{"$BITMAP", atBitmap, 0x80, 0, -1},
	{"$REPARSE_POINT", 0xC0, 0x80, 0, 0x4000},
	{"$EA_INFORMATION", 0xD0, 0x40, 8, 8},
	{"$EA", 0xE0, 0, 0, 0x10000},
	{"$LOGGED_UTILITY_STREAM", 0x100, 0x80, 0, 0x10000},
}

// attrDefBytes is $AttrDef's content: 160 bytes an attribute type, and an
// empty entry to end it, in 2560 bytes.
func attrDefBytes() []byte {
	b := make([]byte, 2560)
	le := binary.LittleEndian
	for i, d := range attrDefs {
		e := b[160*i:]
		copy(e, utf16le(d.name))
		le.PutUint32(e[128:], d.typ)
		le.PutUint32(e[140:], d.flags)
		le.PutUint64(e[144:], uint64(d.min))
		le.PutUint64(e[152:], uint64(d.max))
	}
	return b
}

// Security identifiers, as the binary SIDs NTFS keeps.
var (
	sidSystem    = sid(18)      // S-1-5-18, Local System
	sidAuthUsers = sid(11)      // S-1-5-11, Authenticated Users
	sidAdmins    = sid(32, 544) // S-1-5-32-544, Administrators
	sidUsers     = sid(32, 545) // S-1-5-32-545, Users
)

// sid is S-1-5 with the given sub-authorities.
func sid(subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, 5}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return b
}

// Access rights and ACE flags.
const (
	rightsFull       = 0x001F01FF // full control of a file or directory
	rightsModify     = 0x001301BF // read, write, execute and delete
	rightsReadExec   = 0x001200A9 // read and execute, or list a folder
	rightsSysRead    = 0x00120089 // read, for $AttrDef's and $Boot's
	rightsSysWrite   = 0x0012019F // read and write, for the other files'
	genericAll       = 0x10000000
	genericExecute   = 0x20000000
	genericWrite     = 0x40000000
	genericRead      = 0x80000000
	rightDelete      = 0x00010000
	aceObjectInherit = 0x01
	aceContainer     = 0x02
	aceInheritOnly   = 0x08
	aceInherited     = 0x10
	aceInheritable   = aceObjectInherit | aceContainer | aceInheritOnly
)

// ace is an access-allowed ACE.
type ace struct {
	flags byte
	mask  uint32
	sid   []byte
}

// Security descriptor control bits.
const (
	seDACLPresent     = 0x0004
	seDACLAutoInherit = 0x0400
	seSelfRelative    = 0x8000
)

// descriptor is a self-relative security descriptor: its DACL first, of
// aclSize bytes (0 for just what its ACEs take), then its owner and group.
func descriptor(control uint16, aces []ace, aclSize int, owner, group []byte) []byte {
	le := binary.LittleEndian
	var acl []byte
	for _, a := range aces {
		acl = append(acl, 0, a.flags, 0, 0)
		le.PutUint16(acl[len(acl)-2:], uint16(8+len(a.sid)))
		acl = le.AppendUint32(acl, a.mask)
		acl = append(acl, a.sid...)
	}
	size := 8 + len(acl)
	if aclSize > size {
		size = aclSize
	}
	b := make([]byte, 20+size, 20+size+len(owner)+len(group))
	b[0] = 1
	le.PutUint16(b[2:], control|seSelfRelative)
	le.PutUint32(b[4:], uint32(20+size))
	le.PutUint32(b[8:], uint32(20+size+len(owner)))
	le.PutUint32(b[16:], 20)
	d := b[20:]
	d[0] = 2
	le.PutUint16(d[2:], uint16(size))
	le.PutUint16(d[4:], uint16(len(aces)))
	copy(d[8:], acl)
	b = append(b, owner...)
	return append(b, group...)
}

// systemSD is the descriptor mkntfs gives a system file of its own: Local
// System and the Administrators may read it ($AttrDef and $Boot) or read
// and write it.
func systemSD(rec int) []byte {
	mask := uint32(rightsSysWrite)
	if rec == recAttrDef || rec == recBoot {
		mask = rightsSysRead
	}
	return descriptor(seDACLPresent, []ace{{0, mask, sidSystem}, {0, mask, sidAdmins}}, 0, sidSystem, sidAdmins)
}

// rootSD is the root directory's descriptor, as Windows Vista's disk
// management formats it, in an ACL mkntfs leaves 4 KiB long.
func rootSD() []byte {
	return descriptor(seDACLPresent, []ace{
		{0, rightsFull, sidAdmins},
		{aceInheritable, genericAll, sidAdmins},
		{0, rightsFull, sidSystem},
		{aceInheritable, genericAll, sidSystem},
		{0, rightsModify, sidAuthUsers},
		{aceInheritable, genericRead | genericWrite | genericExecute | rightDelete, sidAuthUsers},
		{0, rightsReadExec, sidUsers},
		{aceInheritable, genericRead | genericExecute, sidUsers},
	}, 0x1000, sidSystem, sidSystem)
}

// secureSDs are the two descriptors mkntfs puts in $Secure, which the
// system files' $STANDARD_INFORMATION point to by ID: 0x100 lets Local
// System and the Administrators read, 0x101 read and write.
var secureSDs = []struct {
	id uint32
	sd []byte
}{
	{0x100, descriptor(seDACLPresent, []ace{{0, rightsSysRead, sidSystem}, {0, rightsSysRead, sidAdmins}}, 0, sidAdmins, sidAdmins)},
	{0x101, descriptor(seDACLPresent, []ace{{0, rightsSysWrite, sidSystem}, {0, rightsSysWrite, sidAdmins}}, 0, sidAdmins, sidAdmins)},
}

// inheritedACEs are what the root's inheritable ACEs give what is made
// under it: its rights, made specific to files and directories, for each
// of the Administrators, Local System, Authenticated Users and Users.
var inheritedACEs = []struct {
	generic, specific uint32
	sid               []byte
}{
	{genericAll, rightsFull, sidAdmins},
	{genericAll, rightsFull, sidSystem},
	{genericRead | genericWrite | genericExecute | rightDelete, rightsModify, sidAuthUsers},
	{genericRead | genericExecute, rightsReadExec, sidUsers},
}

// fileSD and dirSD are the descriptors a file and a directory the scenario
// makes get: owned by the Administrators, with the ACEs they inherit from
// the root. A directory passes them on in turn, so it keeps each generic
// one too, inherit-only.
func fileSD() []byte {
	var aces []ace
	for _, a := range inheritedACEs {
		aces = append(aces, ace{aceInherited, a.specific, a.sid})
	}
	return descriptor(seDACLPresent|seDACLAutoInherit, aces, 0, sidAdmins, sidAdmins)
}

func dirSD() []byte {
	var aces []ace
	for _, a := range inheritedACEs {
		aces = append(aces, ace{aceInherited, a.specific, a.sid}, ace{aceInheritable | aceInherited, a.generic, a.sid})
	}
	return descriptor(seDACLPresent|seDACLAutoInherit, aces, 0, sidAdmins, sidAdmins)
}

// sdHash is the hash $Secure files a descriptor under: each 32-bit word
// added to the hash so far, rotated left by 3.
func sdHash(sd []byte) uint32 {
	var h uint32
	for i := 0; i+4 <= len(sd); i += 4 {
		h = bits.RotateLeft32(h, 3) + binary.LittleEndian.Uint32(sd[i:])
	}
	return h
}

// crc64 is the CRC Windows 8 keeps of $UpCase in $UpCase:$Info, which
// spares chkdsk calling the table obsolete.
func crc64(b []byte) uint64 {
	const poly = 0x9A6C9329AC4BC9B5
	var table [256]uint64
	for i := range table {
		c := uint64(i)
		for range 8 {
			if c&1 != 0 {
				c = poly ^ c>>1
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	crc := ^uint64(0)
	for _, x := range b {
		crc = table[byte(crc)^x] ^ crc>>8
	}
	return ^crc
}

// winIllegal are the characters a Win32 name cannot hold, besides the
// controls.
const winIllegal = `"*/:<>?\|`

// ValidName refuses a name Windows cannot make on NTFS: an empty one, "."
// or "..", one longer than 255 UTF-16 code units, or one holding a control
// character or one of "*/:<>?\|.
func ValidName(name string) error {
	switch {
	case name == "" || name == "." || name == "..":
		return fmt.Errorf("%q is not a file name", name)
	case len(utf16.Encode([]rune(name))) > maxName:
		return fmt.Errorf("%q is longer than the %d characters an NTFS name holds", name, maxName)
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(winIllegal, r) {
			return fmt.Errorf("%q holds %q, which a Windows name cannot", name, r)
		}
	}
	return nil
}

// ValidLabel refuses a label Windows would: longer than 32 characters, or
// holding a control character.
func ValidLabel(label string) error {
	if n := len(utf16.Encode([]rune(label))); n > maxLabel {
		return fmt.Errorf("an NTFS label has at most %d characters, and %q has %d", maxLabel, label, n)
	}
	if i := strings.IndexFunc(label, func(r rune) bool { return r < 0x20 }); i >= 0 {
		return fmt.Errorf("an NTFS label cannot hold control characters, and %q does", label)
	}
	return nil
}

// systemNames are the names the file system keeps at the root.
var systemNames = []string{"$AttrDef", "$BadClus", "$Bitmap", "$Boot", "$Extend", "$LogFile", "$MFT", "$MFTMirr", "$Secure", "$UpCase", "$Volume"}

// isDOSName reports whether Windows files name in both the Win32 and DOS
// namespaces: an 8.3 name of upper-case ASCII it could hold as a short
// name, with at most one dot.
func isDOSName(name string) bool {
	base, ext, dotted := strings.Cut(name, ".")
	if base == "" || len(base) > 8 || len(ext) > 3 || dotted && ext == "" || strings.Contains(ext, ".") {
		return false
	}
	return !slices.ContainsFunc([]rune(base+ext), func(c rune) bool {
		return c <= ' ' || c >= 127 || c >= 'a' && c <= 'z' || strings.ContainsRune(`"*+,/:;<=>?[\]|`, c)
	})
}
