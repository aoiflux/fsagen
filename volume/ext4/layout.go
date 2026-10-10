// Package ext4 lays out ext4 the way mke2fs formats it and Linux writes it.
// The geometry is mke2fs's for the volume's size: its block size, inode
// ratio and reserved blocks, block groups with superblock and descriptor
// backups in groups 0, 1 and the powers of 3, 5 and 7, each flex group's
// bitmaps and inode tables packed at its start, and lost+found made ready
// with 16 KiB of entries. Inodes are 256 bytes, with nanosecond times and a
// creation time; files keep their blocks in extent trees, and directories
// are linear lists of entries. Every structure carries its crc32c.
//
// The features are mke2fs's ext4 set less the journal, 64bit,
// resize_inode, dir_index, huge_file and ext_attr: filetype, extents and
// flex_bg; sparse_super, large_file, dir_nlink, extra_isize and
// metadata_csum.
//
// Deleting does what Linux has done since 5.14: the directory entry is
// wiped, folded into the one before it; the inode keeps its mode and times
// and gains a deletion time, but loses its size, its links and its extents;
// and the blocks are freed with their bytes left where they were.
package ext4

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"time"
)

const (
	superOffset = 1024
	superSize   = 1024
	magic       = 0xEF53
	inodeSize   = 256
	extraIsize  = 32
	firstIno    = 11
	rootIno     = 2
	lostFound   = 11
	descSize    = 32
	// lostFoundSize is how much room mke2fs gives lost+found, so that
	// e2fsck need not allocate blocks to reconnect files to it; see Format.
	lostFoundSize = 16384
	// linkMax is the most links an inode counts; a directory with more
	// subdirectories counts 1 (dir_nlink).
	linkMax = 65000
	// maxName is the longest name, in bytes.
	maxName = 255
	// logFlex is mke2fs's flex group size, 16 groups, as a power of two.
	logFlex  = 4
	flexSize = 1 << logFlex
	// tailSize is the fake entry that ends every directory block and holds
	// its checksum.
	tailSize = 12
)

// Feature and flag bits.
const (
	incompatFiletype = 0x0002
	incompatExtents  = 0x0040
	incompatFlexBG   = 0x0200
	roSparseSuper    = 0x0001
	roLargeFile      = 0x0002
	roDirNlink       = 0x0020
	roExtraIsize     = 0x0040
	roMetadataCsum   = 0x0400
	bgInodeUninit    = 0x0001
	bgBlockUninit    = 0x0002
	bgItableZeroed   = 0x0004
	flagExtents      = 0x00080000
	mountUserXattr   = 0x0004
	mountACL         = 0x0008
	flagSignedHash   = 0x0001
	hashHalfMD4      = 1
	csumCRC32c       = 1
	extentMagic      = 0xF30A
	tailFileType     = 0xDE
)

// Inode types, in i_mode.
const (
	modeFile    = 0x8000
	modeDir     = 0x4000
	modeSymlink = 0xA000
	modeType    = 0xF000
)

// Directory entry file types.
const (
	ftFile    = 1
	ftDir     = 2
	ftSymlink = 7
)

// MinTime and MaxTime are the first and last instants an inode can store:
// 32 bits of seconds from 1970, signed, and two more bits of epoch.
var (
	MinTime = time.Unix(math.MinInt32, 0).UTC()
	MaxTime = time.Unix(1<<34-1<<31-1, 999_999_999).UTC()
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// crc32c is the kernel's crc32c_le: no inversion before or after, so one
// checksum can seed the next.
func crc32c(seed uint32, b []byte) uint32 { return ^crc32.Update(^seed, castagnoli, b) }

// Geometry is where an ext4 volume keeps what.
type Geometry struct {
	BlockSize int
	Blocks    uint32
	// FirstData is the first block of group 0: 1 for 1 KiB blocks, whose
	// block 0 holds only the boot sector, else 0.
	FirstData      uint32
	BlocksPerGroup uint32
	Groups         int
	InodesPerGroup uint32
	// InodeBlocks are each group's inode table blocks, and DescBlocks the
	// group descriptor table's.
	InodeBlocks uint32
	DescBlocks  uint32
	// Reserved are the blocks kept for root.
	Reserved uint32
	// BlockBitmaps, InodeBitmaps and InodeTables are where each group's
	// are, packed at the start of its flex group.
	BlockBitmaps, InodeBitmaps, InodeTables []uint32
}

// DefaultBlockSize is the block size mke2fs gives every volume.
const DefaultBlockSize = 4096

// inodeRatio is the bytes per inode mke2fs gives a volume of size bytes:
// its floppy, small, default, big and huge types.
func inodeRatio(size int64) int64 {
	const mib = 1 << 20
	switch {
	case size < 3*mib:
		return 8192
	case size < 512*mib:
		return 4096
	case size < 4<<40:
		return 16384
	case size < 16<<40:
		return 32768
	}
	return 65536
}

// Plan works out the geometry mke2fs gives a volume of size bytes with
// blocks of blockSize bytes (0 for its default), as ext2fs_initialize does:
// a last group too small to be worth its bookkeeping is dropped.
func Plan(size int64, blockSize int) (Geometry, error) {
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if blockSize != 1024 && blockSize != 2048 && blockSize != 4096 {
		return Geometry{}, fmt.Errorf("an ext4 block is 1024, 2048 or 4096 bytes, not %d", blockSize)
	}
	bs := int64(blockSize)
	blocks := size / bs
	if blocks > math.MaxUint32 {
		return Geometry{}, fmt.Errorf("ext4 without the 64bit feature numbers at most 2^32 blocks; %d bytes of %d-byte blocks are %d", size, bs, blocks)
	}
	g := Geometry{BlockSize: blockSize, BlocksPerGroup: uint32(8 * bs)}
	if bs == 1024 {
		g.FirstData = 1
	}
	inodes := max(blocks*bs/inodeRatio(blocks*bs), firstIno+1)
	// mke2fs reserves 5% for root, and keeps the same share of what is left
	// when the last group is dropped, both in floating point.
	reserved0 := uint64(5.0 * float64(blocks) / 100.0)
	ratio := 100.0 * float64(reserved0) / float64(blocks)
	bpg := int64(g.BlocksPerGroup)
	first := int64(g.FirstData)
	for {
		groups := (blocks - first + bpg - 1) / bpg
		if groups <= 0 {
			return Geometry{}, fmt.Errorf("%d bytes are too small for ext4", size)
		}
		ipg := (inodes + groups - 1) / groups
		if ipg > 8*bs {
			return Geometry{}, fmt.Errorf("%d bytes need more inodes per group than a %d-byte block can map", size, bs)
		}
		// The inodes fill whole inode table blocks, in eights.
		itb := (ipg*inodeSize + bs - 1) / bs
		ipg = max(itb*bs/inodeSize, 8) &^ 7
		itb = (ipg*inodeSize + bs - 1) / bs
		desc := (groups*descSize + bs - 1) / bs
		last := 2 + itb
		if hasSuper(int(groups - 1)) {
			last += 1 + desc
		}
		rem := (blocks - first) % bpg
		if groups == 1 && rem != 0 && rem < last {
			return Geometry{}, fmt.Errorf("%d bytes are too small for ext4", size)
		}
		if rem != 0 && rem < last+50 {
			blocks -= rem
			continue
		}
		g.Blocks, g.Groups = uint32(blocks), int(groups)
		g.InodesPerGroup, g.InodeBlocks, g.DescBlocks = uint32(ipg), uint32(itb), uint32(desc)
		break
	}
	g.Reserved = uint32(ratio * float64(g.Blocks) / 100.0)
	used := g.placeTables()
	if free := int64(g.groupBlocks(0)) - int64(used.countIn(g.start(0), g.groupBlocks(0))); free < 1+lostFoundSize/bs+1 {
		return Geometry{}, fmt.Errorf("%d bytes leave no room in ext4's first block group for the root directory and lost+found", size)
	}
	return g, nil
}

// hasSuper reports whether group i keeps a copy of the superblock and the
// group descriptors (sparse_super): groups 0 and 1 and the powers of 3, 5
// and 7.
func hasSuper(i int) bool {
	if i <= 1 {
		return true
	}
	for _, b := range []int{3, 5, 7} {
		n := b
		for n < i {
			n *= b
		}
		if n == i {
			return true
		}
	}
	return false
}

// Inodes is how many inodes the volume has.
func (g Geometry) Inodes() uint32 { return g.InodesPerGroup * uint32(g.Groups) }

// start is group i's first block, and last its last.
func (g Geometry) start(i int) uint32 { return g.FirstData + uint32(i)*g.BlocksPerGroup }
func (g Geometry) last(i int) uint32  { return g.start(i) + g.groupBlocks(i) - 1 }

// groupBlocks is how many blocks group i has; only the last may be short.
func (g Geometry) groupBlocks(i int) uint32 {
	if i == g.Groups-1 {
		return g.Blocks - g.start(i)
	}
	return g.BlocksPerGroup
}

// meta is how many blocks group i's superblock and descriptor copies take.
func (g Geometry) meta(i int) uint32 {
	if hasSuper(i) {
		return 1 + g.DescBlocks
	}
	return 0
}

func (g Geometry) blockBitmap(i int) uint32 { return g.BlockBitmaps[i] }
func (g Geometry) inodeBitmap(i int) uint32 { return g.InodeBitmaps[i] }
func (g Geometry) inodeTable(i int) uint32  { return g.InodeTables[i] }

// group is the group block b is in.
func (g Geometry) group(b uint32) int { return int((b - g.FirstData) / g.BlocksPerGroup) }

// offset is where block b starts.
func (g Geometry) offset(b uint32) int64 { return int64(b) * int64(g.BlockSize) }

// inodeOffset is where inode ino lies.
func (g Geometry) inodeOffset(ino uint32) int64 {
	i := (ino - 1) / g.InodesPerGroup
	return g.offset(g.inodeTable(int(i))) + int64((ino-1)%g.InodesPerGroup)*inodeSize
}

// superAt is where group i's copy of the superblock lies: 1024 bytes in
// for the primary, at the group's first block for a backup.
func (g Geometry) superAt(i int) int64 {
	if i == 0 {
		return superOffset
	}
	return g.offset(g.start(i))
}

// blockSet is a set of blocks.
type blockSet []uint64

func (s blockSet) has(b uint32) bool { return s[b/64]&(1<<(b%64)) != 0 }
func (s blockSet) add(b, n uint32) {
	for k := b; k < b+n; k++ {
		s[k/64] |= 1 << (k % 64)
	}
}

// countIn is how many of the n blocks from b are in the set.
func (s blockSet) countIn(b, n uint32) int {
	c := 0
	for k := b; k < b+n; k++ {
		if s.has(k) {
			c++
		}
	}
	return c
}

// placeTables lays each group's bitmaps and inode table out as mke2fs does
// with flex_bg (ext2fs_allocate_group_table), and returns every block the
// superblocks, descriptors, bitmaps and tables take.
func (g *Geometry) placeTables() blockSet {
	used := make(blockSet, (uint64(g.Blocks)+63)/64)
	for i := range g.Groups {
		used.add(g.start(i), g.meta(i))
	}
	// free finds num free blocks in a row, searching from start until
	// finish, as ext2fs_get_free_blocks2 does: past the end it wraps to the
	// first block unless finish lies beyond start.
	free := func(start, finish, num uint32) (uint32, bool) {
		b := start
		if b == 0 {
			b = g.FirstData
		}
		if finish == 0 {
			finish = start
		}
		for {
			if uint64(b)+uint64(num)-1 >= uint64(g.Blocks) {
				if finish > start {
					return 0, false
				}
				b = g.FirstData
			}
			if used.countIn(b, num) == 0 {
				return b, true
			}
			if b++; b == finish {
				return 0, false
			}
		}
	}
	// offset is flexbg_offset: where to look for room for a flex group's
	// tables of elem blocks each, rem of them still to place.
	offset := func(group int, start uint32, rem int, elem uint32) uint32 {
		size := min(uint32(rem)*elem, g.BlocksPerGroup/4)
		if start != 0 && start < g.Blocks {
			if b, ok := free(start, start+size, elem); ok {
				return b
			}
		}
		start = g.start(group &^ (flexSize - 1))
		end := g.last(min(group|(flexSize-1), g.Groups-1))
		for _, try := range []struct{ from, n uint32 }{{start, size}, {start, elem}, {0, elem}} {
			if b, ok := free(try.from, end, try.n); ok {
				return b
			}
		}
		return 0
	}
	take := func(start, end, groupStart, n uint32) uint32 {
		b, ok := free(start, end, n)
		if !ok {
			b, _ = free(groupStart, end, n)
		}
		used.add(b, n)
		return b
	}
	g.BlockBitmaps = make([]uint32, g.Groups)
	g.InodeBitmaps = make([]uint32, g.Groups)
	g.InodeTables = make([]uint32, g.Groups)
	for i := range g.Groups {
		lastGrp := min(i|(flexSize-1), g.Groups-1)
		rem := lastGrp - i + 1
		end := g.last(lastGrp)
		tableOffset := uint32(flexSize)
		prev := uint32(0)
		if i%flexSize != 0 {
			prev = g.BlockBitmaps[i-1] + 1
		} else if lastGrp == g.Groups-1 {
			// The last flex group keeps its tables together.
			if tableOffset = uint32(lastGrp & (flexSize - 1)); tableOffset == 0 {
				tableOffset = flexSize
			} else {
				tableOffset++
			}
		}
		g.BlockBitmaps[i] = take(offset(i, prev, rem, 1), end, g.start(i), 1)
		if i%flexSize != 0 {
			prev = g.InodeBitmaps[i-1] + 1
		} else {
			prev = g.BlockBitmaps[i] + tableOffset
		}
		g.InodeBitmaps[i] = take(offset(i, prev, rem, 1), end, g.start(i), 1)
		if i%flexSize != 0 {
			prev = g.InodeTables[i-1] + g.InodeBlocks
		} else {
			prev = g.InodeBitmaps[i] + tableOffset
		}
		at := offset(i, prev, rem, g.InodeBlocks)
		b, _ := free(at, end, g.InodeBlocks)
		used.add(b, g.InodeBlocks)
		g.InodeTables[i] = b
	}
	return used
}

// counts are a volume's free blocks and inodes, overall and by group, and
// the state of each group's descriptor.
type counts struct {
	freeBlocks, freeInodes uint32
	groupBlocks            []uint16
	groupInodes, dirs      []uint16
	flags, itableUnused    []uint16
	// blockCsums and inodeCsums are each group's bitmaps' checksums.
	blockCsums, inodeCsums []uint16
}

// identity is what tells one volume from another.
type identity struct {
	uuid, hashSeed [16]byte
	label          string
	created        time.Time
}

// seed is what every metadata checksum starts from.
func (id identity) seed() uint32 { return crc32c(^uint32(0), id.uuid[:]) }

// superblock is group i's copy of the superblock.
func (g Geometry) superblock(i int, id identity, c counts) []byte {
	b := make([]byte, superSize)
	le := binary.LittleEndian
	created := uint32(id.created.Unix())
	le.PutUint32(b[0x00:], g.Inodes())
	le.PutUint32(b[0x04:], g.Blocks)
	le.PutUint32(b[0x08:], g.Reserved)
	le.PutUint32(b[0x0C:], c.freeBlocks)
	le.PutUint32(b[0x10:], c.freeInodes)
	le.PutUint32(b[0x14:], g.FirstData)
	log := uint32(0)
	for 1024<<log < g.BlockSize {
		log++
	}
	le.PutUint32(b[0x18:], log)
	le.PutUint32(b[0x1C:], log)
	le.PutUint32(b[0x20:], g.BlocksPerGroup)
	le.PutUint32(b[0x24:], g.BlocksPerGroup)
	le.PutUint32(b[0x28:], g.InodesPerGroup)
	le.PutUint32(b[0x30:], created) // last written
	le.PutUint16(b[0x36:], 0xFFFF)  // no maximum mount count
	le.PutUint16(b[0x38:], magic)
	if i == 0 {
		// The backups say nothing of the state: e2fsck checks the primary.
		le.PutUint16(b[0x3A:], 1) // clean
	}
	le.PutUint16(b[0x3C:], 1) // continue on errors
	le.PutUint32(b[0x40:], created)
	le.PutUint32(b[0x4C:], 1) // dynamic revision
	le.PutUint32(b[0x54:], firstIno)
	le.PutUint16(b[0x58:], inodeSize)
	le.PutUint16(b[0x5A:], uint16(i))
	le.PutUint32(b[0x60:], incompatFiletype|incompatExtents|incompatFlexBG)
	le.PutUint32(b[0x64:], roSparseSuper|roLargeFile|roDirNlink|roExtraIsize|roMetadataCsum)
	copy(b[0x68:0x78], id.uuid[:])
	copy(b[0x78:0x88], id.label)
	copy(b[0xEC:0xFC], id.hashSeed[:])
	b[0xFC] = hashHalfMD4
	le.PutUint32(b[0x100:], mountUserXattr|mountACL)
	le.PutUint32(b[0x108:], created)
	le.PutUint16(b[0x15C:], extraIsize)
	le.PutUint16(b[0x15E:], extraIsize)
	le.PutUint32(b[0x160:], flagSignedHash)
	b[0x174] = logFlex
	b[0x175] = csumCRC32c
	// The overhead counts the boot block too, when it is a block of its own.
	overhead := g.FirstData
	for k := range g.Groups {
		overhead += g.meta(k) + 2 + g.InodeBlocks
	}
	le.PutUint32(b[0x248:], overhead)
	le.PutUint32(b[0x3FC:], crc32c(^uint32(0), b[:0x3FC]))
	return b
}

// descriptors are the group descriptor table, in its blocks, each with
// its checksum: the low half of a crc32c of the group number and the
// descriptor, its checksum zeroed.
func (g Geometry) descriptors(seed uint32, c counts) []byte {
	b := make([]byte, int64(g.DescBlocks)*int64(g.BlockSize))
	le := binary.LittleEndian
	for i := range g.Groups {
		d := b[i*descSize : (i+1)*descSize]
		le.PutUint32(d[0:], g.blockBitmap(i))
		le.PutUint32(d[4:], g.inodeBitmap(i))
		le.PutUint32(d[8:], g.inodeTable(i))
		le.PutUint16(d[12:], c.groupBlocks[i])
		le.PutUint16(d[14:], c.groupInodes[i])
		le.PutUint16(d[16:], c.dirs[i])
		le.PutUint16(d[18:], c.flags[i])
		le.PutUint16(d[24:], c.blockCsums[i])
		le.PutUint16(d[26:], c.inodeCsums[i])
		le.PutUint16(d[28:], c.itableUnused[i])
		var n [4]byte
		le.PutUint32(n[:], uint32(i))
		le.PutUint16(d[30:], uint16(crc32c(crc32c(seed, n[:]), d)))
	}
	return b
}

// ValidLabel refuses a label ext4 cannot hold: more than 16 bytes.
func ValidLabel(label string) error {
	if len(label) > 16 {
		return fmt.Errorf("an ext4 label has at most 16 bytes, and %q has %d", label, len(label))
	}
	return nil
}

// ValidName refuses a name ext4 cannot hold: more than 255 bytes.
func ValidName(name string) error {
	if len(name) > maxName {
		return fmt.Errorf("an ext4 name has at most %d bytes, and %q has %d", maxName, name, len(name))
	}
	return nil
}

// encodeTime is t as an inode keeps it: the low 32 bits of its seconds,
// and its nanoseconds shifted over two bits of epoch, which carry the
// seconds past 2038.
func encodeTime(t time.Time) (uint32, uint32) {
	if t.IsZero() {
		return 0, 0
	}
	s := t.Unix()
	epoch := uint32((s-int64(int32(s)))>>32) & 3
	return uint32(int32(s)), uint32(t.Nanosecond())<<2 | epoch
}

func decodeTime(lo, extra uint32) time.Time {
	s := int64(int32(lo)) + int64(extra&3)<<32
	return time.Unix(s, int64(extra>>2)).UTC()
}

// inode is an inode as the volume keeps it.
type inode struct {
	mode, links uint16
	size        int64
	// sectors is i_blocks: the 512-byte sectors the inode's blocks and
	// extent tree take.
	sectors                     uint32
	flags                       uint32
	atime, ctime, mtime, crtime time.Time
	dtime                       uint32
	gen                         uint32
	block                       [60]byte
}

// encode is inode ino's 256 bytes, its checksum included.
func (n *inode) encode(seed, ino uint32) []byte {
	b := make([]byte, inodeSize)
	le := binary.LittleEndian
	le.PutUint16(b[0:], n.mode)
	le.PutUint32(b[4:], uint32(n.size))
	a, ax := encodeTime(n.atime)
	c, cx := encodeTime(n.ctime)
	m, mx := encodeTime(n.mtime)
	cr, crx := encodeTime(n.crtime)
	le.PutUint32(b[8:], a)
	le.PutUint32(b[12:], c)
	le.PutUint32(b[16:], m)
	le.PutUint32(b[20:], n.dtime)
	le.PutUint16(b[26:], n.links)
	le.PutUint32(b[28:], n.sectors)
	le.PutUint32(b[32:], n.flags)
	copy(b[40:100], n.block[:])
	le.PutUint32(b[100:], n.gen)
	le.PutUint32(b[108:], uint32(n.size>>32))
	le.PutUint16(b[128:], extraIsize)
	le.PutUint32(b[132:], cx)
	le.PutUint32(b[136:], mx)
	le.PutUint32(b[140:], ax)
	le.PutUint32(b[144:], cr)
	le.PutUint32(b[148:], crx)
	setInodeCsum(b, seed, ino)
	return b
}

// inodeSeed is what the checksums of inode ino's own blocks (its extent
// tree and, for a directory, its entries) start from.
func inodeSeed(seed, ino, gen uint32) uint32 {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], ino)
	s := crc32c(seed, n[:])
	binary.LittleEndian.PutUint32(n[:], gen)
	return crc32c(s, n[:])
}

// setInodeCsum writes inode b's checksum: a crc32c of its number, its
// generation and itself with the checksum zeroed, in two halves, the high
// one only where the inode's extra fields reach it.
func setInodeCsum(b []byte, seed, ino uint32) {
	le := binary.LittleEndian
	hi := le.Uint16(b[128:]) >= 4
	le.PutUint16(b[124:], 0)
	if hi {
		le.PutUint16(b[130:], 0)
	}
	crc := crc32c(inodeSeed(seed, ino, le.Uint32(b[100:])), b)
	le.PutUint16(b[124:], uint16(crc))
	if hi {
		le.PutUint16(b[130:], uint16(crc>>16))
	}
}

// extent is a run of blocks: len blocks from start, holding the file's
// blocks from logical on.
type extent struct{ logical, start, len uint32 }

// maxExtent is the longest run one extent maps.
const maxExtent = 32768

// extents are the runs blocks make, in order.
func extents(blocks []uint32) []extent {
	var out []extent
	for i, b := range blocks {
		if n := len(out); n > 0 && out[n-1].start+out[n-1].len == b && out[n-1].len < maxExtent {
			out[n-1].len++
			continue
		}
		out = append(out, extent{uint32(i), b, 1})
	}
	return out
}

// header writes an extent tree node's header.
func header(b []byte, entries, max, depth int) {
	le := binary.LittleEndian
	le.PutUint16(b[0:], extentMagic)
	le.PutUint16(b[2:], uint16(entries))
	le.PutUint16(b[4:], uint16(max))
	le.PutUint16(b[6:], uint16(depth))
}

// setExtentTail writes the checksum after an extent block's last slot.
func setExtentTail(b []byte, seed uint32) {
	end := 12 + 12*int(binary.LittleEndian.Uint16(b[4:]))
	binary.LittleEndian.PutUint32(b[end:], crc32c(seed, b[:end]))
}

func putExtent(b []byte, e extent) {
	le := binary.LittleEndian
	le.PutUint32(b[0:], e.logical)
	le.PutUint16(b[4:], uint16(e.len))
	le.PutUint32(b[8:], e.start)
}

func putIndex(b []byte, logical, leaf uint32) {
	le := binary.LittleEndian
	le.PutUint32(b[0:], logical)
	le.PutUint32(b[4:], leaf)
}

// rootEntries is how many extents or indexes the inode itself holds.
const rootEntries = 4

// recLen is the room a directory entry with a name of n bytes takes.
func recLen(n int) int { return (8 + n + 3) &^ 3 }

// setDirTail writes the fake entry that ends directory block b and holds
// its checksum.
func setDirTail(b []byte, seed uint32) {
	le := binary.LittleEndian
	t := b[len(b)-tailSize:]
	clear(t)
	le.PutUint16(t[4:], tailSize)
	t[7] = tailFileType
	le.PutUint32(t[8:], crc32c(seed, b[:len(b)-tailSize]))
}
