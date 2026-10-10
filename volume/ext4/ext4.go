package ext4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// recentlyDeleted is how long after an inode is deleted Linux prefers not
// to reuse it, on a volume with no journal.
const recentlyDeleted = 60

// Options are what an ext4 volume is formatted with.
type Options struct {
	BlockSize int
	Label     string
	// UUID names the volume, and HashSeed seeds its directory hashes.
	UUID, HashSeed [16]byte
	// Clock is when the volume is made, and stamps what the file system
	// does at a time the scenario does not give.
	Clock time.Time
	// Alloc is the block allocation policy.
	Alloc string
	// Generations draws each new inode's generation number, which Linux
	// draws at random.
	Generations *prng.Stream
}

// FS is an ext4 volume being written.
type FS struct {
	dev   *volume.Device
	g     Geometry
	o     Options
	alloc *volume.Allocator
	// inodes are every inode in use or once used, by number; used says
	// which are in use. Each group has free of its inodes free, none below
	// its low-th.
	inodes    map[uint32]*inode
	used      []bool
	free, low []uint32
	dirs      []uint16
	// blockUninit and inodeUninit are the groups whose bitmaps mke2fs left
	// to be worked out, until something is allocated in them, and
	// itableUnused how many inodes at the end of each group's table were
	// never used.
	blockUninit, inodeUninit []bool
	itableUnused             []uint32
	// seed starts every checksum, and limit is how much of a directory
	// block entries may use: the rest holds its checksum.
	seed  uint32
	limit int
	res   *volume.Tracker
	root  *node
	now   time.Time
}

// node is an object's inode and where its content is.
type node struct {
	ino uint32
	in  *inode
	// blocks are its content's blocks in order, and leaves its extent
	// tree's leaf blocks when the inode cannot map them itself.
	blocks, leaves []uint32
	// data is a directory's blocks, as on disk.
	data []byte
}

// Caps is what an ext4 volume holds: every time to the nanosecond, a
// creation time, hard links and symlinks, and every byte of slack.
func Caps(blockSize int) target.Caps {
	return target.Caps{
		BirthTime: true, ChangeTime: true, Hardlinks: true, Symlinks: true,
		Slack: target.SlackExact, ClusterSize: blockSize,
		MinTime: MinTime, MaxTime: MaxTime, ValidName: ValidName, Reserved: []string{"lost+found"},
	}
}

// Granularity is how finely ext4 keeps times: to the nanosecond, all four.
func Granularity() target.Granularity {
	return target.Granularity{Atime: time.Nanosecond, Mtime: time.Nanosecond, Ctime: time.Nanosecond, Btime: time.Nanosecond}
}

// Format lays an empty ext4 volume out on dev as mke2fs does: the root
// directory, lost+found, and the bad blocks inode stamped with the clock.
func Format(dev *volume.Device, o Options, res *volume.Tracker) (*FS, error) {
	g, err := Plan(dev.Size(), o.BlockSize)
	if err != nil {
		return nil, err
	}
	if err := ValidLabel(o.Label); err != nil {
		return nil, err
	}
	alloc, err := volume.NewAllocator(int(g.FirstData), int(g.Blocks-g.FirstData), o.Alloc)
	if err != nil {
		return nil, err
	}
	f := &FS{
		dev: dev, g: g, o: o, alloc: alloc, res: res,
		inodes: map[uint32]*inode{}, used: make([]bool, g.Inodes()+1),
		free: make([]uint32, g.Groups), low: make([]uint32, g.Groups), dirs: make([]uint16, g.Groups),
		blockUninit: make([]bool, g.Groups), inodeUninit: make([]bool, g.Groups), itableUnused: make([]uint32, g.Groups),
		seed: identity{uuid: o.UUID}.seed(), limit: g.BlockSize - tailSize,
	}
	// mke2fs leaves every group's inodes, and every group's blocks but the
	// last's, to be worked out when first used.
	for i := range f.free {
		f.free[i] = g.InodesPerGroup
		f.inodeUninit[i] = true
		f.itableUnused[i] = g.InodesPerGroup
		f.blockUninit[i] = i != g.Groups-1
	}
	f.itableUnused[0] -= firstIno - 1
	// Every group's bookkeeping starts zeroed, whatever the file held, as
	// does the boot block before the superblock. A group holding any of it
	// has its blocks worked out already.
	if err := dev.Zero(0, superOffset); err != nil {
		return nil, err
	}
	place := func(b, n uint32, own bool) error {
		alloc.Mark(volume.Run{Start: int(b), Len: int(n)})
		if own {
			for k := b; k < b+n; k++ {
				f.blockUninit[g.group(k)] = false
			}
		}
		return dev.Zero(g.offset(b), int64(n)*int64(g.BlockSize))
	}
	for i := range g.Groups {
		if err := place(g.start(i), g.meta(i), false); err != nil {
			return nil, err
		}
		for _, t := range [][2]uint32{{g.blockBitmap(i), 1}, {g.inodeBitmap(i), 1}, {g.inodeTable(i), g.InodeBlocks}} {
			if err := place(t[0], t[1], true); err != nil {
				return nil, err
			}
		}
	}
	for ino := uint32(1); ino < firstIno; ino++ {
		f.claim(ino, nil)
	}
	// The bad blocks inode has only the three times ext2 had.
	bad := make([]byte, inodeSize)
	t := uint32(o.Clock.Unix())
	for _, at := range []int{8, 12, 16} {
		binary.LittleEndian.PutUint32(bad[at:], t)
	}
	setInodeCsum(bad, f.seed, 1)
	if _, err := dev.WriteAt(bad, g.inodeOffset(1)); err != nil {
		return nil, err
	}
	// The other reserved inodes are empty, but for their checksums.
	for ino := uint32(rootIno + 1); ino < firstIno; ino++ {
		empty := make([]byte, inodeSize)
		setInodeCsum(empty, f.seed, ino)
		if _, err := dev.WriteAt(empty, g.inodeOffset(ino)); err != nil {
			return nil, err
		}
	}
	f.now = o.Clock
	f.root = &node{ino: rootIno}
	if err := f.mkdir(f.root, f.root, 0o755, 0); err != nil {
		return nil, err
	}
	lpf := &node{ino: lostFound}
	if err := f.mkdir(lpf, f.root, 0o700, 0); err != nil {
		return nil, err
	}
	// mke2fs grows lost+found a block at a time until it has 16 KiB and two
	// blocks, but at most eleven times.
	for i, size := 1, g.BlockSize; i < 12 && (size < lostFoundSize || size < 2*g.BlockSize); i, size = i+1, size+g.BlockSize {
		if err := f.growDir(lpf); err != nil {
			return nil, err
		}
	}
	if err := f.addEntry(f.root, "lost+found", lpf.ino, ftDir); err != nil {
		return nil, err
	}
	f.root.in.links++
	if err := f.writeInode(f.root); err != nil {
		return nil, err
	}
	f.now = time.Time{}
	// Every copy of the superblock and the descriptors is as mke2fs leaves
	// it; Linux updates only the primary ones.
	c, err := f.writeBitmaps()
	if err != nil {
		return nil, err
	}
	for i := range g.Groups {
		if !hasSuper(i) {
			continue
		}
		if _, err := dev.WriteAt(g.superblock(i, f.identity(), c), g.superAt(i)); err != nil {
			return nil, err
		}
		if _, err := dev.WriteAt(g.descriptors(f.seed, c), g.offset(g.start(i)+1)); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *FS) identity() identity {
	return identity{uuid: f.o.UUID, hashSeed: f.o.HashSeed, label: f.o.Label, created: f.o.Clock}
}

// Caps is what the volume holds.
func (f *FS) Caps() target.Caps { return Caps(f.g.BlockSize) }

// Granularity is how finely the volume keeps times.
func (f *FS) Granularity() target.Granularity { return Granularity() }

// Geometry is the volume's layout.
func (f *FS) Geometry() Geometry { return f.g }

// Root is the root directory's record.
func (f *FS) Root() any { return f.root }

// SetNow says when the changes that follow happen; with no time given,
// they happen at the clock.
func (f *FS) SetNow(t time.Time) { f.now = t }

func (f *FS) clock() time.Time {
	if f.now.IsZero() {
		return f.o.Clock
	}
	return f.now
}

func rec(n *volume.Node) *node { return n.Sys.(*node) }

// mkdir makes d, a new directory in parent (itself for the root), with "."
// and ".." in its first block.
func (f *FS) mkdir(d, parent *node, perm fs.FileMode, gen uint32) error {
	now := f.clock()
	d.in = &inode{mode: modeDir | uint16(perm.Perm()), links: 2, flags: flagExtents, atime: now, ctime: now, mtime: now, crtime: now, gen: gen}
	f.claim(d.ino, d.in)
	if err := f.growDir(d); err != nil {
		return err
	}
	b := d.data
	le := binary.LittleEndian
	le.PutUint32(b[0:], d.ino)
	le.PutUint16(b[4:], 12)
	b[6], b[7] = 1, ftDir
	b[8] = '.'
	le.PutUint32(b[12:], parent.ino)
	le.PutUint16(b[16:], uint16(f.limit-12))
	b[18], b[19] = 2, ftDir
	copy(b[20:], "..")
	f.dirs[f.inodeGroup(d.ino)]++
	return f.writeBlock(d, 0)
}

// claim marks inode ino in use, holding in. Its group's inodes are worked
// out from then on, and its table is in use up to ino at least.
func (f *FS) claim(ino uint32, in *inode) {
	if in != nil {
		f.inodes[ino] = in
	}
	if f.used[ino] {
		return
	}
	g := f.inodeGroup(ino)
	f.used[ino] = true
	f.free[g]--
	f.inodeUninit[g] = false
	if r := (ino-1)%f.g.InodesPerGroup + 1; r > f.g.InodesPerGroup-f.itableUnused[g] {
		f.itableUnused[g] = f.g.InodesPerGroup - r
	}
}

// allocate takes count blocks, near the near-th if it can; the groups they
// are in have their blocks worked out from then on.
func (f *FS) allocate(count, near int) ([]volume.Run, error) {
	runs, err := f.alloc.Alloc(count, near)
	for _, r := range runs {
		for g := f.g.group(uint32(r.Start)); g <= f.g.group(uint32(r.Start+r.Len-1)); g++ {
			f.blockUninit[g] = false
		}
	}
	return runs, err
}

// release marks inode ino free.
func (f *FS) release(ino uint32) {
	g := f.inodeGroup(ino)
	f.used[ino] = false
	f.free[g]++
	f.low[g] = min(f.low[g], (ino-1)%f.g.InodesPerGroup)
}

// freeBlocks is how many of group i's blocks are free.
func (f *FS) freeBlocks(i int) int {
	return f.alloc.FreeIn(int(f.g.start(i)), int(f.g.groupBlocks(i)))
}

func (f *FS) inodeGroup(ino uint32) int { return int((ino - 1) / f.g.InodesPerGroup) }

// newInode picks an inode for a new object in parent as Linux does for a
// file on a volume with flex groups: the lowest free one in the first group
// of the parent's flex group that has one, else in the next group that has
// one. An inode deleted within the last minute is taken only when the
// group has no other.
func (f *FS) newInode(parent *node) (uint32, error) {
	pg := f.inodeGroup(parent.ino)
	start := -1
	for g := pg &^ (flexSize - 1); g < min(pg|(flexSize-1)+1, f.g.Groups); g++ {
		if f.free[g] > 0 {
			start = g
			break
		}
	}
	if start < 0 {
		start = pg
	}
	now := uint32(f.clock().Unix())
	for i := range f.g.Groups {
		grp := (start + i) % f.g.Groups
		if f.free[grp] == 0 {
			continue
		}
		first := uint32(grp)*f.g.InodesPerGroup + 1
		recent := uint32(0)
		seen := false
		for ino := first + f.low[grp]; ino < first+f.g.InodesPerGroup; ino++ {
			if f.used[ino] {
				continue
			}
			if !seen {
				f.low[grp], seen = ino-first, true
			}
			if in := f.inodes[ino]; in != nil && in.dtime != 0 && int32(in.dtime-now) < 0 && int32(now-(in.dtime+recentlyDeleted)) < 0 {
				recent = ino
				continue
			}
			return ino, nil
		}
		if recent != 0 {
			return recent, nil
		}
	}
	return 0, errors.New("the volume has no free inode")
}

// Create gives the new node n the name in parent: a new inode stamped with
// the clock, and an entry in parent's first block with room for it.
func (f *FS) Create(parent *volume.Node, name string, n *volume.Node) error {
	p := rec(parent)
	ino, err := f.newInode(p)
	if err != nil {
		return err
	}
	r := &node{ino: ino}
	gen := uint32(f.o.Generations.Uint64())
	now := f.clock()
	ft := byte(ftFile)
	switch n.Kind {
	case volume.Dir:
		if err := f.mkdir(r, p, n.Mode, gen); err != nil {
			return err
		}
		ft = ftDir
	case volume.Symlink:
		ft = ftSymlink
		if err := f.symlink(r, n.Target, gen); err != nil {
			return err
		}
	case volume.File:
		r.in = &inode{mode: modeFile | uint16(n.Mode.Perm()), links: 1, flags: flagExtents, atime: now, ctime: now, mtime: now, crtime: now, gen: gen}
		header(r.in.block[:], 0, rootEntries, 0)
		f.claim(ino, r.in)
	default:
		return errors.ErrUnsupported
	}
	if err := f.writeInode(r); err != nil {
		return err
	}
	if err := f.addEntry(p, name, ino, ft); err != nil {
		return err
	}
	if n.Kind == volume.Dir {
		p.in.links = linksUp(p.in.links)
	}
	n.Sys = r
	return f.touchDir(p)
}

// linksUp is a directory's link count once it has one more subdirectory:
// past linkMax it counts 1, as dir_nlink allows.
func linksUp(n uint16) uint16 {
	if n == 1 || n+1 >= linkMax {
		return 1
	}
	return n + 1
}

func linksDown(n uint16) uint16 {
	if n > 2 {
		return n - 1
	}
	return n
}

// symlink makes r a symlink to to: in the inode itself when it fits with
// its terminating NUL, else in a block of its own.
func (f *FS) symlink(r *node, to string, gen uint32) error {
	now := f.clock()
	r.in = &inode{mode: modeSymlink | 0o777, links: 1, size: int64(len(to)), atime: now, ctime: now, mtime: now, crtime: now, gen: gen}
	f.claim(r.ino, r.in)
	if len(to) < len(r.in.block) {
		copy(r.in.block[:], to)
		return nil
	}
	if len(to) >= f.g.BlockSize {
		return fmt.Errorf("a symlink target is shorter than a block (%d bytes), and this one has %d", f.g.BlockSize, len(to))
	}
	r.in.flags = flagExtents
	if err := f.grow(r, 1); err != nil {
		return err
	}
	b := make([]byte, f.g.BlockSize)
	copy(b, to)
	if _, err := f.dev.WriteAt(b, f.g.offset(r.blocks[0])); err != nil {
		return err
	}
	return f.mapBlocks(r)
}

// touchDir stamps a directory changed now and writes its inode.
func (f *FS) touchDir(d *node) error {
	now := f.clock()
	d.in.mtime, d.in.ctime = now, now
	return f.writeInode(d)
}

// writeInode puts r's inode on disk.
func (f *FS) writeInode(r *node) error {
	_, err := f.dev.WriteAt(r.in.encode(f.seed, r.ino), f.g.inodeOffset(r.ino))
	return err
}

// writeBlock puts block i of directory d on disk, with its checksum.
func (f *FS) writeBlock(d *node, i int) error {
	bs := f.g.BlockSize
	b := d.data[i*bs : (i+1)*bs]
	setDirTail(b, inodeSeed(f.seed, d.ino, d.in.gen))
	_, err := f.dev.WriteAt(b, f.g.offset(d.blocks[i]))
	return err
}

// growDir gives directory d one more block, holding one empty entry the
// size of the block.
func (f *FS) growDir(d *node) error {
	if err := f.grow(d, 1); err != nil {
		return err
	}
	bs := f.g.BlockSize
	b := make([]byte, bs)
	binary.LittleEndian.PutUint16(b[4:], uint16(f.limit))
	d.data = append(d.data, b...)
	d.in.size = int64(len(d.data))
	if err := f.writeBlock(d, len(d.blocks)-1); err != nil {
		return err
	}
	return f.mapBlocks(d)
}

// addEntry names inode ino name in directory d, as ext4_add_entry does:
// in the first entry, block by block, with room after its own name for
// the new one, which splits it; or in a new block when none has room.
func (f *FS) addEntry(d *node, name string, ino uint32, ft byte) error {
	bs := f.g.BlockSize
	need := recLen(len(name))
	le := binary.LittleEndian
	for i := 0; ; i++ {
		if i == len(d.blocks) {
			if err := f.growDir(d); err != nil {
				return err
			}
		}
		blk := d.data[i*bs : (i+1)*bs]
		for off := 0; off <= f.limit-need; {
			used := le.Uint32(blk[off:]) != 0
			rl := int(le.Uint16(blk[off+4:]))
			if rl < 8 || off+rl > f.limit {
				return fmt.Errorf("directory inode %d: a broken entry at byte %d of block %d", d.ino, off, i)
			}
			nlen := recLen(int(blk[off+6]))
			room := rl
			if used {
				room = rl - nlen
			}
			if room < need {
				off += rl
				continue
			}
			if used {
				le.PutUint16(blk[off+4:], uint16(nlen))
				off += nlen
				le.PutUint16(blk[off+4:], uint16(rl-nlen))
			}
			le.PutUint32(blk[off:], ino)
			blk[off+6], blk[off+7] = byte(len(name)), ft
			copy(blk[off+8:], name)
			return f.writeBlock(d, i)
		}
	}
}

// removeEntry takes name out of directory d as ext4_delete_entry has done
// since Linux 5.14: an entry with one before it in its block is folded into
// that one and zeroed; the first entry of a block keeps only its length.
func (f *FS) removeEntry(d *node, name string) error {
	bs := f.g.BlockSize
	le := binary.LittleEndian
	for i := range d.blocks {
		blk := d.data[i*bs : (i+1)*bs]
		prev := -1
		for off := 0; off < f.limit; {
			rl := int(le.Uint16(blk[off+4:]))
			if rl < 8 || off+rl > f.limit {
				return fmt.Errorf("directory inode %d: a broken entry at byte %d of block %d", d.ino, off, i)
			}
			if le.Uint32(blk[off:]) != 0 && string(blk[off+8:off+8+int(blk[off+6])]) == name {
				if prev >= 0 {
					le.PutUint16(blk[prev+4:], uint16(int(le.Uint16(blk[prev+4:]))+rl))
					clear(blk[off : off+rl])
				} else {
					clear(blk[off : off+4])
					clear(blk[off+6 : off+rl])
				}
				return f.writeBlock(d, i)
			}
			prev, off = off, off+rl
		}
	}
	return fmt.Errorf("directory inode %d has no entry %q", d.ino, name)
}

// grow adds count blocks to r's content, after its last one if they are
// free.
func (f *FS) grow(r *node, count int) error {
	near := -1
	if len(r.blocks) > 0 {
		near = int(r.blocks[len(r.blocks)-1]) + 1
	}
	runs, err := f.allocate(count, near)
	if err != nil {
		return err
	}
	for _, u := range volume.Units(runs) {
		r.blocks = append(r.blocks, uint32(u))
	}
	return nil
}

// mapBlocks writes r's extent tree: in the inode when four extents map its
// blocks, else in leaf blocks the inode indexes. It sets i_blocks and
// writes the inode.
func (f *FS) mapBlocks(r *node) error {
	es := extents(r.blocks)
	per := (f.g.BlockSize - 12) / 12
	clear(r.in.block[:])
	if len(es) <= rootEntries {
		f.alloc.Release(units(r.leaves))
		r.leaves = nil
		header(r.in.block[:], len(es), rootEntries, 0)
		for i, e := range es {
			putExtent(r.in.block[12+12*i:], e)
		}
	} else {
		need := (len(es) + per - 1) / per
		if need > rootEntries {
			return fmt.Errorf("%d extents are more than this volume maps (%d): the file is too fragmented", len(es), rootEntries*per)
		}
		if len(r.leaves) > need {
			f.alloc.Release(units(r.leaves[need:]))
			r.leaves = r.leaves[:need]
		}
		for len(r.leaves) < need {
			runs, err := f.allocate(1, -1)
			if err != nil {
				return err
			}
			r.leaves = append(r.leaves, uint32(runs[0].Start))
		}
		header(r.in.block[:], need, rootEntries, 1)
		for i, leaf := range r.leaves {
			part := es[i*per : min((i+1)*per, len(es))]
			b := make([]byte, f.g.BlockSize)
			header(b, len(part), per, 0)
			for k, e := range part {
				putExtent(b[12+12*k:], e)
			}
			setExtentTail(b, inodeSeed(f.seed, r.ino, r.in.gen))
			if _, err := f.dev.WriteAt(b, f.g.offset(leaf)); err != nil {
				return err
			}
			putIndex(r.in.block[12+12*i:], part[0].logical, leaf)
		}
	}
	r.in.sectors = uint32((len(r.blocks) + len(r.leaves)) * f.g.BlockSize / 512)
	return f.writeInode(r)
}

func units(blocks []uint32) []int {
	out := make([]int, len(blocks))
	for i, b := range blocks {
		out[i] = int(b)
	}
	return out
}

// read reads r's first size bytes of content from disk, and where they lie
// in the image file.
func (f *FS) read(r *node, size int64) ([]byte, []target.Extent, error) {
	out := make([]byte, 0, size)
	var exts []target.Extent
	bs := int64(f.g.BlockSize)
	for i := 0; int64(len(out)) < size; i++ {
		k := min(bs, size-int64(len(out)))
		off := f.g.offset(r.blocks[i])
		buf := make([]byte, k)
		if _, err := f.dev.ReadAt(buf, off); err != nil {
			return nil, nil, err
		}
		out = append(out, buf...)
		abs := f.dev.Abs(off)
		if m := len(exts); m > 0 && exts[m-1].Offset+exts[m-1].Length == abs {
			exts[m-1].Length += k
		} else {
			exts = append(exts, target.Extent{Offset: abs, Length: k})
		}
	}
	return out, exts, nil
}

// cut frees r's blocks from the keep-th on, recording what they held, up
// to size bytes, as residue of cause.
func (f *FS) cut(r *node, keep int, size int64, cause string) error {
	if keep >= len(r.blocks) {
		return nil
	}
	if start := int64(keep) * int64(f.g.BlockSize); start < size {
		data, exts, err := f.read(&node{blocks: r.blocks[keep:]}, size-start)
		if err != nil {
			return err
		}
		f.res.Add(cause, nil, nil, exts, data)
	}
	f.alloc.Release(units(r.blocks[keep:]))
	r.blocks = r.blocks[:keep]
	return nil
}

// Commit writes n's content: in place over its blocks, extending or
// cutting them to fit; or, when it was truncated first, into newly
// allocated blocks after freeing the old ones, whose bytes stay behind.
// The last block is zeroed past the end of the content, as the page cache
// writes it.
func (f *FS) Commit(vn *volume.Node, truncated bool) error {
	r := rec(vn)
	bs := int64(f.g.BlockSize)
	size := int64(len(vn.Data))
	if truncated {
		if err := f.cut(r, 0, r.in.size, target.ResidueOverwrite); err != nil {
			return err
		}
	}
	need := int((size + bs - 1) / bs)
	switch {
	case need < len(r.blocks):
		if err := f.cut(r, need, r.in.size, target.ResidueOverwrite); err != nil {
			return err
		}
	case need > len(r.blocks):
		if err := f.grow(r, need-len(r.blocks)); err != nil {
			return err
		}
	}
	for i, b := range r.blocks {
		chunk := vn.Data[int64(i)*bs : min(int64(i+1)*bs, size)]
		if pad := int64(len(chunk)) % bs; pad != 0 {
			chunk = append(slices.Clip(chunk), make([]byte, bs-pad)...)
		}
		if _, err := f.dev.WriteAt(chunk, f.g.offset(b)); err != nil {
			return err
		}
	}
	r.in.size = size
	now := f.clock()
	r.in.mtime, r.in.ctime = now, now
	return f.mapBlocks(r)
}

// Remove takes name out of parent. An object with no name left is deleted
// as Linux evicts it: the inode keeps its mode and times and gains its
// deletion time, its size and links go to 0, and its extents are zeroed;
// its blocks are freed with their bytes in place.
func (f *FS) Remove(parent *volume.Node, name string, vn *volume.Node) error {
	p, r := rec(parent), rec(vn)
	if err := f.removeEntry(p, name); err != nil {
		return err
	}
	now := f.clock()
	if r.in.mode&modeType == modeDir {
		p.in.links = linksDown(p.in.links)
		r.in.links = 0
	} else {
		r.in.links--
	}
	r.in.ctime = now
	if err := f.touchDir(p); err != nil {
		return err
	}
	if vn.Names > 0 {
		return f.writeInode(r)
	}
	return f.evict(r, now)
}

// evict deletes r, whose last name is gone.
func (f *FS) evict(r *node, now time.Time) error {
	data, exts, err := f.read(r, min(r.in.size, int64(len(r.blocks))*int64(f.g.BlockSize)))
	if err != nil {
		return err
	}
	if r.in.flags&flagExtents == 0 {
		// A fast symlink's target goes with the inode's in-memory copy.
		clear(r.in.block[:])
	} else if err := f.zeroExtents(r); err != nil {
		return err
	}
	f.alloc.Release(units(r.blocks))
	f.alloc.Release(units(r.leaves))
	r.blocks, r.leaves = nil, nil
	r.in.size, r.in.sectors, r.in.links = 0, 0, 0
	r.in.dtime = uint32(now.Unix())
	if r.in.mode&modeType == modeDir {
		f.dirs[f.inodeGroup(r.ino)]--
	}
	f.release(r.ino)
	if err := f.writeInode(r); err != nil {
		return err
	}
	raw := r.in.encode(f.seed, r.ino)
	entry := &target.ResidueEntry{
		Type: "ext4_inode", Number: int64(r.ino), Offset: f.dev.Abs(f.g.inodeOffset(r.ino)), Length: inodeSize,
		Deleted: now.UTC().Format(time.RFC3339Nano),
	}
	if len(exts) == 0 {
		data = nil
	}
	f.res.Add(target.ResidueDelete, entry, raw, exts, data)
	return nil
}

// zeroExtents empties r's extent tree as ext4_ext_remove_space leaves it:
// every extent's start and length zeroed and its logical block kept, every
// node's count 0, and the inode's root a leaf again with its index bytes
// left in place.
func (f *FS) zeroExtents(r *node) error {
	le := binary.LittleEndian
	wipe := func(b []byte, n int) {
		for i := range n {
			e := b[12+12*i:]
			le.PutUint16(e[4:], 0)
			le.PutUint16(e[6:], 0)
			le.PutUint32(e[8:], 0)
		}
		le.PutUint16(b[2:], 0)
	}
	root := r.in.block[:]
	n := int(le.Uint16(root[2:]))
	if len(r.leaves) == 0 {
		wipe(root, n)
	} else {
		for _, leaf := range r.leaves {
			b := make([]byte, f.g.BlockSize)
			if _, err := f.dev.ReadAt(b, f.g.offset(leaf)); err != nil {
				return err
			}
			wipe(b, int(le.Uint16(b[2:])))
			setExtentTail(b, inodeSeed(f.seed, r.ino, r.in.gen))
			if _, err := f.dev.WriteAt(b, f.g.offset(leaf)); err != nil {
				return err
			}
		}
		le.PutUint16(root[2:], 0)
	}
	header(root, 0, rootEntries, 0)
	return nil
}

// Rename gives n its new entry, then removes the old one, as ext4_rename
// does; a directory that changes parent has its ".." repointed.
func (f *FS) Rename(from *volume.Node, oldName string, to *volume.Node, newName string, vn *volume.Node) error {
	src, dst, r := rec(from), rec(to), rec(vn)
	ft := byte(ftFile)
	switch r.in.mode & modeType {
	case modeDir:
		ft = ftDir
	case modeSymlink:
		ft = ftSymlink
	}
	if err := f.addEntry(dst, newName, r.ino, ft); err != nil {
		return err
	}
	r.in.ctime = f.clock()
	if err := f.writeInode(r); err != nil {
		return err
	}
	if err := f.removeEntry(src, oldName); err != nil {
		return err
	}
	if ft == ftDir && src != dst {
		binary.LittleEndian.PutUint32(r.data[12:], dst.ino)
		if err := f.writeBlock(r, 0); err != nil {
			return err
		}
		src.in.links = linksDown(src.in.links)
		dst.in.links = linksUp(dst.in.links)
	}
	if err := f.touchDir(src); err != nil {
		return err
	}
	if src != dst {
		return f.touchDir(dst)
	}
	return nil
}

// Link gives the file n a further name in parent.
func (f *FS) Link(parent *volume.Node, name string, vn *volume.Node) error {
	p, r := rec(parent), rec(vn)
	if r.in.links >= linkMax {
		return fmt.Errorf("the file has the most links ext4 allows (%d)", linkMax)
	}
	if err := f.addEntry(p, name, r.ino, ftFile); err != nil {
		return err
	}
	r.in.links++
	r.in.ctime = f.clock()
	if err := f.writeInode(r); err != nil {
		return err
	}
	return f.touchDir(p)
}

// SetTimes stores t's non-zero times in n's inode.
func (f *FS) SetTimes(vn *volume.Node, t target.Times) error {
	r := rec(vn)
	for _, s := range []struct {
		to   *time.Time
		from time.Time
	}{{&r.in.atime, t.Atime}, {&r.in.mtime, t.Mtime}, {&r.in.ctime, t.Ctime}, {&r.in.crtime, t.Btime}} {
		if !s.from.IsZero() {
			*s.to = s.from.UTC()
		}
	}
	return f.writeInode(r)
}

// Chmod stores n's permission bits.
func (f *FS) Chmod(vn *volume.Node) error {
	r := rec(vn)
	r.in.mode = r.in.mode&modeType | uint16(vn.Mode.Perm())
	r.in.ctime = f.clock()
	return f.writeInode(r)
}

// WriteSlack writes data past byte at of n's content, in its last block.
func (f *FS) WriteSlack(vn *volume.Node, at int64, data []byte) error {
	r := rec(vn)
	bs := int64(f.g.BlockSize)
	i := int(at / bs)
	if at%bs == 0 || i >= len(r.blocks) || at%bs+int64(len(data)) > bs {
		return fmt.Errorf("%d bytes from byte %d do not fit the slack of a %d-byte block", len(data), at, bs)
	}
	_, err := f.dev.WriteAt(data, f.g.offset(r.blocks[i])+at%bs)
	return err
}

// writeBitmaps writes every group's bitmaps but those left to be worked
// out, and returns the counts and flags the descriptors carry, the
// bitmaps' checksums included.
func (f *FS) writeBitmaps() (counts, error) {
	g := f.g
	bs := g.BlockSize
	c := counts{
		groupBlocks: make([]uint16, g.Groups), groupInodes: make([]uint16, g.Groups), dirs: slices.Clone(f.dirs),
		flags: make([]uint16, g.Groups), itableUnused: make([]uint16, g.Groups),
		blockCsums: make([]uint16, g.Groups), inodeCsums: make([]uint16, g.Groups),
	}
	for i := range g.Groups {
		c.groupBlocks[i] = uint16(f.freeBlocks(i))
		c.groupInodes[i] = uint16(f.free[i])
		c.freeBlocks += uint32(c.groupBlocks[i])
		c.freeInodes += uint32(c.groupInodes[i])
		c.itableUnused[i] = uint16(f.itableUnused[i])
		c.flags[i] = bgItableZeroed
		if f.blockUninit[i] {
			c.flags[i] |= bgBlockUninit
		} else {
			bm := make([]byte, bs)
			start, n := g.start(i), g.groupBlocks(i)
			for k := range uint32(bs * 8) {
				if k >= n || f.alloc.Used(int(start+k)) {
					bm[k/8] |= 1 << (k % 8)
				}
			}
			c.blockCsums[i] = uint16(crc32c(f.seed, bm[:g.BlocksPerGroup/8]))
			if _, err := f.dev.WriteAt(bm, g.offset(g.blockBitmap(i))); err != nil {
				return c, err
			}
		}
		if f.inodeUninit[i] {
			c.flags[i] |= bgInodeUninit
		} else {
			im := make([]byte, bs)
			first := uint32(i)*g.InodesPerGroup + 1
			for k := range uint32(bs * 8) {
				if k >= g.InodesPerGroup || f.used[first+k] {
					im[k/8] |= 1 << (k % 8)
				}
			}
			c.inodeCsums[i] = uint16(crc32c(f.seed, im[:g.InodesPerGroup/8]))
			if _, err := f.dev.WriteAt(im, g.offset(g.inodeBitmap(i))); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// Flush writes the bitmaps, the primary group descriptors and the primary
// superblock.
func (f *FS) Flush() error {
	c, err := f.writeBitmaps()
	if err != nil {
		return err
	}
	if _, err := f.dev.WriteAt(f.g.descriptors(f.seed, c), f.g.offset(f.g.start(0)+1)); err != nil {
		return err
	}
	_, err = f.dev.WriteAt(f.g.superblock(0, f.identity(), c), superOffset)
	return err
}

// Open reads the finished volume back.
func (f *FS) Open() (target.Reader, error) { return Open(f.dev) }

var (
	_ volume.Driver     = (*FS)(nil)
	_ volume.LinkDriver = (*FS)(nil)
	_ volume.Clocked    = (*FS)(nil)
)
