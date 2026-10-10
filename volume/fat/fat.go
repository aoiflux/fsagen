package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// maxEntries is how many entries a directory may hold.
const maxEntries = 65536

// Options are what a FAT32 volume is formatted with.
type Options struct {
	ClusterSize int
	Label       string
	// Serial is the volume serial number.
	Serial uint32
	// Hidden is how many sectors precede the volume on its disk.
	Hidden uint32
	// Clock stamps what is created before the scenario sets its times: the
	// label, and each new entry until it is stamped.
	Clock time.Time
	// Alloc is the allocation policy.
	Alloc string
}

// FS is a FAT32 volume being written.
type FS struct {
	dev   *volume.Device
	g     Geometry
	o     Options
	alloc *volume.Allocator
	fat   []uint32
	res   *volume.Tracker
	root  *node
}

// node is where an object is on disk.
type node struct {
	// parent holds its entries: slot is its short entry, after lfn long
	// ones. The root has none.
	parent    *dir
	slot, lfn int
	// chain is its content's clusters; a directory's entries are its
	// content.
	chain []uint32
	size  uint32
	// self is a directory's entries.
	self *dir
}

// dir is a directory's entries, as in its clusters.
type dir struct {
	owner *node
	data  []byte
}

// Caps is what a FAT32 volume holds: one stream per file, creation times
// but no change time, no links, and every byte of slack.
func Caps(clusterSize int) target.Caps {
	return target.Caps{
		BirthTime: true, Slack: target.SlackExact, ClusterSize: clusterSize,
		MinTime: MinTime, MaxTime: MaxTime, FoldsCase: true, ValidName: ValidName,
	}
}

// Format lays an empty FAT32 volume out on dev.
func Format(dev *volume.Device, o Options, res *volume.Tracker) (*FS, error) {
	g, err := Plan(dev.Size(), o.ClusterSize)
	if err != nil {
		return nil, err
	}
	if err := ValidLabel(o.Label); err != nil {
		return nil, err
	}
	alloc, err := volume.NewAllocator(2, g.Clusters, o.Alloc)
	if err != nil {
		return nil, err
	}
	f := &FS{dev: dev, g: g, o: o, alloc: alloc, fat: make([]uint32, g.Clusters+2), res: res}
	f.fat[0], f.fat[1] = 0x0FFFFFF8, eoc
	// The reserved area and the FATs start zeroed, whatever the file held.
	if err := dev.Zero(0, g.dataSector()*sectorSize); err != nil {
		return nil, err
	}
	f.root = &node{}
	f.root.self = &dir{owner: f.root}
	alloc.Mark(volume.Run{Start: rootCluster, Len: 1})
	f.root.chain = []uint32{rootCluster}
	f.fat[rootCluster] = eoc
	f.root.self.data = make([]byte, g.ClusterSize)
	if o.Label != "" {
		e := f.root.self.data[:entrySize]
		copy(e, padLabel(o.Label))
		e[11] = attrVolumeID
		stamp(e, time.Time{}, o.Clock, time.Time{})
	}
	if err := f.writeSlots(f.root.self, 0, f.g.ClusterSize/entrySize); err != nil {
		return nil, err
	}
	return f, f.writeBoot()
}

// Caps is what the volume holds.
func (f *FS) Caps() target.Caps { return Caps(f.g.ClusterSize) }

// Granularity is how finely FAT keeps times: the access date to the day,
// the write time to two seconds, the creation time to 10 ms. It keeps no
// change time.
func (f *FS) Granularity() target.Granularity {
	return target.Granularity{Atime: 24 * time.Hour, Mtime: 2 * time.Second, Btime: 10 * time.Millisecond}
}

// Geometry is the volume's layout.
func (f *FS) Geometry() Geometry { return f.g }

// Root is the root directory's record.
func (f *FS) Root() any { return f.root }

func rec(n *volume.Node) *node { return n.Sys.(*node) }

// short is n's short entry.
func (f *FS) short(n *node) []byte {
	return n.parent.data[n.slot*entrySize : (n.slot+1)*entrySize]
}

// slotOffset is where slot i of d lies on the device.
func (f *FS) slotOffset(d *dir, i int) int64 {
	at := i * entrySize
	return f.g.clusterOffset(d.owner.chain[at/f.g.ClusterSize]) + int64(at%f.g.ClusterSize)
}

// writeSlots puts n entries of d from slot i on disk.
func (f *FS) writeSlots(d *dir, i, n int) error {
	for k := i; k < i+n; k++ {
		if _, err := f.dev.WriteAt(d.data[k*entrySize:(k+1)*entrySize], f.slotOffset(d, k)); err != nil {
			return err
		}
	}
	return nil
}

// taken reports whether a live entry of d other than skip has short name s.
func taken(d *dir, s shortName, skip *node) bool {
	for i := range len(d.data) / entrySize {
		e := d.data[i*entrySize : (i+1)*entrySize]
		switch {
		case e[0] == 0:
			return false
		case e[0] == deleted || e[11] == attrLFN || e[11]&attrVolumeID != 0:
			continue
		case skip != nil && skip.parent == d && skip.slot == i:
			continue
		case shortName(e[:11]) == s:
			return true
		}
	}
	return false
}

// entries are the entries that give name to an object in d: its long-name
// entries when it needs them, then its short entry, which holds only the
// name and the case bits.
func entries(d *dir, name string, self *node) ([][entrySize]byte, error) {
	s, bits, mixed, ok := fits(name)
	var short [entrySize]byte
	if ok && taken(d, s, self) {
		return nil, fmt.Errorf("%q is the short name of another file in its directory", name)
	}
	if ok && !mixed {
		copy(short[:], s[:])
		short[12] = bits
		return [][entrySize]byte{short}, nil
	}
	if !ok {
		var err error
		if s, err = generate(name, func(s shortName) bool { return taken(d, s, self) }); err != nil {
			return nil, err
		}
	}
	copy(short[:], s[:])
	return append(lfnEntries(name, s), short), nil
}

// place finds the first run of n free entries in d, as Windows reuses
// deleted ones first, growing the directory by a zeroed cluster at a time
// when no run is long enough.
func (f *FS) place(d *dir, n int) (int, error) {
	for {
		run, total := 0, len(d.data)/entrySize
		for i := 0; i < total; i++ {
			if b := d.data[i*entrySize]; b == 0 || b == deleted {
				run++
				if run == n {
					return i - n + 1, nil
				}
			} else {
				run = 0
			}
		}
		if total+f.g.ClusterSize/entrySize > maxEntries {
			return 0, fmt.Errorf("the directory holds the most entries FAT allows (%d)", maxEntries)
		}
		if err := f.grow(d.owner, 1); err != nil {
			return 0, err
		}
		d.data = append(d.data, make([]byte, f.g.ClusterSize)...)
		last := d.owner.chain[len(d.owner.chain)-1]
		if err := f.dev.Zero(f.g.clusterOffset(last), int64(f.g.ClusterSize)); err != nil {
			return 0, err
		}
	}
}

// grow adds count clusters to n's chain, after its last one if they are
// free.
func (f *FS) grow(n *node, count int) error {
	near := -1
	if len(n.chain) > 0 {
		near = int(n.chain[len(n.chain)-1]) + 1
	}
	runs, err := f.alloc.Alloc(count, near)
	if err != nil {
		return err
	}
	for _, u := range volume.Units(runs) {
		if len(n.chain) > 0 {
			f.fat[n.chain[len(n.chain)-1]] = uint32(u)
		}
		n.chain = append(n.chain, uint32(u))
		f.fat[u] = eoc
	}
	return nil
}

// cut frees n's clusters from the keep-th on.
func (f *FS) cut(n *node, keep int) {
	if keep >= len(n.chain) {
		return
	}
	freed := make([]int, 0, len(n.chain)-keep)
	for _, c := range n.chain[keep:] {
		f.fat[c] = 0
		freed = append(freed, int(c))
	}
	f.alloc.Release(freed)
	n.chain = n.chain[:keep]
	if keep > 0 {
		f.fat[n.chain[keep-1]] = eoc
	}
}

// Create gives the new node name in parent: its entries in the first free
// run of parent, stamped with the clock, and for a directory a zeroed
// cluster holding "." and "..".
func (f *FS) Create(parent *volume.Node, name string, n *volume.Node) error {
	d := rec(parent).self
	es, err := entries(d, name, nil)
	if err != nil {
		return err
	}
	r := &node{lfn: len(es) - 1}
	short := es[len(es)-1][:]
	attr := byte(attrArchive)
	if n.Kind == volume.Dir {
		attr = attrDirectory
		r.self = &dir{owner: r, data: make([]byte, f.g.ClusterSize)}
		if err := f.grow(r, 1); err != nil {
			return err
		}
	}
	if n.Mode&0o200 == 0 {
		attr |= attrReadOnly
	}
	short[11] = attr
	stamp(short, f.o.Clock, f.o.Clock, f.o.Clock)
	if r.self != nil {
		setFirst(short, r.chain[0])
		parentFirst := uint32(0)
		if p := rec(parent); p != f.root {
			parentFirst = p.chain[0]
		}
		for i, dots := range []string{".", ".."} {
			e := r.self.data[i*entrySize : (i+1)*entrySize]
			copy(e, short)
			copy(e[:11], []byte(dots + "          ")[:11])
			e[12] = 0
			if i == 1 {
				setFirst(e, parentFirst)
			}
		}
		if err := f.dev.Zero(f.g.clusterOffset(r.chain[0]), int64(f.g.ClusterSize)); err != nil {
			return err
		}
		if err := f.writeSlots(r.self, 0, 2); err != nil {
			return err
		}
	}
	n.Sys = r
	return f.enter(d, r, es)
}

// enter writes es into d's first free run and makes them r's.
func (f *FS) enter(d *dir, r *node, es [][entrySize]byte) error {
	at, err := f.place(d, len(es))
	if err != nil {
		return err
	}
	for i, e := range es {
		copy(d.data[(at+i)*entrySize:], e[:])
	}
	r.parent, r.slot, r.lfn = d, at+len(es)-1, len(es)-1
	return f.writeSlots(d, at, len(es))
}

// read reads n's first size bytes of content from disk, and where they lie
// in the image file.
func (f *FS) read(n *node, size int64) ([]byte, []target.Extent, error) {
	out := make([]byte, 0, size)
	var extents []target.Extent
	cs := int64(f.g.ClusterSize)
	for i := 0; int64(len(out)) < size; i++ {
		k := min(cs, size-int64(len(out)))
		off := f.g.clusterOffset(n.chain[i])
		buf := make([]byte, k)
		if _, err := f.dev.ReadAt(buf, off); err != nil {
			return nil, nil, err
		}
		out = append(out, buf...)
		abs := f.dev.Abs(off)
		if m := len(extents); m > 0 && extents[m-1].Offset+extents[m-1].Length == abs {
			extents[m-1].Length += k
		} else {
			extents = append(extents, target.Extent{Offset: abs, Length: k})
		}
	}
	return out, extents, nil
}

// free records the content of n's clusters from the keep-th on as residue
// of cause, then frees them.
func (f *FS) free(n *node, keep int, size int64, cause string) error {
	start := int64(keep) * int64(f.g.ClusterSize)
	if start < size {
		tail := &node{chain: n.chain[keep:]}
		data, extents, err := f.read(tail, size-start)
		if err != nil {
			return err
		}
		f.res.Add(cause, nil, nil, extents, data)
	}
	f.cut(n, keep)
	return nil
}

// Commit writes n's content: in place over its clusters, extending or
// cutting the chain to fit; or, when it was truncated first, into newly
// allocated clusters after freeing the old ones, whose bytes stay behind.
// The last sector is zeroed past the end of the content, and the rest of
// the cluster keeps whatever it held.
func (f *FS) Commit(vn *volume.Node, truncated bool) error {
	n := rec(vn)
	cs := int64(f.g.ClusterSize)
	size := int64(len(vn.Data))
	if size > 0xFFFFFFFF {
		return errors.New("a FAT file holds less than 4 GiB")
	}
	if truncated {
		if err := f.free(n, 0, int64(n.size), target.ResidueOverwrite); err != nil {
			return err
		}
	}
	need := int((size + cs - 1) / cs)
	switch {
	case need < len(n.chain):
		if err := f.free(n, need, int64(n.size), target.ResidueOverwrite); err != nil {
			return err
		}
	case need > len(n.chain):
		if err := f.grow(n, need-len(n.chain)); err != nil {
			return err
		}
	}
	for i, c := range n.chain {
		chunk := vn.Data[int64(i)*cs : min(int64(i+1)*cs, size)]
		if pad := len(chunk) % sectorSize; pad != 0 {
			chunk = append(slices.Clip(chunk), make([]byte, sectorSize-pad)...)
		}
		if _, err := f.dev.WriteAt(chunk, f.g.clusterOffset(c)); err != nil {
			return err
		}
	}
	n.size = uint32(size)
	e := f.short(n)
	first := uint32(0)
	if len(n.chain) > 0 {
		first = n.chain[0]
	}
	setFirst(e, first)
	binary.LittleEndian.PutUint32(e[28:], n.size)
	e[11] |= attrArchive
	return f.writeSlots(n.parent, n.slot, 1)
}

// unname marks n's entries deleted, as Windows does: 0xE5 over the first
// byte of each, the rest left as it was.
func (f *FS) unname(n *node) error {
	first := n.slot - n.lfn
	for i := first; i <= n.slot; i++ {
		n.parent.data[i*entrySize] = deleted
	}
	return f.writeSlots(n.parent, first, n.lfn+1)
}

// residueEntry describes n's short entry, as a delete or rename left it.
func (f *FS) residueEntry(n *node) (*target.ResidueEntry, []byte) {
	off := f.slotOffset(n.parent, n.slot)
	return &target.ResidueEntry{Type: "fat_dirent", Number: f.g.address(off), Offset: f.dev.Abs(off), Length: entrySize}, f.short(n)
}

// Remove deletes n's entries and frees its clusters; both keep their bytes.
func (f *FS) Remove(_ *volume.Node, _ string, vn *volume.Node) error {
	n := rec(vn)
	if err := f.unname(n); err != nil {
		return err
	}
	entry, raw := f.residueEntry(n)
	size := int64(n.size)
	if n.self != nil {
		size = int64(len(n.self.data))
	}
	data, extents, err := f.read(n, size)
	if err != nil {
		return err
	}
	f.res.Add(target.ResidueDelete, entry, raw, extents, data)
	f.cut(n, 0)
	return nil
}

// Rename gives n new entries in to, then deletes its old ones, which stay
// behind; the short entry's attributes, times, cluster and size go with it.
// A directory that changes parent has its ".." entry repointed.
func (f *FS) Rename(from *volume.Node, _ string, to *volume.Node, newName string, vn *volume.Node) error {
	n := rec(vn)
	d := rec(to).self
	es, err := entries(d, newName, n)
	if err != nil {
		return err
	}
	old := f.short(n)
	short := es[len(es)-1][:]
	copy(short[11:12], old[11:12])
	copy(short[13:], old[13:])
	oldNode := *n
	if err := f.enter(d, n, es); err != nil {
		return err
	}
	if err := f.unname(&oldNode); err != nil {
		return err
	}
	entry, raw := f.residueEntry(&oldNode)
	f.res.Add(target.ResidueRename, entry, raw, nil, nil)
	if n.self != nil && from != to {
		parentFirst := uint32(0)
		if p := rec(to); p != f.root {
			parentFirst = p.chain[0]
		}
		setFirst(n.self.data[entrySize:2*entrySize], parentFirst)
		return f.writeSlots(n.self, 1, 1)
	}
	return nil
}

// SetTimes stamps n's short entry.
func (f *FS) SetTimes(vn *volume.Node, t target.Times) error {
	n := rec(vn)
	stamp(f.short(n), t.Atime, t.Mtime, t.Btime)
	return f.writeSlots(n.parent, n.slot, 1)
}

// Chmod sets or clears the read-only attribute: a file nobody may write is
// read-only, as Go's os.Chmod makes it on Windows.
func (f *FS) Chmod(vn *volume.Node) error {
	n := rec(vn)
	e := f.short(n)
	if vn.Mode&0o200 == 0 {
		e[11] |= attrReadOnly
	} else {
		e[11] &^= attrReadOnly
	}
	return f.writeSlots(n.parent, n.slot, 1)
}

// WriteSlack writes data past byte at of n's content, in its last cluster.
func (f *FS) WriteSlack(vn *volume.Node, at int64, data []byte) error {
	n := rec(vn)
	cs := int64(f.g.ClusterSize)
	i := int(at / cs)
	if at%cs == 0 || i >= len(n.chain) || at%cs+int64(len(data)) > cs {
		return fmt.Errorf("%d bytes from byte %d do not fit the slack of a %d-byte cluster", len(data), at, cs)
	}
	_, err := f.dev.WriteAt(data, f.g.clusterOffset(n.chain[i])+at%cs)
	return err
}

// Flush writes both FATs, the FSInfo sectors and the boot sectors.
func (f *FS) Flush() error {
	buf := make([]byte, int64(f.g.FATSectors)*sectorSize)
	for i, v := range f.fat {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	for i := range numFATs {
		if _, err := f.dev.WriteAt(buf, f.g.fatOffset(i)); err != nil {
			return err
		}
	}
	return f.writeBoot()
}

// writeBoot writes the boot sector and FSInfo, and their backups.
func (f *FS) writeBoot() error {
	boot := bootSector(f.g, f.o.Hidden, f.o.Serial, f.o.Label)
	info := fsInfo(f.alloc.Free(), f.alloc.Hint())
	for _, base := range []int64{0, backupBoot} {
		if _, err := f.dev.WriteAt(boot, base*sectorSize); err != nil {
			return err
		}
		if _, err := f.dev.WriteAt(info, (base+fsInfoSector)*sectorSize); err != nil {
			return err
		}
	}
	return nil
}

// Open reads the finished volume back.
func (f *FS) Open() (target.Reader, error) { return Open(f.dev) }

var _ volume.Driver = (*FS)(nil)
