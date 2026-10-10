package ntfs

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// entry is an index entry: a directory's, filing a record under the
// $FILE_NAME it holds as its key, or a view index's, filing data under any
// key.
type entry struct {
	ref  uint64
	name string
	key  []byte
	// child is the VCN of the index block that holds the entries before
	// this one, in a node that has children.
	child int64
	// view entries keep their data offset and length, and body is their
	// key and data as they lie after the 16-byte header.
	view       bool
	dataOffset uint16
	dataLength uint16
	body       []byte
}

// fileEntry files the record ref under its $FILE_NAME f.
func fileEntry(ref uint64, f fileName) entry {
	return entry{ref: ref, name: f.name, key: f.encode()}
}

// encode is the entry as a leaf holds it.
func (e entry) encode() []byte {
	le := binary.LittleEndian
	if e.view {
		b := make([]byte, align8(16+len(e.body)))
		le.PutUint16(b[0:], e.dataOffset)
		le.PutUint16(b[2:], e.dataLength)
		le.PutUint16(b[8:], uint16(len(b)))
		le.PutUint16(b[10:], uint16(e.dataOffset)-16)
		copy(b[16:], e.body)
		return b
	}
	b := make([]byte, align8(16+len(e.key)))
	le.PutUint64(b[0:], e.ref)
	le.PutUint16(b[8:], uint16(len(b)))
	le.PutUint16(b[10:], uint16(len(e.key)))
	copy(b[16:], e.key)
	return b
}

// encodeIn is the entry as a node holds it: in a node with children, with
// its child's VCN at its end.
func (e entry) encodeIn(node bool) []byte {
	b := e.encode()
	if !node {
		return b
	}
	le := binary.LittleEndian
	b = append(b, make([]byte, 8)...)
	le.PutUint16(b[8:], uint16(len(b)))
	le.PutUint16(b[12:], ieNode)
	le.PutUint64(b[len(b)-8:], uint64(e.child))
	return b
}

// size is how many bytes the entry takes in a node, with children or not.
func (e entry) size(node bool) int {
	n := align8(16 + len(e.key))
	if e.view {
		n = align8(16 + len(e.body))
	}
	if node {
		n += 8
	}
	return n
}

// endEntry ends a node's entries; in a node with children, it points at
// the index block of VCN child (child < 0 for none).
func endEntry(child int64) []byte {
	le := binary.LittleEndian
	if child < 0 {
		b := make([]byte, 16)
		le.PutUint16(b[8:], 16)
		le.PutUint16(b[12:], ieEnd)
		return b
	}
	b := make([]byte, 24)
	le.PutUint16(b[8:], 24)
	le.PutUint16(b[12:], ieEnd|ieNode)
	le.PutUint64(b[16:], uint64(child))
	return b
}

// entries lays a leaf's entries out, its end entry last.
func entries(es []entry, child int64) []byte {
	var b []byte
	for _, e := range es {
		b = append(b, e.encode()...)
	}
	return append(b, endEntry(child)...)
}

// indexRoot is an $INDEX_ROOT value: what it indexes and how it collates
// it, then the node's header and entries. A large index's root has
// children in index blocks.
func indexRoot(typ, coll uint32, g Geometry, body []byte, large bool) []byte {
	le := binary.LittleEndian
	b := make([]byte, 32, 32+len(body))
	le.PutUint32(b[0:], typ)
	le.PutUint32(b[4:], coll)
	le.PutUint32(b[8:], indexSize)
	b[12] = g.perIndexBlock()
	le.PutUint32(b[16:], 16)
	le.PutUint32(b[20:], uint32(16+len(body)))
	le.PutUint32(b[24:], uint32(16+len(body)))
	if large {
		b[28] = ihLarge
	}
	return append(b, body...)
}

// blockRoom is how many bytes of entries an index block holds.
const blockRoom = indexSize - 0x40

// indexBlock lays the entries body out as the index block of VCN vcn,
// over prev, its last image: past the entries what was there stays, as an
// entry's removal leaves the bytes the others moved up from.
func indexBlock(prev []byte, vcn int64, body []byte, node bool) ([]byte, error) {
	const usaOfs, entriesAt = 0x28, 0x40
	if len(body) > blockRoom {
		return nil, fmt.Errorf("%d bytes of entries do not fit one index block", len(body))
	}
	le := binary.LittleEndian
	b := prev
	copy(b, "INDX")
	le.PutUint16(b[4:], usaOfs)
	le.PutUint16(b[6:], indexSize/sectorSize+1)
	le.PutUint64(b[8:], 0)
	le.PutUint64(b[16:], uint64(vcn))
	le.PutUint32(b[0x18:], entriesAt-0x18)
	le.PutUint32(b[0x1C:], uint32(entriesAt-0x18+len(body)))
	le.PutUint32(b[0x20:], indexSize-0x18)
	b[0x24] = 0
	if node {
		b[0x24] = ihLarge
	}
	copy(b[entriesAt:], body)
	return b, nil
}

// inode is a node of a directory's index, a B-tree: its root, in
// $INDEX_ROOT, or an index block.
type inode struct {
	es []entry
	// end is the VCN of the index block the end entry points to, -1 in a
	// leaf; vcn is the block's own, -1 for the root.
	end, vcn int64
	// raw is a block as it was last written, before its update sequence
	// array was applied, and usn the number it was written with. The
	// root's $INDEX_ROOT is always exactly as big as its entries.
	raw []byte
	usn uint16
}

func (n *inode) leaf() bool { return n.end < 0 }

// child is the VCN of the block before entry i, or after the last entry.
func (n *inode) child(i int) int64 {
	if i < len(n.es) {
		return n.es[i].child
	}
	return n.end
}

// size is how many bytes the node's entries take, its end entry's too.
func (n *inode) size() int {
	s := len(endEntry(n.end))
	for _, e := range n.es {
		s += e.size(!n.leaf())
	}
	return s
}

func (n *inode) body() []byte {
	var b []byte
	for _, e := range n.es {
		b = append(b, e.encodeIn(!n.leaf())...)
	}
	return append(b, endEntry(n.end)...)
}

// insert puts e at pos with the block left before it, and points the
// entry after it at the block right.
func (n *inode) insert(pos int, e entry, left, right int64) {
	e.child = left
	n.es = slices.Insert(n.es, pos, e)
	if pos+1 < len(n.es) {
		n.es[pos+1].child = right
	} else {
		n.end = right
	}
}

// dirIndex is an index: a directory's $I30, or a view index such as
// $Reparse's $R.
type dirIndex struct {
	// name is the index's attribute name, typ the attribute it indexes (0
	// for a view index), coll how it collates, and cmp orders two entries
	// that way.
	name      string
	typ, coll uint32
	cmp       func(a, b entry) int
	root      *inode
	blocks    map[int64]*inode
	// bitmap is $BITMAP's value, nil while the index has never had a
	// block.
	bitmap []byte
	// dirty are the blocks to write, and rootDirty says the record is to
	// be written.
	dirty     map[int64]bool
	rootDirty bool
}

// newDirIndex is an empty directory's index.
func newDirIndex() *dirIndex { return newIndex("$I30", atFileName, collFileName, byName) }

// newIndex is an empty index.
func newIndex(name string, typ, coll uint32, cmp func(a, b entry) int) *dirIndex {
	return &dirIndex{name: name, typ: typ, coll: coll, cmp: cmp, root: &inode{end: -1, vcn: -1}, blocks: map[int64]*inode{}, dirty: map[int64]bool{}}
}

// byName orders directory entries by name, as COLLATION_FILE_NAME does.
func byName(a, b entry) int { return collate(a.name, b.name) }

// byULongs orders view entries by their keys read as 32-bit numbers, one
// after another, as COLLATION_NTOFS_ULONGS does.
func byULongs(a, b entry) int {
	le := binary.LittleEndian
	ka, kb := a.body[:a.dataOffset-16], b.body[:b.dataOffset-16]
	for i := 0; i+4 <= len(ka) && i+4 <= len(kb); i += 4 {
		if c := cmpU32(le.Uint32(ka[i:]), le.Uint32(kb[i:])); c != 0 {
			return c
		}
	}
	return len(ka) - len(kb)
}

// step is a node on the way down the index, and the place in it the way
// goes on from or ends at.
type step struct {
	n   *inode
	pos int
}

// lookup walks down the index to key's entry if there is one, else to the
// place in a leaf it would go.
func (ix *dirIndex) lookup(key entry) ([]step, bool) {
	var path []step
	for n := ix.root; ; n = ix.blocks[n.child(path[len(path)-1].pos)] {
		i, found := slices.BinarySearchFunc(n.es, key, ix.cmp)
		path = append(path, step{n, i})
		if found || n.leaf() {
			return path, found
		}
	}
}

// mark says node n is to be written.
func (ix *dirIndex) mark(n *inode) {
	if n == ix.root {
		ix.rootDirty = true
	} else {
		ix.dirty[n.vcn] = true
	}
}

// rootValue is the $INDEX_ROOT value.
func (ix *dirIndex) rootValue(g Geometry) []byte {
	return indexRoot(ix.typ, ix.coll, g, ix.root.body(), !ix.root.leaf())
}

// An index is a B-tree, changed as libntfs-3g changes one:
//
//   - A new entry goes into a leaf. The root grows in the record while the
//     record keeps 120 bytes free; past that, its entries move to a new
//     index block and it points there. $INDEX_ROOT is resized to what its
//     entries take at every change.
//   - A full block splits at its median entry by count: the entries after
//     it go to a new block, the median goes up into the parent in front of
//     the entry that pointed to the block, and the block keeps those
//     before. A parent with no room is split or moved first, and the
//     insert starts over.
//   - A removed entry in a leaf is taken out. One in a node with children
//     is replaced by its successor, the first entry of the leftmost leaf
//     after it. A leaf left empty is freed, and the parent's entry that
//     pointed to it is taken out and added again from the top.
//   - A new block takes the lowest VCN free in $BITMAP, which grows 8 bytes
//     at a time, and is written whole, from zeros. A freed block is left on
//     disk as it was.

// indexAdd files e in directory d's index.
func (f *FS) indexAdd(d *node, e entry) error {
	ix := d.dir
	for {
		path, found := ix.lookup(e)
		if found {
			return fmt.Errorf("record %d's %s already has an entry %q", d.rec.num, ix.name, e.name)
		}
		at := path[len(path)-1]
		need := at.n.size() + e.size(false)
		fits := need <= blockRoom
		var err error
		switch {
		case at.n == ix.root:
			fits, err = f.makeRoom(d, need)
		case !fits:
			_, err = f.split(d, path)
		}
		if err != nil {
			return err
		}
		if fits {
			at.n.es = slices.Insert(at.n.es, at.pos, e)
			ix.mark(at.n)
			return nil
		}
	}
}

// makeRoom reports true if d's record holds its $INDEX_ROOT grown to room
// bytes of entries and keeps 120 bytes free, or holds it at all when it
// had less free before, as libntfs-3g resizes it; else it moves the root's
// entries to a new index block and reports false. Where the record would
// not hold the root at all, libntfs-3g moves the root out to an extension
// record; fsagen moves its entries to a block then too.
func (f *FS) makeRoom(d *node, room int) (bool, error) {
	ix := d.dir
	oldLen, newLen := align8(64+ix.root.size()), align8(64+room)
	used := d.rec.used() - len(d.rec.find(atIndexRoot, ix.name).encode()) + oldLen
	if after := used - oldLen + newLen; after <= recordSize && (newLen <= oldLen || after+120 <= recordSize || used+120 > recordSize) {
		return true, nil
	}
	return false, f.reparent(d)
}

// reparent moves the root's entries to a new index block, and points the
// root's end entry at it; the first time, it gives the directory $BITMAP
// and $INDEX_ALLOCATION.
func (f *FS) reparent(d *node) error {
	ix := d.dir
	if ix.bitmap == nil {
		ix.bitmap = make([]byte, 8)
		d.rec.add(&attr{typ: atBitmap, name: ix.name, resident: true, value: ix.bitmap})
		d.rec.add(nonresident(atIndexAlloc, ix.name, 0, nil, 0, 0, 0))
	}
	vcn, err := f.newBlock(d, ix.root.es, ix.root.end)
	if err != nil {
		return err
	}
	if ix.blocks[vcn].size() > blockRoom {
		return fmt.Errorf("record %d's index root does not fit an index block", d.rec.num)
	}
	ix.root.es, ix.root.end = nil, vcn
	ix.rootDirty = true
	return nil
}

// newBlock makes a new index block of es and end, at the lowest VCN free
// in $BITMAP, with $INDEX_ALLOCATION grown to hold it, and returns its VCN.
func (f *FS) newBlock(d *node, es []entry, end int64) (int64, error) {
	ix := d.dir
	bit := len(ix.bitmap) * 8
	for i := range bit {
		if ix.bitmap[i/8]&(1<<(i%8)) == 0 {
			bit = i
			break
		}
	}
	if bit/8 >= len(ix.bitmap) {
		ix.bitmap = append(ix.bitmap, make([]byte, 8)...)
	}
	ix.bitmap[bit/8] |= 1 << (bit % 8)
	d.rec.find(atBitmap, ix.name).value = ix.bitmap
	vcn := int64(bit) * int64(f.g.perIndexBlock())
	ix.blocks[vcn] = &inode{es: es, end: end, vcn: vcn, raw: make([]byte, indexSize), usn: 1}
	ix.dirty[vcn] = true
	ix.rootDirty = true
	return vcn, f.cover(d, vcn)
}

// freeBlock frees index block vcn in $BITMAP and leaves it on disk as it
// was last written.
func (f *FS) freeBlock(d *node, vcn int64) {
	ix := d.dir
	bit := vcn / int64(f.g.perIndexBlock())
	ix.bitmap[bit/8] &^= 1 << (bit % 8)
	delete(ix.blocks, vcn)
	delete(ix.dirty, vcn)
	ix.rootDirty = true
}

// split splits the index block at the end of path in two. When the parent
// has no room for the median, the parent is split or moved instead, and
// split reports false: the caller starts over.
func (f *FS) split(d *node, path []step) (bool, error) {
	ix := d.dir
	b, up := path[len(path)-1].n, path[len(path)-2]
	m := len(b.es) / 2
	median := b.es[m]
	vcn, err := f.newBlock(d, slices.Clone(b.es[m+1:]), b.end)
	if err != nil {
		return false, err
	}
	var ok bool
	if up.n == ix.root {
		if ok, err = f.makeRoom(d, ix.root.size()+median.size(true)); ok {
			ix.root.insert(up.pos, median, b.vcn, vcn)
			ix.mark(ix.root)
		}
	} else if up.n.size()+median.size(!b.leaf())+8 > blockRoom {
		_, err = f.split(d, path[:len(path)-1])
	} else {
		up.n.insert(up.pos, median, b.vcn, vcn)
		ix.mark(up.n)
		ok = true
	}
	if !ok {
		f.freeBlock(d, vcn)
		return false, err
	}
	if !b.leaf() {
		b.end = median.child
	}
	b.es = slices.Clone(b.es[:m])
	ix.mark(b)
	return true, nil
}

// indexRemove takes key's entry out of d's index.
func (f *FS) indexRemove(d *node, key entry) error {
	for {
		path, found := d.dir.lookup(key)
		if !found {
			return fmt.Errorf("record %d's %s has no entry %q", d.rec.num, d.dir.name, key.name)
		}
		done, err := f.remove(d, path)
		if err != nil || done {
			return err
		}
	}
}

// remove takes out the entry path ends at, and reports false when the
// index had to change first: the caller starts over.
func (f *FS) remove(d *node, path []step) (bool, error) {
	ix := d.dir
	k := len(path) - 1
	n, i := path[k].n, path[k].pos
	if n.leaf() {
		if n != ix.root && len(n.es) == 1 {
			return true, f.removeLeaf(d, path)
		}
		n.es = slices.Delete(n.es, i, i+1)
		ix.mark(n)
		return true, nil
	}
	// The successor: the first entry of the leftmost leaf after entry i.
	down := append(slices.Clone(path[:k]), step{n, i + 1})
	leaf := ix.blocks[n.child(i+1)]
	for down = append(down, step{leaf, 0}); !leaf.leaf(); down = append(down, step{leaf, 0}) {
		leaf = ix.blocks[leaf.child(0)]
	}
	if len(leaf.es) == 0 {
		return false, fmt.Errorf("record %d's index has an empty leaf", d.rec.num)
	}
	succ := leaf.es[0]
	succ.child = n.es[i].child
	if grow := succ.size(true) - n.es[i].size(true); grow > 0 {
		if n == ix.root {
			if ok, err := f.makeRoom(d, n.size()+grow); !ok {
				return false, err
			}
		} else if n.size()+grow > blockRoom {
			_, err := f.split(d, path[:k+1])
			return false, err
		}
	}
	n.es[i] = succ
	ix.mark(n)
	if len(leaf.es) == 1 {
		return true, f.removeLeaf(d, down)
	}
	leaf.es = slices.Delete(leaf.es, 0, 1)
	ix.mark(leaf)
	return true, nil
}

// removeLeaf frees the block path ends at, whose last entry is going, and
// takes the parent's entry that pointed to it out, to add it again; when
// that is the end entry, the entry before takes its place, and a parent
// left with no entries goes too, or, the root, becomes a leaf.
func (f *FS) removeLeaf(d *node, path []step) error {
	ix := d.dir
	k := len(path) - 1
	f.freeBlock(d, path[k].n.vcn)
	up := path[k-1]
	p := up.n
	switch {
	case up.pos < len(p.es):
		return f.takeout(d, p, up.pos)
	case len(p.es) > 0:
		p.end = p.es[len(p.es)-1].child
		return f.takeout(d, p, len(p.es)-1)
	case p != ix.root:
		return f.removeLeaf(d, path[:k])
	}
	p.end = -1
	ix.mark(p)
	return nil
}

// takeout takes entry i out of node p and adds it again from the top.
func (f *FS) takeout(d *node, p *inode, i int) error {
	e := p.es[i]
	e.child = 0
	p.es = slices.Delete(p.es, i, i+1)
	d.dir.mark(p)
	return f.indexAdd(d, e)
}

// indexUpdate puts e in place of the entry with its key in d's index.
func (f *FS) indexUpdate(d *node, e entry) error {
	path, found := d.dir.lookup(e)
	if !found {
		return fmt.Errorf("record %d's %s has no entry %q", d.rec.num, d.dir.name, e.name)
	}
	at := path[len(path)-1]
	e.child = at.n.es[at.pos].child
	at.n.es[at.pos] = e
	d.dir.mark(at.n)
	return nil
}
