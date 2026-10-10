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

// encode is the entry as an index holds it.
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

// entries lays a node's entries out, its end entry last.
func entries(es []entry, child int64) []byte {
	var b []byte
	for _, e := range es {
		b = append(b, e.encode()...)
	}
	return append(b, endEntry(child)...)
}

// indexRoot is an $INDEX_ROOT value: what it indexes and how it collates
// it, then the node's header and entries. A large index's root holds only
// an end entry that points at the first index block.
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

// indexBlock lays the leaf entries body out as the index block of VCN vcn,
// over prev, its last image: past the entries what was there stays, as
// Windows leaves it when entries move up over a removed one.
func indexBlock(prev []byte, vcn int64, body []byte) ([]byte, error) {
	const usaOfs, entriesAt = 0x28, 0x40
	if entriesAt+len(body) > indexSize {
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
	copy(b[entriesAt:], body)
	return b, nil
}

// dirIndex is a directory's $I30 index: its entries in order, and once
// they outgrow the record, the index block they live in instead.
type dirIndex struct {
	entries []entry
	large   bool
	// block is the index block as it was last written, before its update
	// sequence array was applied, and usn the number it was written with.
	block []byte
	usn   uint16
}

// insert files e in its place.
func (d *dirIndex) insert(e entry) {
	i, _ := slices.BinarySearchFunc(d.entries, e, func(a, b entry) int { return collate(a.name, b.name) })
	d.entries = slices.Insert(d.entries, i, e)
}

// remove takes the entry for name out, and reports whether there was one.
func (d *dirIndex) remove(name string) bool {
	i := slices.IndexFunc(d.entries, func(e entry) bool { return e.name == name })
	if i < 0 {
		return false
	}
	d.entries = slices.Delete(d.entries, i, i+1)
	return true
}
