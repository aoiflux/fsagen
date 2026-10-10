package ntfs

import (
	"bytes"
	"encoding/binary"

	"github.com/aoiflux/fsagen/target"
)

// goneEntry is an entry taken out of a directory's index by a delete or a
// rename: the record it named, the $FILE_NAME it was filed under, and the
// operation that took it out.
type goneEntry struct {
	dir   *node
	ref   uint64
	key   []byte
	op    int
	path  string
	cause string
}

// forget notes that n's name nm is leaving directory d's index, so what is
// left of its entry can be looked for once the volume is finished.
func (f *FS) forget(d *node, n *node, nm *name, cause string) {
	op, p := f.res.Source()
	f.gone = append(f.gone, goneEntry{dir: d, ref: n.rec.ref(), key: n.entry(nm).key, op: op, path: p, cause: cause})
}

// leftEntries records as residue each entry taken out of an index whose
// bytes are still whole in one of the directory's index blocks: past the
// entries of a block in use, where the entries after it moved up from, or
// anywhere in a block the index freed, or in any block of a directory
// that was deleted. A tool reading index slack finds it there. Where it
// is found more than once, the first place counts; an entry in the
// $INDEX_ROOT is not looked for.
func (f *FS) leftEntries() error {
	blocks := map[*node][]indexImage{}
	for _, g := range f.gone {
		imgs, ok := blocks[g.dir]
		if !ok {
			var err error
			if imgs, err = f.indexImages(g.dir); err != nil {
				return err
			}
			blocks[g.dir] = imgs
		}
		f.findEntry(g, imgs)
	}
	return nil
}

// indexImage is one index block of a directory as the finished volume
// holds it, its update sequence array undone, and where looking in it for
// what was left starts.
type indexImage struct {
	pos  int64
	b    []byte
	from int
}

// indexImages reads directory d's index blocks back from the volume, as a
// tool would: every one $INDEX_ALLOCATION maps that is still an index
// block of d.
func (f *FS) indexImages(d *node) ([]indexImage, error) {
	ia := d.rec.find(atIndexAlloc, "$I30")
	if ia == nil || d.dir == nil {
		return nil, nil
	}
	live := d.rec.flags&recInUse != 0
	var out []indexImage
	per := int64(f.g.perIndexBlock())
	for bit := int64(0); f.blockPos(bit*per)+indexSize <= ia.size; bit++ {
		vcn := bit * per
		pos := f.blockPos(vcn)
		b, _, err := f.readRuns(ia.runs, pos, indexSize)
		if err != nil {
			return nil, err
		}
		if string(b[:4]) != "INDX" || unprotect(b) != nil || int64(binary.LittleEndian.Uint64(b[16:])) != vcn {
			continue
		}
		from := 0x40
		if inUse := bit/8 < int64(len(d.dir.bitmap)) && d.dir.bitmap[bit/8]&(1<<(bit%8)) != 0; live && inUse {
			from = 0x18 + int(binary.LittleEndian.Uint32(b[0x1C:]))
		}
		out = append(out, indexImage{pos, b, from})
	}
	return out, nil
}

// findEntry records g as residue at the first place its bytes are whole.
func (f *FS) findEntry(g goneEntry, imgs []indexImage) {
	le := binary.LittleEndian
	n := len(g.key)
	for _, img := range imgs {
		for p := (img.from + 7) &^ 7; p+16+n <= indexSize; p += 8 {
			e := img.b[p:]
			length := int(le.Uint16(e[8:]))
			if le.Uint64(e) != g.ref || int(le.Uint16(e[10:])) != n || length < 16+n || p+length > indexSize || !bytes.Equal(e[16:16+n], g.key) {
				continue
			}
			ia := g.dir.rec.find(atIndexAlloc, "$I30")
			off, run, err := f.at(ia.runs, img.pos+int64(p))
			if err != nil || run < int64(length) {
				continue
			}
			disk := make([]byte, length)
			if _, err := f.dev.ReadAt(disk, off); err != nil {
				continue
			}
			entry := &target.ResidueEntry{Type: "ntfs_index_entry", Number: int64(refNum(g.ref)), Seq: int(g.ref >> 48), Offset: f.dev.Abs(off), Length: length}
			f.res.AddFrom(g.op, g.path, g.cause, entry, disk, nil, nil)
			return
		}
	}
}
