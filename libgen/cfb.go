package libgen

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
)

// A compound file ([MS-CFB]) is a small file system in one file: a FAT of
// 512-byte sectors, a directory of 128-byte entries arranged as a tree of
// storages and streams, and a second, finer FAT (the MiniFAT) for the
// streams under 4096 bytes, which live packed in 64-byte sectors inside one
// stream of the root (the mini stream). Office keeps a document's macros in
// one, vbaProject.bin.
//
// fsagen writes version 3. Every CLSID, state and time is zero, which the
// specification allows for every entry, so the bytes depend on the names and
// contents alone. Each storage's children are a binary search tree in the
// order the specification fixes, balanced, with every node black: the
// specification names that as the simplest valid red-black tree.

// CFBEntry is one stream, or with Storage set one storage holding Children,
// in a compound file.
type CFBEntry struct {
	Name     string
	Data     []byte
	Storage  bool
	Children []CFBEntry
}

const (
	cfbSector      = 512
	cfbMiniSector  = 64
	cfbMiniCutoff  = 4096
	cfbDirEntry    = 128
	cfbHeaderFATs  = 109
	cfbFreeSect    = 0xFFFFFFFF
	cfbEndOfChain  = 0xFFFFFFFE
	cfbFATSect     = 0xFFFFFFFD
	cfbNoStream    = 0xFFFFFFFF
	cfbMaxNameUTF  = 31
	cfbTypeStorage = 1
	cfbTypeStream  = 2
	cfbTypeRoot    = 5
	cfbColorBlack  = 1
)

var cfbSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// cfbNode is one directory entry as it will be written.
type cfbNode struct {
	name               string
	kind               byte
	left, right, child uint32
	data               []byte
	start              uint32
	size               uint64
	children           []int
}

// BuildCFB writes a compound file whose root storage holds entries.
func BuildCFB(entries []CFBEntry) ([]byte, error) {
	nodes := []*cfbNode{{name: "Root Entry", kind: cfbTypeRoot}}
	if err := cfbAdd(&nodes, 0, entries); err != nil {
		return nil, err
	}
	for _, n := range nodes {
		n.left, n.right, n.child = cfbNoStream, cfbNoStream, cfbNoStream
	}
	for _, n := range nodes {
		if len(n.children) > 0 {
			n.child = cfbTree(nodes, n.children)
		}
	}

	// The streams under the cutoff are packed into the mini stream, each from
	// a 64-byte boundary, and chained in the MiniFAT; the rest get sectors of
	// their own.
	var mini []byte
	var miniFAT []uint32
	var big []*cfbNode
	for _, n := range nodes[1:] {
		if n.kind != cfbTypeStream {
			continue
		}
		n.size = uint64(len(n.data))
		switch {
		case len(n.data) == 0:
			n.start = cfbEndOfChain
		case len(n.data) < cfbMiniCutoff:
			n.start = uint32(len(miniFAT))
			miniFAT = appendChain(miniFAT, len(miniFAT), roundUp(len(n.data), cfbMiniSector)/cfbMiniSector)
			mini = append(mini, n.data...)
			mini = append(mini, make([]byte, roundUp(len(mini), cfbMiniSector)-len(mini))...)
		default:
			big = append(big, n)
		}
	}

	sectors := func(n int) int { return roundUp(n, cfbSector) / cfbSector }
	nDir := sectors(len(nodes) * cfbDirEntry)
	nMiniFAT := sectors(len(miniFAT) * 4)
	nMini := sectors(len(mini))
	rest := nDir + nMiniFAT + nMini
	for _, n := range big {
		rest += sectors(len(n.data))
	}
	// The FAT has to describe its own sectors too.
	nFAT := 0
	for nFAT*cfbSector/4 < nFAT+rest {
		nFAT++
	}
	if nFAT > cfbHeaderFATs {
		return nil, fmt.Errorf("compound file of %d sectors needs %d FAT sectors, more than the %d its header lists", nFAT+rest, nFAT, cfbHeaderFATs)
	}

	fat := make([]uint32, nFAT*cfbSector/4)
	for i := range fat {
		fat[i] = cfbFreeSect
	}
	for i := 0; i < nFAT; i++ {
		fat[i] = cfbFATSect
	}
	next := nFAT
	place := func(count int) uint32 {
		if count == 0 {
			return cfbEndOfChain
		}
		start := next
		copy(fat[start:], appendChain(nil, start, count))
		next += count
		return uint32(start)
	}
	dirStart := place(nDir)
	miniFATStart := place(nMiniFAT)
	nodes[0].start = place(nMini)
	nodes[0].size = uint64(len(mini))
	for _, n := range big {
		n.start = place(sectors(len(n.data)))
	}

	out := make([]byte, cfbSector*(1+next))
	h := out[:cfbSector]
	copy(h, cfbSignature)
	binary.LittleEndian.PutUint16(h[0x18:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(h[0x1A:], 0x0003) // major version: 512-byte sectors
	binary.LittleEndian.PutUint16(h[0x1C:], 0xFFFE) // byte order: little-endian
	binary.LittleEndian.PutUint16(h[0x1E:], 9)      // sector shift
	binary.LittleEndian.PutUint16(h[0x20:], 6)      // mini sector shift
	binary.LittleEndian.PutUint32(h[0x2C:], uint32(nFAT))
	binary.LittleEndian.PutUint32(h[0x30:], dirStart)
	binary.LittleEndian.PutUint32(h[0x38:], cfbMiniCutoff)
	binary.LittleEndian.PutUint32(h[0x3C:], miniFATStart)
	binary.LittleEndian.PutUint32(h[0x40:], uint32(nMiniFAT))
	binary.LittleEndian.PutUint32(h[0x44:], cfbEndOfChain) // no DIFAT sectors
	for i := 0; i < cfbHeaderFATs; i++ {
		v := uint32(cfbFreeSect)
		if i < nFAT {
			v = uint32(i)
		}
		binary.LittleEndian.PutUint32(h[0x4C+4*i:], v)
	}

	sector := func(n uint32) []byte { return out[cfbSector*(1+int(n)):] }
	for i, v := range fat {
		binary.LittleEndian.PutUint32(sector(0)[4*i:], v)
	}
	for i, n := range nodes {
		cfbWriteEntry(sector(dirStart)[i*cfbDirEntry:], n)
	}
	// Unused entries in the last directory sector are empty, with no
	// siblings and no child.
	for i := len(nodes); i < nDir*cfbSector/cfbDirEntry; i++ {
		e := sector(dirStart)[i*cfbDirEntry:]
		binary.LittleEndian.PutUint32(e[0x44:], cfbNoStream)
		binary.LittleEndian.PutUint32(e[0x48:], cfbNoStream)
		binary.LittleEndian.PutUint32(e[0x4C:], cfbNoStream)
	}
	if nMiniFAT > 0 {
		m := sector(miniFATStart)[:nMiniFAT*cfbSector]
		for i := range len(m) / 4 {
			v := uint32(cfbFreeSect)
			if i < len(miniFAT) {
				v = miniFAT[i]
			}
			binary.LittleEndian.PutUint32(m[4*i:], v)
		}
	}
	if nMini > 0 {
		copy(sector(nodes[0].start), mini)
	}
	for _, n := range big {
		copy(sector(n.start), n.data)
	}
	return out, nil
}

// cfbAdd appends entries, and everything under them, to nodes as the
// children of nodes[parent].
func cfbAdd(nodes *[]*cfbNode, parent int, entries []CFBEntry) error {
	seen := map[string]bool{}
	for _, e := range entries {
		if err := checkCFBName(e.Name); err != nil {
			return err
		}
		if seen[cfbFold(e.Name)] {
			return fmt.Errorf("compound file: two entries named %q in one storage", e.Name)
		}
		seen[cfbFold(e.Name)] = true
		n := &cfbNode{name: e.Name, kind: cfbTypeStream, data: e.Data}
		if e.Storage {
			n.kind, n.data = cfbTypeStorage, nil
		}
		*nodes = append(*nodes, n)
		id := len(*nodes) - 1
		(*nodes)[parent].children = append((*nodes)[parent].children, id)
		if e.Storage {
			if err := cfbAdd(nodes, id, e.Children); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCFBName refuses a name a directory entry cannot hold.
func checkCFBName(name string) error {
	switch n := len(utf16.Encode([]rune(name))); {
	case n == 0:
		return fmt.Errorf("compound file: an entry has no name")
	case n > cfbMaxNameUTF:
		return fmt.Errorf("compound file: %q is longer than the %d UTF-16 units a name holds", name, cfbMaxNameUTF)
	case strings.ContainsAny(name, `/\:!`):
		return fmt.Errorf("compound file: %q contains a character names cannot (/ \\ : !)", name)
	}
	return nil
}

// cfbFold is a name upper-cased the way the specification compares names.
func cfbFold(name string) string { return strings.Map(unicode.ToUpper, name) }

// cfbLess is the specification's order for siblings: a shorter name first,
// then names of one length by their upper-cased UTF-16 units.
func cfbLess(a, b string) int {
	ua, ub := utf16.Encode([]rune(cfbFold(a))), utf16.Encode([]rune(cfbFold(b)))
	if len(ua) != len(ub) {
		return len(ua) - len(ub)
	}
	return slices.Compare(ua, ub)
}

// cfbTree links ids, the children of one storage, into a balanced binary
// search tree and returns its root.
func cfbTree(nodes []*cfbNode, ids []int) uint32 {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, func(a, b int) int { return cfbLess(nodes[a].name, nodes[b].name) })
	var build func(lo, hi int) uint32
	build = func(lo, hi int) uint32 {
		if lo >= hi {
			return cfbNoStream
		}
		mid := (lo + hi) / 2
		n := nodes[ids[mid]]
		n.left, n.right = build(lo, mid), build(mid+1, hi)
		return uint32(ids[mid])
	}
	return build(0, len(ids))
}

// cfbWriteEntry writes one directory entry. Its CLSID, state bits and both
// times stay zero.
func cfbWriteEntry(e []byte, n *cfbNode) {
	name := utf16z(n.name)
	copy(e, name)
	binary.LittleEndian.PutUint16(e[0x40:], uint16(len(name)))
	e[0x42], e[0x43] = n.kind, cfbColorBlack
	binary.LittleEndian.PutUint32(e[0x44:], n.left)
	binary.LittleEndian.PutUint32(e[0x48:], n.right)
	binary.LittleEndian.PutUint32(e[0x4C:], n.child)
	binary.LittleEndian.PutUint32(e[0x74:], n.start)
	binary.LittleEndian.PutUint64(e[0x78:], n.size)
}

// appendChain appends to fat a chain of count entries for the sectors from
// first on, each pointing at the next and the last ending it.
func appendChain(fat []uint32, first, count int) []uint32 {
	for i := 0; i < count; i++ {
		v := uint32(first + i + 1)
		if i == count-1 {
			v = cfbEndOfChain
		}
		fat = append(fat, v)
	}
	return fat
}
