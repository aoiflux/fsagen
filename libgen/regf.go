package libgen

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

// A Windows registry hive file (REGF), in the format Windows XP SP2 and
// later save: version 1.5, a 4 KiB base block, then hive bins of cells. Each
// key is a named-key cell listing its subkeys through a hash leaf ("lh",
// sorted the way Windows looks names up) and its values through a value
// list; small values are stored in the value cell itself and values past
// 16344 bytes are split into segments behind a big-data cell, as Windows
// does. Every key shares one security descriptor. That is what a hive parser
// walks and what Windows itself loads.
//
// The builder writes a hive that has just been saved: no free cells but the
// rest of the last bin, nothing deleted, primary and secondary sequence
// numbers equal so no log needs replaying.

// RegTypes is the closed set of value types a hive can hold here, by their
// Windows names.
var RegTypes = []string{"REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_MULTI_SZ", "REG_QWORD"}

var regTypeCode = map[string]uint32{
	"REG_NONE": 0, "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
	"REG_DWORD_BIG_ENDIAN": 5, "REG_MULTI_SZ": 7, "REG_QWORD": 11,
}

const (
	// MaxRegKeyName and MaxRegValueName bound names, in characters.
	MaxRegKeyName   = 255
	MaxRegValueName = 16383
	// regBigData is the largest value stored in one cell; past it a value is
	// split into segments of this size.
	regBigData = 16344
	// regLeafMax is the most subkeys one hash leaf lists; a key with more
	// gets an index of leaves ("ri").
	regLeafMax = 512
	regBinSize = 4096
)

// RegValue is one value of a key: a name, a type code and the data as the
// hive stores it.
type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

// RegKey is a key, by its path below the root, with when it was last written
// and its values in order.
type RegKey struct {
	Path        string // Software\Microsoft\Windows\CurrentVersion\Run
	LastWritten time.Time
	Values      []RegValue
}

// HiveSpec is a hive's contents.
type HiveSpec struct {
	// FileName is the name the base block records for the file it was saved
	// to; Windows keeps the last 31 characters of the path.
	FileName string
	// Modified is when the hive was last written; it also dates every key the
	// spec creates only as the parent of another.
	Modified time.Time
	Keys     []RegKey
}

// ParseRegValue reads a scenario's value as the hive stores it: text for the
// string types, a number for the integer types, hex digits (spaces allowed)
// for REG_BINARY and REG_NONE, and the list for REG_MULTI_SZ.
func ParseRegValue(typ, data string, strs []string) (uint32, []byte, error) {
	code, ok := regTypeCode[typ]
	if !ok {
		return 0, nil, fmt.Errorf("value type %q (want one of: %s)", typ, strings.Join(RegTypes, ", "))
	}
	if typ == "REG_MULTI_SZ" {
		if data != "" {
			return 0, nil, fmt.Errorf("REG_MULTI_SZ takes strings, a list, not data")
		}
		var b []byte
		for _, s := range strs {
			if s == "" {
				return 0, nil, fmt.Errorf("REG_MULTI_SZ cannot hold an empty string; it would end the list")
			}
			b = append(b, utf16z(s)...)
		}
		return code, append(b, 0, 0), nil
	}
	if len(strs) > 0 {
		return 0, nil, fmt.Errorf("strings is for REG_MULTI_SZ; %s takes data", typ)
	}
	number := func(bits int) (uint64, error) {
		v, base := strings.TrimSpace(data), 10
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			v, base = v[2:], 16
		}
		n, err := strconv.ParseUint(v, base, bits)
		if err != nil {
			return 0, fmt.Errorf("%s %q is not a %d-bit unsigned number", typ, data, bits)
		}
		return n, nil
	}
	switch typ {
	case "REG_SZ", "REG_EXPAND_SZ":
		return code, utf16z(data), nil
	case "REG_DWORD":
		n, err := number(32)
		return code, binary.LittleEndian.AppendUint32(nil, uint32(n)), err
	case "REG_DWORD_BIG_ENDIAN":
		n, err := number(32)
		return code, binary.BigEndian.AppendUint32(nil, uint32(n)), err
	case "REG_QWORD":
		n, err := number(64)
		return code, binary.LittleEndian.AppendUint64(nil, n), err
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(data), ""))
	if err != nil {
		return 0, nil, fmt.Errorf("%s %q is not hex bytes (for example 01 02 ff)", typ, data)
	}
	return code, b, nil
}

// SplitRegPath splits a key path at its backslashes, refusing an empty
// component and a name longer than a key's.
func SplitRegPath(p string) ([]string, error) {
	parts := strings.Split(strings.Trim(p, `\`), `\`)
	for _, c := range parts {
		switch {
		case c == "":
			return nil, fmt.Errorf("key path %q has an empty component", p)
		case len(utf16.Encode([]rune(c))) > MaxRegKeyName:
			return nil, fmt.Errorf("key name %q is longer than the %d characters a key name holds", c, MaxRegKeyName)
		}
	}
	return parts, nil
}

// regFold is a name as Windows compares it: upper case, unit by unit.
func regFold(name string) []uint16 {
	u := utf16.Encode([]rune(name))
	for i, c := range u {
		if c < 0xD800 || c > 0xDFFF {
			u[i] = uint16(unicode.ToUpper(rune(c)))
		}
	}
	return u
}

func regCompare(a, b string) int { return slices.Compare(regFold(a), regFold(b)) }

// regNode is a key while the tree is built.
type regNode struct {
	name     string
	written  time.Time
	values   []RegValue
	children []*regNode
	given    bool

	offset, listOff, valuesOff uint32
	parent                     *regNode
}

func (n *regNode) child(name string) *regNode {
	for _, c := range n.children {
		if regCompare(c.name, name) == 0 {
			return c
		}
	}
	return nil
}

// BuildHive writes the hive.
func BuildHive(spec HiveSpec) ([]byte, error) {
	root := &regNode{name: "ROOT", written: spec.Modified}
	for _, k := range spec.Keys {
		parts, err := SplitRegPath(k.Path)
		if err != nil {
			return nil, err
		}
		n := root
		for _, p := range parts {
			c := n.child(p)
			if c == nil {
				c = &regNode{name: p, written: spec.Modified, parent: n}
				n.children = append(n.children, c)
			}
			n = c
		}
		if n.given {
			return nil, fmt.Errorf("key %q is given twice", k.Path)
		}
		n.given = true
		if !k.LastWritten.IsZero() {
			n.written = k.LastWritten
		}
		for i, v := range k.Values {
			if len(utf16.Encode([]rune(v.Name))) > MaxRegValueName {
				return nil, fmt.Errorf("key %q: value name is longer than %d characters", k.Path, MaxRegValueName)
			}
			if slices.ContainsFunc(k.Values[:i], func(o RegValue) bool { return regCompare(o.Name, v.Name) == 0 }) {
				return nil, fmt.Errorf("key %q: value %q is given twice", k.Path, v.Name)
			}
		}
		n.values = k.Values
	}

	h := &hive{}
	h.alloc(root)
	return h.write(spec, root), nil
}

// hive lays cells out in bins and then writes them.
type hive struct {
	cells   []regCell
	end     uint32 // the next free offset in the bins
	binEnd  uint32 // where the current bin ends
	bins    []uint32
	skOff   uint32
	skCount int
}

// regCell is one cell: where it is and what fills it, which is written once
// every offset is known.
type regCell struct {
	off  uint32
	size uint32
	fill func([]byte)
	free bool
}

// place reserves a cell of n bytes of data (plus its size field, rounded to
// eight bytes) and returns its offset. A cell never crosses a bin; a cell
// bigger than a bin gets a bin of its own, sized to fit.
func (h *hive) place(n int, fill func([]byte)) uint32 {
	size := uint32(roundUp(n+4, 8))
	if h.end+size > h.binEnd {
		h.closeBin()
		binSize := uint32(roundUp(int(size)+32, regBinSize))
		h.bins = append(h.bins, h.end)
		h.binEnd = h.end + binSize
		h.end += 32
	}
	off := h.end
	h.cells = append(h.cells, regCell{off: off, size: size, fill: fill})
	h.end += size
	return off
}

// closeBin leaves the rest of the current bin as one free cell.
func (h *hive) closeBin() {
	if len(h.bins) > 0 && h.end < h.binEnd {
		h.cells = append(h.cells, regCell{off: h.end, size: h.binEnd - h.end, free: true})
	}
	h.end = h.binEnd
}

// alloc places every cell: the root, the shared security descriptor, then
// each key depth first with its values and its subkey list.
func (h *hive) alloc(root *regNode) {
	var walk func(n *regNode)
	sd := regSecurityDescriptor()
	walk = func(n *regNode) {
		h.skCount++
		n.offset = h.place(76+len(regName(n.name)), nil)
		if n.parent == nil {
			h.skOff = h.place(20+len(sd), nil)
		}
		if len(n.values) > 0 {
			n.valuesOff = h.place(4*len(n.values), nil)
		}
		slices.SortStableFunc(n.children, func(a, b *regNode) int { return regCompare(a.name, b.name) })
		if len(n.children) > 0 {
			if len(n.children) <= regLeafMax {
				n.listOff = h.place(4+8*len(n.children), nil)
			} else {
				leaves := (len(n.children) + regLeafMax - 1) / regLeafMax
				n.listOff = h.place(4+4*leaves, nil)
			}
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)
	h.allocValues(root, sd)
}

// cellFor is the cell placed at off. Cells are placed at rising offsets, so
// the list is sorted.
func (h *hive) cellFor(off uint32) *regCell {
	i, _ := slices.BinarySearchFunc(h.cells, off, func(c regCell, o uint32) int { return int(c.off) - int(o) })
	return &h.cells[i]
}

// allocValues places each value's cell and its data, and gives every placed
// cell its content.
func (h *hive) allocValues(root *regNode, sd []byte) {
	le := binary.LittleEndian
	var keys []*regNode
	var walk func(*regNode)
	walk = func(n *regNode) {
		keys = append(keys, n)
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)

	for _, n := range keys {
		var vkOffs []uint32
		for _, v := range n.values {
			v := v
			name := regName(v.Name)
			var dataOff uint32
			size := uint32(len(v.Data))
			switch {
			case len(v.Data) <= 4:
				size |= 0x80000000
				var inline [4]byte
				copy(inline[:], v.Data)
				dataOff = le.Uint32(inline[:])
			case len(v.Data) <= regBigData:
				dataOff = h.place(len(v.Data), func(b []byte) { copy(b, v.Data) })
			default:
				dataOff = h.placeBig(v.Data)
			}
			flags := uint16(0)
			if regLatin1(v.Name) {
				flags = 1
			}
			vkOffs = append(vkOffs, h.place(20+len(name), func(b []byte) {
				copy(b, "vk")
				le.PutUint16(b[2:], uint16(len(name)))
				le.PutUint32(b[4:], size)
				le.PutUint32(b[8:], dataOff)
				le.PutUint32(b[12:], v.Type)
				le.PutUint16(b[16:], flags)
				copy(b[20:], name)
			}))
		}
		if n.valuesOff != 0 {
			offs := vkOffs
			h.cellFor(n.valuesOff).fill = func(b []byte) {
				for i, o := range offs {
					le.PutUint32(b[4*i:], o)
				}
			}
		}
	}

	for _, n := range keys {
		n := n
		h.cellFor(n.offset).fill = func(b []byte) { h.nk(b, n) }
		if n.listOff != 0 {
			h.lists(n)
		}
	}
	h.cellFor(h.skOff).fill = func(b []byte) {
		copy(b, "sk")
		le.PutUint32(b[4:], h.skOff)
		le.PutUint32(b[8:], h.skOff)
		le.PutUint32(b[12:], uint32(h.skCount))
		le.PutUint32(b[16:], uint32(len(sd)))
		copy(b[20:], sd)
	}
}

// placeBig stores data past one cell's worth as a big-data cell, a list of
// its segments, and the segments. Every segment cell holds a full 16344
// bytes, the last one padded with zeros: Windows drops a value whose last
// segment is any shorter.
func (h *hive) placeBig(data []byte) uint32 {
	le := binary.LittleEndian
	var segs []uint32
	for i := 0; i < len(data); i += regBigData {
		seg := data[i:min(i+regBigData, len(data))]
		segs = append(segs, h.place(regBigData, func(b []byte) { copy(b, seg) }))
	}
	list := h.place(4*len(segs), func(b []byte) {
		for i, s := range segs {
			le.PutUint32(b[4*i:], s)
		}
	})
	return h.place(8, func(b []byte) {
		copy(b, "db")
		le.PutUint16(b[2:], uint16(len(segs)))
		le.PutUint32(b[4:], list)
	})
}

// lists fills a key's subkey list: one hash leaf, or an index of leaves
// placed after everything else.
func (h *hive) lists(n *regNode) {
	le := binary.LittleEndian
	leaf := func(children []*regNode) func([]byte) {
		return func(b []byte) {
			copy(b, "lh")
			le.PutUint16(b[2:], uint16(len(children)))
			for i, c := range children {
				le.PutUint32(b[4+8*i:], c.offset)
				le.PutUint32(b[8+8*i:], regHash(c.name))
			}
		}
	}
	if len(n.children) <= regLeafMax {
		h.cellFor(n.listOff).fill = leaf(n.children)
		return
	}
	var leaves []uint32
	for i := 0; i < len(n.children); i += regLeafMax {
		part := n.children[i:min(i+regLeafMax, len(n.children))]
		leaves = append(leaves, h.place(4+8*len(part), leaf(part)))
	}
	h.cellFor(n.listOff).fill = func(b []byte) {
		copy(b, "ri")
		le.PutUint16(b[2:], uint16(len(leaves)))
		for i, l := range leaves {
			le.PutUint32(b[4+4*i:], l)
		}
	}
}

// nk fills a named-key cell.
func (h *hive) nk(b []byte, n *regNode) {
	le := binary.LittleEndian
	name := regName(n.name)
	flags := uint16(0)
	if regLatin1(n.name) {
		flags |= 0x20 // KEY_COMP_NAME
	}
	parent := uint32(0)
	if n.parent == nil {
		flags |= 0x0C // KEY_HIVE_ENTRY | KEY_NO_DELETE
	} else {
		parent = n.parent.offset
	}
	maxSub, maxVal, maxData := 0, 0, 0
	for _, c := range n.children {
		maxSub = max(maxSub, 2*len(utf16.Encode([]rune(c.name))))
	}
	for _, v := range n.values {
		maxVal = max(maxVal, 2*len(utf16.Encode([]rune(v.Name))))
		maxData = max(maxData, len(v.Data))
	}
	none := uint32(0xFFFFFFFF)
	list, values := none, none
	if n.listOff != 0 {
		list = n.listOff
	}
	if n.valuesOff != 0 {
		values = n.valuesOff
	}
	copy(b, "nk")
	le.PutUint16(b[2:], flags)
	le.PutUint64(b[4:], filetime(n.written))
	le.PutUint32(b[16:], parent)
	le.PutUint32(b[20:], uint32(len(n.children)))
	le.PutUint32(b[28:], list)
	le.PutUint32(b[32:], none) // no volatile subkeys in a file
	le.PutUint32(b[36:], uint32(len(n.values)))
	le.PutUint32(b[40:], values)
	le.PutUint32(b[44:], h.skOff)
	le.PutUint32(b[48:], none) // no class name
	le.PutUint32(b[52:], uint32(maxSub))
	le.PutUint32(b[60:], uint32(maxVal))
	le.PutUint32(b[64:], uint32(maxData))
	le.PutUint16(b[72:], uint16(len(name)))
	copy(b[76:], name)
}

// write lays the base block and the bins out and fills every cell.
func (h *hive) write(spec HiveSpec, root *regNode) []byte {
	le := binary.LittleEndian
	h.closeBin()
	out := make([]byte, regBinSize+int(h.end))

	base := out[:regBinSize]
	copy(base, "regf")
	le.PutUint32(base[4:], 1)
	le.PutUint32(base[8:], 1)
	le.PutUint64(base[12:], filetime(spec.Modified))
	le.PutUint32(base[20:], 1)
	le.PutUint32(base[24:], 5)
	le.PutUint32(base[28:], 0) // a primary hive file
	le.PutUint32(base[32:], 1) // direct memory load
	le.PutUint32(base[36:], root.offset)
	le.PutUint32(base[40:], h.end)
	le.PutUint32(base[44:], 1) // clustering factor
	name := utf16.Encode([]rune(spec.FileName))
	if len(name) > 31 {
		name = name[len(name)-31:]
	}
	for i, u := range name {
		le.PutUint16(base[48+2*i:], u)
	}
	sum := uint32(0)
	for i := 0; i < 508; i += 4 {
		sum ^= le.Uint32(base[i:])
	}
	switch sum { // as Windows computes it
	case 0:
		sum = 1
	case 0xFFFFFFFF:
		sum = 0xFFFFFFFE
	}
	le.PutUint32(base[508:], sum)

	data := out[regBinSize:]
	for i, start := range h.bins {
		end := h.end
		if i+1 < len(h.bins) {
			end = h.bins[i+1]
		}
		bin := data[start:end]
		copy(bin, "hbin")
		le.PutUint32(bin[4:], start)
		le.PutUint32(bin[8:], end-start)
		if i == 0 {
			le.PutUint64(bin[20:], filetime(spec.Modified))
		}
	}
	for _, c := range h.cells {
		cell := data[c.off : c.off+c.size]
		if c.free {
			le.PutUint32(cell, c.size) // a free cell has a positive size
			continue
		}
		le.PutUint32(cell, uint32(-int32(c.size)))
		c.fill(cell[4:])
	}
	return out
}

// regLatin1 reports whether a name can be stored a byte per character,
// which Windows does for any name whose characters are all below 0x100.
func regLatin1(s string) bool {
	for _, r := range s {
		if r > 0xFF {
			return false
		}
	}
	return true
}

// regName is a name as a cell stores it: a byte per character when it fits,
// else UTF-16.
func regName(s string) []byte {
	if !regLatin1(s) {
		return utf16le(s)
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = append(b, byte(r))
	}
	return b
}

// regHash is a subkey's hash in a hash leaf: each upper-cased UTF-16 unit,
// times 37 per step.
func regHash(name string) uint32 {
	h := uint32(0)
	for _, u := range regFold(name) {
		h = h*37 + uint32(u)
	}
	return h
}

// regSecurityDescriptor is the self-relative security descriptor every key
// shares: owned by Administrators with SYSTEM as group; full control for
// SYSTEM and Administrators and read for Users, inherited by subkeys.
func regSecurityDescriptor() []byte {
	le := binary.LittleEndian
	system, _ := EncodeSID("S-1-5-18")
	admins, _ := EncodeSID("S-1-5-32-544")
	users, _ := EncodeSID("S-1-5-32-545")
	ace := func(mask uint32, sid []byte) []byte {
		a := []byte{0x00, 0x02} // ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE
		a = le.AppendUint16(a, uint16(8+len(sid)))
		a = le.AppendUint32(a, mask)
		return append(a, sid...)
	}
	aces := slices.Concat(ace(0xF003F, system), ace(0xF003F, admins), ace(0x20019, users))
	acl := []byte{2, 0}
	acl = le.AppendUint16(acl, uint16(8+len(aces)))
	acl = le.AppendUint16(acl, 3)
	acl = le.AppendUint16(acl, 0)
	acl = append(acl, aces...)

	sd := []byte{1, 0}
	sd = le.AppendUint16(sd, 0x8004) // SE_SELF_RELATIVE | SE_DACL_PRESENT
	owner := 20 + len(acl)
	sd = le.AppendUint32(sd, uint32(owner))
	sd = le.AppendUint32(sd, uint32(owner+len(admins)))
	sd = le.AppendUint32(sd, 0)
	sd = le.AppendUint32(sd, 20)
	return slices.Concat(sd, acl, admins, system)
}
