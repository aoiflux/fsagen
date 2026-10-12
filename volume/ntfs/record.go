package ntfs

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aoiflux/libntfs"
)

// errRecordFull says a record has no room for what was to go in it.
var errRecordFull = errors.New("the MFT record is full")

// attr is one attribute of a record: resident, with its value in the
// record, or not, with its clusters in a runlist.
type attr struct {
	typ  uint32
	name string
	id   uint16
	// indexed marks a resident value an index files the record under, as
	// every $FILE_NAME is.
	indexed  bool
	resident bool
	value    []byte
	// runs map a non-resident attribute's clusters in order; alloc is
	// what they hold, size the attribute's length and init how much of it
	// was ever written.
	runs              []run
	alloc, size, init int64
	// sparse marks a non-resident attribute NTFS keeps sparse, whose header
	// carries the bytes its clusters hold besides what it maps.
	sparse bool
}

func align8(n int) int { return (n + 7) &^ 7 }

// encode is the attribute as a record holds it.
func (a *attr) encode() []byte {
	le := binary.LittleEndian
	name := utf16le(a.name)
	var b []byte
	if a.resident {
		vo := 24 + align8(len(name))
		b = make([]byte, align8(vo+len(a.value)))
		le.PutUint16(b[10:], 24)
		le.PutUint32(b[16:], uint32(len(a.value)))
		le.PutUint16(b[20:], uint16(vo))
		if a.indexed {
			b[22] = 1
		}
		copy(b[24:], name)
		copy(b[vo:], a.value)
	} else {
		mp := runlist(a.runs)
		head := 64
		if a.sparse {
			head = 72
		}
		mo := head + align8(len(name))
		b = make([]byte, align8(mo+len(mp)))
		b[8] = 1
		le.PutUint16(b[10:], uint16(head))
		if a.sparse {
			// The clusters it holds: those its runs map, holes left out.
			var held int64
			if n := clusters(a.runs); n > 0 {
				held = int64(len(lcns(a.runs))) * (a.alloc / n)
			}
			le.PutUint16(b[12:], libntfs.AttrFlagSparse)
			le.PutUint64(b[64:], uint64(held))
		}
		le.PutUint64(b[24:], uint64(clusters(a.runs)-1))
		le.PutUint16(b[32:], uint16(mo))
		le.PutUint64(b[40:], uint64(a.alloc))
		le.PutUint64(b[48:], uint64(a.size))
		le.PutUint64(b[56:], uint64(a.init))
		copy(b[head:], name)
		copy(b[mo:], mp)
	}
	le.PutUint32(b[0:], a.typ)
	le.PutUint32(b[4:], uint32(len(b)))
	b[9] = byte(len(name) / 2)
	le.PutUint16(b[14:], a.id)
	return b
}

// clusters is how many clusters runs map.
func clusters(runs []run) int64 {
	var n int64
	for _, r := range runs {
		n += r.length
	}
	return n
}

// lcns lists the clusters runs map, holes left out.
func lcns(runs []run) []int {
	var out []int
	for _, r := range runs {
		for i := int64(0); r.lcn >= 0 && i < r.length; i++ {
			out = append(out, int(r.lcn+i))
		}
	}
	return out
}

// record is an MFT record.
type record struct {
	num   uint32
	seq   uint16
	links uint16
	flags uint16
	// next is the ID the next new attribute gets, and usn the update
	// sequence number the record was last written with.
	next  uint16
	usn   uint16
	attrs []*attr
	// raw is the record as it was last written, before its update sequence
	// array was applied: what is past its end stays as it was, as Windows
	// leaves it.
	raw []byte
	// unnumbered is set for the records mkntfs lays out without giving them
	// their number.
	unnumbered bool
}

// newRecord is an empty record laid over raw, its last image (nil for a
// record never written).
func newRecord(num uint32, seq uint16, raw []byte) *record {
	if raw == nil {
		raw = make([]byte, libntfs.RecordSize)
	}
	return &record{num: num, seq: seq, raw: raw}
}

// ref is the record's file reference: its number and sequence number.
func (r *record) ref() uint64 { return uint64(r.num) | uint64(r.seq)<<48 }

func refNum(ref uint64) uint32 { return uint32(ref & 0xFFFFFFFFFFFF) }

// order is how a record sorts its attributes: by type, then name.
func order(a, b *attr) int {
	if a.typ != b.typ {
		return cmp.Compare(a.typ, b.typ)
	}
	return collate(a.name, b.name)
}

// add puts a new attribute in its place, with the next ID.
func (r *record) add(a *attr) *attr {
	a.id = r.next
	r.next++
	r.put(a)
	return a
}

// put puts a in its place, keeping its ID: after the attributes that sort
// before it or with it, and for a $FILE_NAME also after those whose values
// sort before its, as libntfs-3g finds the place of an indexed attribute.
func (r *record) put(a *attr) {
	i := 0
	for i < len(r.attrs) && placeAfter(r.attrs[i], a) {
		i++
	}
	r.attrs = slices.Insert(r.attrs, i, a)
}

func placeAfter(x, a *attr) bool {
	switch c := order(x, a); {
	case c != 0:
		return c < 0
	case a.typ == libntfs.AttrTypeFileName:
		return bytes.Compare(x.value, a.value) <= 0
	}
	return true
}

// drop takes a out of the record.
func (r *record) drop(a *attr) {
	r.attrs = slices.DeleteFunc(r.attrs, func(x *attr) bool { return x == a })
}

// find is the first attribute of type typ named name, or nil.
func (r *record) find(typ uint32, name string) *attr {
	for _, a := range r.attrs {
		if a.typ == typ && a.name == name {
			return a
		}
	}
	return nil
}

// used is how many bytes the record takes with its attributes encoded.
func (r *record) used() int {
	n := 0x38 + 8
	for _, a := range r.attrs {
		n += len(a.encode())
	}
	return n
}

// encode lays the record out over its last image and protects it with the
// next update sequence number, which it keeps.
func (r *record) encode() ([]byte, error) {
	le := binary.LittleEndian
	b := r.raw
	off := 0x38
	for _, a := range r.attrs {
		e := a.encode()
		if off+len(e)+8 > libntfs.RecordSize {
			return nil, fmt.Errorf("record %d: %w", r.num, errRecordFull)
		}
		copy(b[off:], e)
		off += len(e)
	}
	le.PutUint32(b[off:], libntfs.AttrTypeEnd)
	le.PutUint32(b[off+4:], 0)
	copy(b, "FILE")
	le.PutUint16(b[4:], 0x30)
	le.PutUint16(b[6:], libntfs.RecordSize/sectorSize+1)
	le.PutUint64(b[8:], 0)
	le.PutUint16(b[16:], r.seq)
	le.PutUint16(b[18:], r.links)
	le.PutUint16(b[20:], 0x38)
	le.PutUint16(b[22:], r.flags)
	le.PutUint32(b[24:], uint32(off+8))
	le.PutUint32(b[28:], libntfs.RecordSize)
	le.PutUint64(b[32:], 0)
	le.PutUint16(b[40:], r.next)
	le.PutUint16(b[42:], 0)
	num := r.num
	if r.unnumbered {
		num = 0
	}
	le.PutUint32(b[44:], num)
	r.usn = nextUSN(r.usn)
	out := slices.Clone(b)
	if err := libntfs.ProtectFixup(out, r.usn); err != nil {
		return nil, fmt.Errorf("record %d: %w", r.num, err)
	}
	return out, nil
}

// nextUSN is the update sequence number to write with after u: never 0 or
// 0xFFFF.
func nextUSN(u uint16) uint16 {
	if u++; u == 0 || u == 0xFFFF {
		return 1
	}
	return u
}

// fits reports whether the record holds its attributes.
func (r *record) fits() bool { return r.used() <= libntfs.RecordSize }

// times are the four times NTFS keeps in $STANDARD_INFORMATION and every
// $FILE_NAME, in its order: created, data changed, record changed, read.
type times struct{ created, modified, changed, accessed time.Time }

func (t times) put(b []byte) {
	le := binary.LittleEndian
	le.PutUint64(b[0:], libntfs.TimeToFiletime(t.created))
	le.PutUint64(b[8:], libntfs.TimeToFiletime(t.modified))
	le.PutUint64(b[16:], libntfs.TimeToFiletime(t.changed))
	le.PutUint64(b[24:], libntfs.TimeToFiletime(t.accessed))
}

func allAt(t time.Time) times { return times{t, t, t, t} }

// stdInfo is a $STANDARD_INFORMATION value: NTFS 1.2's 48 bytes when it
// points at no security descriptor, else 3.0's 72.
func stdInfo(t times, flags, securityID uint32) []byte {
	n := 48
	if securityID != 0 {
		n = 72
	}
	b := make([]byte, n)
	t.put(b)
	binary.LittleEndian.PutUint32(b[32:], flags)
	if n == 72 {
		binary.LittleEndian.PutUint32(b[52:], securityID)
	}
	return b
}

// fileName is a $FILE_NAME value.
type fileName struct {
	parent      uint64
	t           times
	alloc, size int64
	flags       uint32
	// reparse is a reparse point's tag, kept where the flags say there is
	// one.
	reparse   uint32
	name      string
	namespace byte
}

func (f fileName) encode() []byte {
	name := utf16le(f.name)
	b := make([]byte, 66+len(name))
	le := binary.LittleEndian
	le.PutUint64(b[0:], f.parent)
	f.t.put(b[8:])
	le.PutUint64(b[40:], uint64(f.alloc))
	le.PutUint64(b[48:], uint64(f.size))
	le.PutUint32(b[56:], f.flags)
	le.PutUint32(b[60:], f.reparse)
	b[64] = byte(len(name) / 2)
	b[65] = f.namespace
	copy(b[66:], name)
	return b
}

// upcase is the $UpCase table Windows and mkntfs write, which the volume
// carries and collates its names by.
var upcase = libntfs.DefaultUpCase()

// collate orders two names as NTFS indexes them: by their upper case in
// $UpCase, code unit by code unit, then the shorter first.
func collate(a, b string) int { return upcase.Compare(a, b) }
