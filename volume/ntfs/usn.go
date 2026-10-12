package ntfs

import (
	"encoding/binary"
	"slices"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/libntfs"
)

// The change journal, $Extend\$UsnJrnl, as Windows keeps it on every system
// volume: a sparse $J stream of USN_RECORD_V2 records, which never straddle
// a 4 KiB page, and a $Max stream with the journal's limits and its ID.
//
// A file the scenario changes is journaled as a handle on it is: the first
// time each reason appears while it is open, a record with every reason so
// far, and when the operation is over a last record that adds
// USN_REASON_CLOSE. A delete is reported only in that last record. Each
// record is stamped with the time the operation runs, never with a time
// the scenario sets, and the file's $STANDARD_INFORMATION keeps the USN of
// its last record. A directory's index changing on its own is not
// journaled, as Windows journals only the entry's file.
const (
	// recUsnJrnl is $UsnJrnl's record: the first one after mkntfs's own,
	// as Windows takes the lowest free record when the journal is created.
	recUsnJrnl = systemRecords
	// usnPage is the span no record crosses: one that would is put at the
	// start of the next, the rest of the page left zero.
	usnPage = 4096
	// usnMaxSize and usnDelta are the maximum size and allocation delta
	// Windows gives a system volume's journal: 32 MiB and 8 MiB.
	usnMaxSize = 32 << 20
	usnDelta   = 8 << 20
	// usnHeader is a version 2 record's length before its name.
	usnHeader = 60
	// faJournal are $UsnJrnl's file attributes.
	faJournal = faSysHidden | libntfs.FileAttrArchive | libntfs.FileAttrSparseFile
)

// journal is the change journal being written.
type journal struct {
	rec *record
	j   *attr
	// open are the files changed by the operation running, in the order it
	// first changed them; byNode finds each one's change.
	open   []*change
	byNode map[*node]*change
}

// change is what one operation has done to one file so far: the reasons,
// and the reference, name and flags its records carry.
type change struct {
	n            *node
	ref, parent  uint64
	name         string
	attrs, secID uint32
	reasons      uint32
	// gone says the file was deleted: its record is free and keeps no USN.
	gone bool
}

// startJournal creates $Extend\$UsnJrnl, empty, stamped with the clock, as
// enabling the journal on a new volume does.
func (f *FS) startJournal() error {
	if int64(recUsnJrnl) >= f.records {
		if err := f.growMFT(recUsnJrnl + 1); err != nil {
			return err
		}
	}
	for len(f.inUse) <= recUsnJrnl {
		f.inUse = append(f.inUse, false)
	}
	f.inUse[recUsnJrnl] = true
	old := f.recs[recUsnJrnl]
	r := newRecord(recUsnJrnl, old.seq, old.raw)
	r.usn = old.usn
	r.flags, r.links = libntfs.MFTFlagInUse, 1
	f.recs[r.num] = r
	clock := f.o.Clock
	r.add(&attr{typ: libntfs.AttrTypeStandardInfo, resident: true, value: stdInfo(allAt(clock), faJournal, 0x101)})
	fn := fileName{parent: f.recs[libntfs.MFTEntryExtend].ref(), t: allAt(clock), flags: faJournal, name: "$UsnJrnl", namespace: libntfs.NamespaceWinDOS}
	r.add(&attr{typ: libntfs.AttrTypeFileName, resident: true, indexed: true, value: fn.encode()})
	j := r.add(&attr{typ: libntfs.AttrTypeData, name: "$J", sparse: true})
	limits := make([]byte, 32)
	le := binary.LittleEndian
	le.PutUint64(limits[0:], usnMaxSize)
	le.PutUint64(limits[8:], usnDelta)
	le.PutUint64(limits[16:], libntfs.TimeToFiletime(clock)) // the journal's ID
	r.add(&attr{typ: libntfs.AttrTypeData, name: "$Max", resident: true, value: limits})
	if err := f.writeRecord(r); err != nil {
		return err
	}
	f.extEntries = append(f.extEntries, fileEntry(r.ref(), fn))
	slices.SortFunc(f.extEntries, func(a, b entry) int { return collate(a.name, b.name) })
	ext := f.recs[libntfs.MFTEntryExtend]
	ext.find(libntfs.AttrTypeIndexRoot, "$I30").value = indexRoot(libntfs.AttrTypeFileName, libntfs.CollationFileName, f.g, entries(f.extEntries, -1), false)
	if err := f.writeRecord(ext); err != nil {
		return err
	}
	f.jrnl = &journal{rec: r, j: j, byNode: map[*node]*change{}}
	return nil
}

// BeginOp closes what the operation before left open, and journals what
// follows only while operation n is a scenario's (n > 0): the settle pass
// after the last one is fsagen's, not the scenario's.
func (f *FS) BeginOp(n int) {
	f.endOp()
	f.journaling = n > 0
}

// endOp closes every file the operation changed, journaling each one's
// last record, and forgets the times they had before it.
func (f *FS) endOp() {
	clear(f.before)
	j := f.jrnl
	if j == nil || len(j.open) == 0 || f.jerr != nil {
		return
	}
	for _, c := range j.open {
		usn, err := f.usnRecord(c, c.reasons|libntfs.USNReasonClose)
		if err == nil && !c.gone {
			f.putUSN(c.n, usn)
			err = f.writeRecord(c.n.rec)
		}
		if err != nil {
			f.jerr = err
			return
		}
	}
	j.open = j.open[:0]
	clear(j.byNode)
	f.jerr = f.writeRecord(j.rec)
}

// snap keeps n's times as they are before the operation changes them, the
// first time it does.
func (f *FS) snap(n *node) {
	if _, ok := f.before[n]; !ok {
		f.before[n] = n.si
	}
}

// journal notes that the running operation did reason to n, under its name
// nm (nil for the name it was last journaled under, or its first). A
// reason new to the file this operation is journaled at once, unless defer
// is set, as a delete is reported only when the file is closed.
func (f *FS) journal(n *node, nm *name, reason uint32, deferred bool) error {
	j := f.jrnl
	if j == nil || !f.journaling {
		return nil
	}
	c := j.byNode[n]
	if c == nil {
		c = &change{n: n}
		j.byNode[n] = c
		j.open = append(j.open, c)
		if nm == nil {
			nm = n.names[0]
		}
	}
	c.ref, c.attrs, c.secID = n.rec.ref(), n.usnAttrs(), n.secID()
	if nm != nil {
		c.parent, c.name = nm.fn.parent, nm.fn.name
	}
	if reason&^c.reasons == 0 {
		return nil
	}
	c.reasons |= reason
	if deferred {
		c.gone = c.gone || reason&libntfs.USNReasonFileDelete != 0
		return nil
	}
	usn, err := f.usnRecord(c, c.reasons)
	if err != nil {
		return err
	}
	f.putUSN(n, usn)
	return nil
}

// usnAttrs are the file attributes a record gives: $STANDARD_INFORMATION's,
// and the directory flag for a directory.
func (n *node) usnAttrs() uint32 {
	if n.dir != nil {
		return n.attrs | libntfs.FileAttrDirectory
	}
	return n.attrs
}

// secID is the security ID n's $STANDARD_INFORMATION points to.
func (n *node) secID() uint32 {
	si := n.rec.find(libntfs.AttrTypeStandardInfo, "").value
	if len(si) < 72 {
		return 0
	}
	return binary.LittleEndian.Uint32(si[52:])
}

// putUSN puts usn in n's $STANDARD_INFORMATION, which is written with its
// record.
func (f *FS) putUSN(n *node, usn int64) {
	if si := n.rec.find(libntfs.AttrTypeStandardInfo, "").value; len(si) >= 72 {
		binary.LittleEndian.PutUint64(si[64:], uint64(usn))
	}
}

// usnRecord appends a version 2 record of c with reasons to $J, stamped
// with the clock, and returns its USN: where it starts in $J.
func (f *FS) usnRecord(c *change, reasons uint32) (int64, error) {
	name := utf16le(c.name)
	b := make([]byte, align8(usnHeader+len(name)))
	le := binary.LittleEndian
	le.PutUint32(b[0:], uint32(len(b)))
	le.PutUint16(b[4:], 2)
	le.PutUint64(b[8:], c.ref)
	le.PutUint64(b[16:], c.parent)
	le.PutUint64(b[32:], libntfs.TimeToFiletime(f.clock()))
	le.PutUint32(b[40:], reasons)
	le.PutUint32(b[48:], c.secID)
	le.PutUint32(b[52:], c.attrs)
	le.PutUint16(b[56:], uint16(len(name)))
	le.PutUint16(b[58:], usnHeader)
	copy(b[usnHeader:], name)

	j := f.jrnl.j
	usn := j.size
	if usn%usnPage+int64(len(b)) > usnPage {
		usn += usnPage - usn%usnPage
	}
	le.PutUint64(b[24:], uint64(usn))
	end := usn + int64(len(b))
	cs := int64(f.g.ClusterSize)
	if need := ceil(end, cs) - clusters(j.runs); need > 0 {
		near := -1
		if k := len(j.runs); k > 0 {
			near = int(j.runs[k-1].lcn + j.runs[k-1].length)
		}
		runs, err := f.allocate(need, near)
		if err != nil {
			return 0, err
		}
		if err := f.put(runs, nil); err != nil {
			return 0, err
		}
		j.runs = extend(j.runs, runs)
		j.alloc = clusters(j.runs) * cs
	}
	if err := f.writeRuns(j.runs, usn, b); err != nil {
		return 0, err
	}
	j.size, j.init = end, end
	return usn, nil
}

// changedTimes reports whether setting t's non-zero times on n changes one
// to something other than the operation's own time or what n had before
// the operation: a time set the way a program sets one, which Windows
// journals as a basic-info change. The times fsagen stamps to make the
// driver's agree with the scenario's are one or the other.
func (f *FS) changedTimes(n *node, t target.Times) bool {
	was, now := f.before[n], f.clock()
	for _, p := range [][3]time.Time{
		{t.Btime, n.si.created, was.created},
		{t.Mtime, n.si.modified, was.modified},
		{t.Ctime, n.si.changed, was.changed},
		{t.Atime, n.si.accessed, was.accessed},
	} {
		if !p[0].IsZero() && !p[0].Equal(p[1]) && !p[0].Equal(now) && !p[0].Equal(p[2]) {
			return true
		}
	}
	return false
}
