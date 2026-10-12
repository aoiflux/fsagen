package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/internal/reparse"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/libntfs"
)

// newRecordFor takes a free record for a new object: the lowest from
// firstUser up, growing $MFT when it holds none. A record used before
// keeps the sequence number its deletion moved on.
func (f *FS) newRecordFor() (*record, error) {
	n := int64(firstUser)
	for n < int64(len(f.inUse)) && f.inUse[n] {
		n++
	}
	if n >= f.records {
		if err := f.growMFT(n + 1); err != nil {
			return nil, err
		}
	}
	for int64(len(f.inUse)) <= n {
		f.inUse = append(f.inUse, false)
	}
	f.inUse[n] = true
	old := f.recs[uint32(n)]
	r := newRecord(uint32(n), old.seq, old.raw)
	r.usn = old.usn
	f.recs[r.num] = r
	return r, nil
}

// growMFT makes $MFT hold want records: it formats each new one as an
// empty record, and when its clusters are full it takes mftGrowth records'
// worth more, after its last cluster if they are free, as libntfs-3g does.
func (f *FS) growMFT(want int64) error {
	cs := int64(f.g.ClusterSize)
	data := f.mft.find(libntfs.AttrTypeData, "")
	for clusters(data.runs)*cs < want*libntfs.RecordSize {
		last := data.runs[len(data.runs)-1]
		near := int(last.lcn + last.length)
		n := ceil(mftGrowth*libntfs.RecordSize, cs)
		a := f.zone
		if int64(a.Free()) < n {
			a = f.data
		}
		got, err := a.Alloc(int(n), near)
		if err != nil {
			return fmt.Errorf("$MFT cannot grow: %w", err)
		}
		for _, g := range got {
			r := run{int64(g.Start), int64(g.Len)}
			if k := len(data.runs) - 1; data.runs[k].lcn+data.runs[k].length == r.lcn {
				data.runs[k].length += r.length
			} else {
				data.runs = append(data.runs, r)
			}
			if err := f.put([]run{r}, nil); err != nil {
				return err
			}
		}
		data.alloc = clusters(data.runs) * cs
	}
	data.size, data.init = want*libntfs.RecordSize, want*libntfs.RecordSize
	bm := f.mft.find(libntfs.AttrTypeBitmap, "")
	if need := (ceil(want, 8) + 7) &^ 7; need > bm.size {
		if need > bm.alloc {
			return fmt.Errorf("$MFT's bitmap cannot map %d records", want)
		}
		bm.size, bm.init = need, need
	}
	for i := f.records; i < want; i++ {
		r := newRecord(uint32(i), 1, nil)
		f.recs[r.num] = r
		if err := f.writeRecord(r); err != nil {
			return err
		}
	}
	f.records = want
	return f.writeRecord(f.mft)
}

// security is the ID of the descriptor a new directory (dir) or file
// points to. The first of each kind adds its descriptor to $Secure: to
// $SDS, where every entry is written twice, 256 KiB apart, and to $SDH and
// $SII.
func (f *FS) security(dir bool) (uint32, error) {
	id, sd := &f.fileSec, fileSD()
	if dir {
		id, sd = &f.dirSec, dirSD()
	}
	if *id != 0 {
		return *id, nil
	}
	const half = 0x40000
	e := sdsEntry(f.nextSec, f.sdsEnd, sd)
	if f.sdsEnd%half+int64(len(e)) > half {
		return 0, errors.New("$Secure's first 256 KiB of descriptors are full")
	}
	sds := f.secure.find(libntfs.AttrTypeData, "$SDS")
	end := f.sdsEnd + half + int64(len(e))
	if end > sds.alloc {
		return 0, errors.New("$Secure's $SDS has no room for another descriptor")
	}
	for _, at := range []int64{f.sdsEnd, f.sdsEnd + half} {
		if err := f.writeRuns(sds.runs, at, e); err != nil {
			return 0, err
		}
	}
	sds.size, sds.init = max(sds.size, end), max(sds.init, end)
	sdh, sii := f.secure.find(libntfs.AttrTypeIndexRoot, "$SDH"), f.secure.find(libntfs.AttrTypeIndexRoot, "$SII")
	hs, is := viewEntries(sdh.value), viewEntries(sii.value)
	hs, is = secureEntries(hs, is, f.nextSec, f.sdsEnd, sd)
	sdh.value = indexRoot(0, libntfs.CollationSecurityHash, f.g, entries(hs, -1), false)
	sii.value = indexRoot(0, libntfs.CollationULong, f.g, entries(is, -1), false)
	if err := f.writeRecord(f.secure); err != nil {
		return 0, err
	}
	*id = f.nextSec
	f.nextSec++
	f.sdsEnd += align16(int64(len(e)))
	return *id, nil
}

// viewEntries reads back the entries of a view index root f wrote.
func viewEntries(root []byte) []entry {
	le := binary.LittleEndian
	var out []entry
	for p := 16 + int(le.Uint32(root[16:])); p < len(root); {
		e := root[p:]
		n := int(le.Uint16(e[8:]))
		if le.Uint16(e[12:])&libntfs.IndexFlagLast != 0 {
			break
		}
		out = append(out, entry{view: true, dataOffset: le.Uint16(e[0:]), dataLength: le.Uint16(e[2:]), body: slices.Clone(e[16:n])})
		p += n
	}
	return out
}

// junctionDrive is the drive a junction's target is written on. An image
// has no drive letter of its own; C: is the one a system volume has, and
// the junctions Windows makes there (Documents and Settings) point at it.
const junctionDrive = `C:`

// reparseData is the reparse data of the link vn is: a symlink's target as
// given, a junction's as a path on junctionDrive.
func reparseData(vn *volume.Node) ([]byte, error) {
	if vn.Kind != volume.Junction {
		return reparse.Symlink(vn.Target)
	}
	t := path.Clean(vn.Target)
	if t == "." {
		t = ""
	}
	return reparse.Junction(junctionDrive + `\` + strings.ReplaceAll(t, "/", `\`))
}

// namespace is the namespace Windows files a name it creates in: Win32
// and DOS at once for a valid upper-case 8.3 name, else Win32 alone, as
// short names are off.
func namespace(leaf string) byte {
	if isDOSName(leaf) {
		return libntfs.NamespaceWinDOS
	}
	return libntfs.NamespaceWin32
}

// fnFlags are the flags n's $FILE_NAME attributes carry.
func (n *node) fnFlags() uint32 {
	if n.dir != nil {
		return libntfs.FileAttrDupFileNameIndexPresent | n.attrs&libntfs.FileAttrReparsePoint
	}
	return n.attrs
}

// entry is n's name nm as its directory's index files it: with the flags
// and reparse tag NTFS keeps there up to date, as libntfs-3g and Windows
// bring an entry up to date when the record changes.
func (n *node) entry(nm *name) entry {
	fn := nm.fn
	if n.tag != 0 {
		fn.flags |= libntfs.FileAttrReparsePoint
		fn.reparse = n.tag
	}
	return fileEntry(n.rec.ref(), fn)
}

// nameIn is n's name leaf in directory p, or nil.
func (n *node) nameIn(p *node, leaf string) *name {
	for _, nm := range n.names {
		if nm.parent == p && collate(nm.fn.name, leaf) == 0 {
			return nm
		}
	}
	return nil
}

// Create gives the new node n the name in parent: a new record stamped
// with the clock, and an entry in parent's index. A symlink or junction is
// an empty file or directory with a reparse point, filed in $Reparse too.
func (f *FS) Create(parent *volume.Node, leaf string, vn *volume.Node) error {
	p := nodeOf(parent)
	link := vn.Kind == volume.Symlink || vn.Kind == volume.Junction
	dir := vn.Kind == volume.Dir || link && vn.LinkDir
	if !dir && !link && vn.Kind != volume.File {
		return errors.ErrUnsupported
	}
	var data []byte
	if link {
		var err error
		if data, err = reparseData(vn); err != nil {
			return err
		}
	}
	sec, err := f.security(dir)
	if err != nil {
		return err
	}
	r, err := f.newRecordFor()
	if err != nil {
		return err
	}
	now := f.clock()
	n := &node{rec: r, si: allAt(now)}
	r.flags, r.links = libntfs.MFTFlagInUse, 1
	if dir {
		r.flags |= libntfs.MFTFlagDirectory
		n.dir = newDirIndex()
	} else {
		n.attrs = libntfs.FileAttrArchive
		if vn.Mode&0o200 == 0 {
			n.attrs |= libntfs.FileAttrReadOnly
		}
	}
	if link {
		n.tag = binary.LittleEndian.Uint32(data)
		n.attrs |= libntfs.FileAttrReparsePoint
	}
	r.add(&attr{typ: libntfs.AttrTypeStandardInfo, resident: true, value: stdInfo(n.si, n.attrs, sec)})
	if dir {
		r.add(&attr{typ: libntfs.AttrTypeIndexRoot, name: "$I30", resident: true, value: indexRoot(libntfs.AttrTypeFileName, libntfs.CollationFileName, f.g, entries(nil, -1), false)})
	} else {
		r.add(&attr{typ: libntfs.AttrTypeData, resident: true})
	}
	// The reparse point is set once the object is made, as Windows sets it,
	// so the record's $FILE_NAME does not show it; its entry does.
	nm := &name{parent: p, fn: fileName{parent: p.rec.ref(), t: n.si, flags: n.fnFlags() &^ libntfs.FileAttrReparsePoint, name: leaf, namespace: namespace(leaf)}}
	nm.a = r.add(&attr{typ: libntfs.AttrTypeFileName, resident: true, indexed: true, value: nm.fn.encode()})
	n.names = []*name{nm}
	if link {
		r.add(&attr{typ: libntfs.AttrTypeReparsePoint, resident: true, value: data})
	}
	if err := f.writeRecord(r); err != nil {
		return err
	}
	vn.Sys = n
	if err := f.indexAdd(p, n.entry(nm)); err != nil {
		return err
	}
	f.before[n] = times{}
	if err := f.journal(n, nm, libntfs.USNReasonFileCreate, false); err != nil {
		return err
	}
	if link {
		if err := f.indexAdd(f.reparse, reparseEntry(n)); err != nil {
			return err
		}
		if err := f.writeIndex(f.reparse); err != nil {
			return err
		}
		if err := f.journal(n, nm, libntfs.USNReasonReparsePointChange, false); err != nil {
			return err
		}
	}
	return f.touchDir(p)
}

// reparseEntry is n's entry in $Reparse's $R index: its tag and file
// reference as the key, and no data, as libntfs-3g files one.
func reparseEntry(n *node) entry {
	key := make([]byte, 12)
	binary.LittleEndian.PutUint32(key, n.tag)
	binary.LittleEndian.PutUint64(key[4:], n.rec.ref())
	return entry{view: true, dataOffset: 16 + 12, body: key}
}

// Link gives the file n the further name leaf in parent: a $FILE_NAME in
// the POSIX namespace, as NTFS adds a hard link (it gives the name no
// short name where short names are on), with the times n has once the
// link has changed its record.
func (f *FS) Link(parent *volume.Node, leaf string, vn *volume.Node) error {
	p, n := nodeOf(parent), nodeOf(vn)
	f.snap(n)
	n.si.changed = f.clock()
	f.putStdInfo(n)
	first := n.names[0].fn
	nm := &name{parent: p, fn: fileName{parent: p.rec.ref(), t: n.si, alloc: first.alloc, size: first.size, flags: first.flags, reparse: first.reparse, name: leaf, namespace: libntfs.NamespacePOSIX}}
	nm.a = n.rec.add(&attr{typ: libntfs.AttrTypeFileName, resident: true, indexed: true, value: nm.fn.encode()})
	n.names = append(n.names, nm)
	n.rec.links++
	if err := f.fit(n.rec); err != nil {
		return err
	}
	f.setSizes(n)
	if err := f.indexAdd(p, n.entry(nm)); err != nil {
		return err
	}
	if err := f.putFileNames(n); err != nil {
		return err
	}
	if err := f.journal(n, nm, libntfs.USNReasonHardLinkChange, false); err != nil {
		return err
	}
	if err := f.writeRecord(n.rec); err != nil {
		return err
	}
	if err := f.touchDir(p); err != nil {
		return err
	}
	return f.writeParents(n)
}

// touchDir stamps a directory's entries changed now and writes its index
// and record.
func (f *FS) touchDir(d *node) error {
	f.snap(d)
	now := f.clock()
	d.si.modified, d.si.changed = now, now
	f.putStdInfo(d)
	d.dir.rootDirty = true
	return f.writeIndex(d)
}

// putStdInfo puts n's times and flags in its $STANDARD_INFORMATION.
func (f *FS) putStdInfo(n *node) {
	si := n.rec.find(libntfs.AttrTypeStandardInfo, "").value
	n.si.put(si)
	binary.LittleEndian.PutUint32(si[32:], n.attrs)
}

// putFileNames puts each of n's $FILE_NAMEs in its record and in its
// directory's index.
func (f *FS) putFileNames(n *node) error {
	for _, nm := range n.names {
		nm.a.value = nm.fn.encode()
		if err := f.indexUpdate(nm.parent, n.entry(nm)); err != nil {
			return err
		}
	}
	return nil
}

// writeParents writes what changed of the indexes n's names are in.
func (f *FS) writeParents(n *node) error {
	done := map[*node]bool{}
	for _, nm := range n.names {
		if !done[nm.parent] {
			done[nm.parent] = true
			if err := f.writeIndex(nm.parent); err != nil {
				return err
			}
		}
	}
	return nil
}

// setSizes puts the size of n's content, and what it takes, in its
// $FILE_NAMEs.
func (f *FS) setSizes(n *node) {
	var alloc, size int64
	if d := n.rec.find(libntfs.AttrTypeData, ""); d != nil && d.resident {
		alloc, size = int64(align8(len(d.value))), int64(len(d.value))
	} else if d != nil {
		alloc, size = d.alloc, d.size
	}
	for _, nm := range n.names {
		nm.fn.alloc, nm.fn.size = alloc, size
	}
}

// store writes data as the content of a, a $DATA attribute of r: in the
// record while it fits there, which Windows tries only while the content
// has never left it; else in clusters, in place over the ones it has,
// extended or cut to fit, or in newly allocated ones when it was truncated
// first, the old ones freed with their bytes left behind. The last cluster
// is zeroed past the end of the content, as the cache manager writes it.
func (f *FS) store(r *record, a *attr, data []byte, truncated bool) error {
	if a.resident {
		a.value = slices.Clone(data)
		if r.fits() {
			return nil
		}
		a.resident, a.value = false, nil
	} else if truncated {
		if err := f.cut(a, 0, target.ResidueOverwrite); err != nil {
			return err
		}
	}
	if err := f.place(a, data); err != nil {
		return err
	}
	return f.fit(r)
}

// place writes data over the clusters of a, a non-resident attribute,
// taking more or freeing some to fit it.
func (f *FS) place(a *attr, data []byte) error {
	cs := int64(f.g.ClusterSize)
	size := int64(len(data))
	need := ceil(size, cs)
	switch have := clusters(a.runs); {
	case need < have:
		if err := f.cut(a, need, target.ResidueOverwrite); err != nil {
			return err
		}
	case need > have:
		near := -1
		if k := len(a.runs); k > 0 {
			near = int(a.runs[k-1].lcn + a.runs[k-1].length)
		}
		runs, err := f.allocate(need-have, near)
		if err != nil {
			return err
		}
		a.runs = extend(a.runs, runs)
	}
	padded := make([]byte, need*cs)
	copy(padded, data)
	if err := f.writeRuns(a.runs, 0, padded); err != nil {
		return err
	}
	a.alloc, a.size, a.init = need*cs, size, size
	return nil
}

// fit moves r's largest resident content to clusters, as often as it
// takes for r to hold its attributes.
func (f *FS) fit(r *record) error {
	for !r.fits() {
		var big *attr
		for _, a := range r.attrs {
			if a.typ == libntfs.AttrTypeData && a.resident && len(a.value) > 0 && (big == nil || len(a.value) > len(big.value)) {
				big = a
			}
		}
		if big == nil {
			return fmt.Errorf("record %d: %w", r.num, errRecordFull)
		}
		data := big.value
		big.resident, big.value = false, nil
		if err := f.place(big, data); err != nil {
			return err
		}
	}
	return nil
}

// Commit writes n's content (see store), and the sizes in its names.
func (f *FS) Commit(vn *volume.Node, truncated bool) error {
	n := nodeOf(vn)
	a := n.rec.find(libntfs.AttrTypeData, "")
	old, err := f.journaled(a)
	if err != nil {
		return err
	}
	if err := f.store(n.rec, a, vn.Data, truncated); err != nil {
		return err
	}
	if err := f.changed(n); err != nil {
		return err
	}
	return f.journalData(n, old, vn.Data, truncated, false)
}

// journaled is a $DATA attribute's content as it is before a write, when
// the change journal is to say what the write did to it.
func (f *FS) journaled(a *attr) ([]byte, error) {
	switch {
	case f.jrnl == nil || !f.journaling || a == nil:
		return nil, nil
	case a.resident:
		return a.value, nil
	}
	data, _, err := f.readRuns(a.runs, 0, a.size)
	return data, err
}

// journalData journals what writing data over old did to n's content, or
// to a named stream (named): cut to nothing first (truncated), shortened,
// changed where it was, or made longer, each reason in that order, as a
// program truncating and then writing is journaled.
func (f *FS) journalData(n *node, old, data []byte, truncated, named bool) error {
	over, ext, cut := uint32(libntfs.USNReasonDataOverwrite), uint32(libntfs.USNReasonDataExtend), uint32(libntfs.USNReasonDataTruncation)
	if named {
		over, ext, cut = libntfs.USNReasonNamedDataOverwrite, libntfs.USNReasonNamedDataExtend, libntfs.USNReasonNamedDataTruncation
	}
	base := old
	var reasons []uint32
	if truncated {
		if len(old) > 0 {
			reasons = append(reasons, cut)
		}
		base = nil
	}
	k := min(len(data), len(base))
	switch {
	case len(data) < len(base):
		reasons = append(reasons, cut)
	case !bytes.Equal(data[:k], base[:k]):
		reasons = append(reasons, over)
	}
	if len(data) > len(base) {
		reasons = append(reasons, ext)
	}
	for _, r := range reasons {
		if err := f.journal(n, nil, r, false); err != nil {
			return err
		}
	}
	return nil
}

// changed stamps n's content changed now and writes its record and its
// names, whose sizes follow the content.
func (f *FS) changed(n *node) error {
	f.snap(n)
	f.setSizes(n)
	now := f.clock()
	n.si.modified, n.si.changed = now, now
	f.putStdInfo(n)
	if err := f.putFileNames(n); err != nil {
		return err
	}
	if err := f.writeRecord(n.rec); err != nil {
		return err
	}
	return f.writeParents(n)
}

// WriteStream writes a named stream of n as a named $DATA attribute,
// stored as content is (see store), replacing what it held as opening it
// to be overwritten does.
func (f *FS) WriteStream(vn *volume.Node, stream string) error {
	n := nodeOf(vn)
	a := n.rec.find(libntfs.AttrTypeData, stream)
	created := a == nil
	old, err := f.journaled(a)
	if err != nil {
		return err
	}
	if created {
		a = n.rec.add(&attr{typ: libntfs.AttrTypeData, name: stream, resident: true})
	}
	if err := f.store(n.rec, a, vn.Streams[stream], true); err != nil {
		return err
	}
	if err := f.changed(n); err != nil {
		return err
	}
	if created {
		if err := f.journal(n, nil, libntfs.USNReasonStreamChange, false); err != nil {
			return err
		}
	}
	return f.journalData(n, old, vn.Streams[stream], true, true)
}

// cut frees d's clusters from the keep-th on, recording what they held, up
// to its size, as residue of cause.
func (f *FS) cut(d *attr, keep int64, cause string) error {
	cs := int64(f.g.ClusterSize)
	if keep >= clusters(d.runs) {
		return nil
	}
	if start := keep * cs; start < d.size {
		data, exts, err := f.readRuns(d.runs, start, d.size-start)
		if err != nil {
			return err
		}
		f.res.Add(cause, nil, nil, exts, data)
	}
	var kept, freed []run
	left := keep
	for _, r := range d.runs {
		switch {
		case left >= r.length:
			kept = append(kept, r)
			left -= r.length
		case left > 0:
			kept = append(kept, run{r.lcn, left})
			freed = append(freed, run{r.lcn + left, r.length - left})
			left = 0
		default:
			freed = append(freed, r)
		}
	}
	f.release(freed)
	d.runs = kept
	d.alloc = keep * cs
	d.size, d.init = min(d.size, keep*cs), min(d.init, keep*cs)
	return nil
}

// Remove takes name out of parent. The object keeps its record while it
// has another name; the name's $FILE_NAME goes, and the record's link
// count. Its last name gone, it is deleted as Windows deletes it: its
// record loses its in-use flag and its sequence number goes up, but keeps
// everything else; its clusters, its streams' too, are freed with their
// bytes in place; a link leaves $Reparse.
func (f *FS) Remove(parent *volume.Node, leaf string, vn *volume.Node) error {
	p, n := nodeOf(parent), nodeOf(vn)
	nm := n.nameIn(p, leaf)
	if nm == nil {
		return fmt.Errorf("record %d has no name %q in record %d", n.rec.num, leaf, p.rec.num)
	}
	f.snap(n)
	f.forget(p, n, nm, target.ResidueDelete)
	if err := f.indexRemove(p, n.entry(nm)); err != nil {
		return err
	}
	if err := f.touchDir(p); err != nil {
		return err
	}
	r := n.rec
	if vn.Names > 0 {
		if err := f.journal(n, nm, libntfs.USNReasonHardLinkChange, false); err != nil {
			return err
		}
		r.drop(nm.a)
		n.names = slices.DeleteFunc(n.names, func(x *name) bool { return x == nm })
		r.links--
		n.si.changed = f.clock()
		f.putStdInfo(n)
		return f.writeRecord(r)
	}
	// The file is still its own until it is closed, which journals the
	// delete under the reference it had.
	if err := f.journal(n, nm, libntfs.USNReasonFileDelete, true); err != nil {
		return err
	}
	if n.tag != 0 {
		if err := f.indexRemove(f.reparse, reparseEntry(n)); err != nil {
			return err
		}
		if err := f.writeIndex(f.reparse); err != nil {
			return err
		}
	}
	// The content goes with the record; each stream's is left on its own.
	type freed struct {
		data []byte
		exts []target.Extent
	}
	var content freed
	var streams []freed
	for _, a := range r.attrs {
		if a.typ != libntfs.AttrTypeData || a.resident || a.size == 0 {
			continue
		}
		data, exts, err := f.readRuns(a.runs, 0, a.size)
		if err != nil {
			return err
		}
		if a.name == "" {
			content = freed{data, exts}
		} else {
			streams = append(streams, freed{data, exts})
		}
	}
	for _, a := range r.attrs {
		if !a.resident {
			f.release(a.runs)
		}
	}
	r.flags &^= libntfs.MFTFlagInUse
	r.seq++
	if r.seq == 0 {
		r.seq = 1
	}
	f.inUse[r.num] = false
	raw, err := f.putRecord(r)
	if err != nil {
		return err
	}
	off, _, err := f.at(f.mft.find(libntfs.AttrTypeData, "").runs, int64(r.num)*libntfs.RecordSize)
	if err != nil {
		return err
	}
	entry := &target.ResidueEntry{Type: "ntfs_mft_record", Number: int64(r.num), Seq: int(r.seq), Offset: f.dev.Abs(off), Length: libntfs.RecordSize}
	f.res.Add(target.ResidueDelete, entry, raw, content.exts, content.data)
	for _, s := range streams {
		f.res.Add(target.ResidueDelete, nil, nil, s.exts, s.data)
	}
	return nil
}

// Rename moves n's name oldName in from to newName in to: out of its old
// directory's index and into its new one's, with a $FILE_NAME in the Win32
// namespace that takes the times n has once the rename has changed its
// record, as NTFS writes it.
func (f *FS) Rename(from *volume.Node, oldName string, to *volume.Node, newName string, vn *volume.Node) error {
	src, dst, n := nodeOf(from), nodeOf(to), nodeOf(vn)
	nm := n.nameIn(src, oldName)
	if nm == nil {
		return fmt.Errorf("record %d has no name %q in record %d", n.rec.num, oldName, src.rec.num)
	}
	f.snap(n)
	if err := f.journal(n, nm, libntfs.USNReasonRenameOldName, false); err != nil {
		return err
	}
	f.forget(src, n, nm, target.ResidueRename)
	if err := f.indexRemove(src, n.entry(nm)); err != nil {
		return err
	}
	n.si.changed = f.clock()
	f.putStdInfo(n)
	nm.parent = dst
	nm.fn.parent, nm.fn.name, nm.fn.t, nm.fn.namespace = dst.rec.ref(), newName, n.si, namespace(newName)
	nm.fn.flags, nm.fn.reparse = n.fnFlags(), n.tag
	n.rec.drop(nm.a)
	nm.a.value = nm.fn.encode()
	n.rec.put(nm.a)
	if err := f.journal(n, nm, libntfs.USNReasonRenameNewName, false); err != nil {
		return err
	}
	if err := f.writeRecord(n.rec); err != nil {
		return err
	}
	if err := f.indexAdd(dst, n.entry(nm)); err != nil {
		return err
	}
	if err := f.touchDir(src); err != nil {
		return err
	}
	if src != dst {
		return f.touchDir(dst)
	}
	return nil
}

// SetTimes stores t's non-zero times in n's $STANDARD_INFORMATION; setting
// one the way a program does is a basic-info change to the journal.
func (f *FS) SetTimes(vn *volume.Node, t target.Times) error {
	n := nodeOf(vn)
	f.snap(n)
	basic := f.changedTimes(n, t)
	n.si = setTimes(n.si, t)
	f.putStdInfo(n)
	if basic {
		if err := f.journal(n, nil, libntfs.USNReasonBasicInfoChange, false); err != nil {
			return err
		}
	}
	return f.writeRecord(n.rec)
}

// setTimes is to with t's non-zero times in place of its own.
func setTimes(to times, t target.Times) times {
	for _, s := range []struct {
		to   *time.Time
		from time.Time
	}{{&to.accessed, t.Atime}, {&to.modified, t.Mtime}, {&to.changed, t.Ctime}, {&to.created, t.Btime}} {
		if !s.from.IsZero() {
			*s.to = s.from.UTC()
		}
	}
	return to
}

// SetFileNameTimes stores t's non-zero times in the $FILE_NAME of n's name
// leaf in parent, in its record and its directory's index alike, as a tool
// that sets them writes both. Times it already has write nothing.
func (f *FS) SetFileNameTimes(parent *volume.Node, leaf string, vn *volume.Node, t target.Times) error {
	p, n := nodeOf(parent), nodeOf(vn)
	nm := n.nameIn(p, leaf)
	if nm == nil {
		return fmt.Errorf("record %d has no name %q in record %d", n.rec.num, leaf, p.rec.num)
	}
	was := nm.fn.t
	if nm.fn.t = setTimes(was, t); nm.fn.t == was {
		return nil
	}
	nm.a.value = nm.fn.encode()
	if err := f.indexUpdate(p, n.entry(nm)); err != nil {
		return err
	}
	if err := f.writeRecord(n.rec); err != nil {
		return err
	}
	return f.writeIndex(p)
}

// Chmod sets or clears a file's read-only attribute, as Windows maps a
// mode without the owner's write bit.
func (f *FS) Chmod(vn *volume.Node) error {
	n := nodeOf(vn)
	if n.dir != nil || n.tag != 0 {
		return nil
	}
	f.snap(n)
	was := n.attrs
	if vn.Mode&0o200 == 0 {
		n.attrs |= libntfs.FileAttrReadOnly
	} else {
		n.attrs &^= libntfs.FileAttrReadOnly
	}
	n.si.changed = f.clock()
	f.putStdInfo(n)
	if n.attrs != was {
		if err := f.journal(n, nil, libntfs.USNReasonBasicInfoChange, false); err != nil {
			return err
		}
	}
	return f.writeRecord(n.rec)
}

// WriteSlack writes data just past byte at of n's content, in the rest of
// its last cluster.
func (f *FS) WriteSlack(vn *volume.Node, at int64, data []byte) error {
	d := nodeOf(vn).rec.find(libntfs.AttrTypeData, "")
	switch {
	case d.resident:
		return errors.New("the content is kept in the MFT record, with no cluster and so no slack")
	case at != d.size || at+int64(len(data)) > d.alloc:
		return fmt.Errorf("%d bytes from byte %d do not fit the slack of %d bytes in %d", len(data), at, d.size, d.alloc)
	}
	return f.writeRuns(d.runs, at, data)
}

// mode is how a node reads back: a directory open to all, a file read-only
// or not.
func mode(dir bool, attrs uint32) fs.FileMode {
	switch {
	case dir:
		return fs.ModeDir | 0o777
	case attrs&libntfs.FileAttrReadOnly != 0:
		return 0o444
	}
	return 0o666
}
