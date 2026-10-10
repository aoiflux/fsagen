package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
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
	data := f.mft.find(atData, "")
	for clusters(data.runs)*cs < want*recordSize {
		last := data.runs[len(data.runs)-1]
		near := int(last.lcn + last.length)
		n := ceil(mftGrowth*recordSize, cs)
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
	data.size, data.init = want*recordSize, want*recordSize
	bm := f.mft.find(atBitmap, "")
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
	sds := f.secure.find(atData, "$SDS")
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
	sdh, sii := f.secure.find(atIndexRoot, "$SDH"), f.secure.find(atIndexRoot, "$SII")
	hs, is := viewEntries(sdh.value), viewEntries(sii.value)
	hs, is = secureEntries(hs, is, f.nextSec, f.sdsEnd, sd)
	sdh.value = indexRoot(0, collSecHash, f.g, entries(hs, -1), false)
	sii.value = indexRoot(0, collULong, f.g, entries(is, -1), false)
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
		if le.Uint16(e[12:])&ieEnd != 0 {
			break
		}
		out = append(out, entry{view: true, dataOffset: le.Uint16(e[0:]), dataLength: le.Uint16(e[2:]), body: slices.Clone(e[16:n])})
		p += n
	}
	return out
}

// Create gives the new node n the name in parent: a new record stamped
// with the clock, and an entry in parent's index.
func (f *FS) Create(parent *volume.Node, name string, vn *volume.Node) error {
	p := nodeOf(parent)
	dir := vn.Kind == volume.Dir
	if !dir && vn.Kind != volume.File {
		return errors.ErrUnsupported
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
	n := &node{rec: r, parent: p, si: allAt(now)}
	r.flags, r.links = recInUse, 1
	ns := byte(nsWin32)
	if isDOSName(name) {
		ns = nsWin32DOS
	}
	n.fn = fileName{parent: p.rec.ref(), t: n.si, name: name, namespace: ns}
	if dir {
		r.flags |= recDir
		n.fn.flags = faI30Index
		n.dir = &dirIndex{}
	} else {
		n.attrs = faArchive
		if vn.Mode&0o200 == 0 {
			n.attrs |= faReadOnly
		}
		n.fn.flags = n.attrs
	}
	r.add(&attr{typ: atStdInfo, resident: true, value: stdInfo(n.si, n.attrs, sec)})
	if dir {
		r.add(&attr{typ: atIndexRoot, name: "$I30", resident: true, value: indexRoot(atFileName, collFileName, f.g, entries(nil, -1), false)})
	} else {
		r.add(&attr{typ: atData, resident: true})
	}
	r.add(&attr{typ: atFileName, resident: true, indexed: true, value: n.fn.encode()})
	if err := f.writeRecord(r); err != nil {
		return err
	}
	vn.Sys = n
	p.dir.insert(fileEntry(r.ref(), n.fn))
	return f.touchDir(p)
}

// touchDir stamps a directory's entries changed now and writes its index
// and record.
func (f *FS) touchDir(d *node) error {
	now := f.clock()
	d.si.modified, d.si.changed = now, now
	f.putStdInfo(d)
	return f.writeIndex(d)
}

// putStdInfo puts n's times and flags in its $STANDARD_INFORMATION.
func (f *FS) putStdInfo(n *node) {
	si := n.rec.find(atStdInfo, "").value
	n.si.put(si)
	binary.LittleEndian.PutUint32(si[32:], n.attrs)
}

// putFileName puts n's $FILE_NAME in its record and in its parent's index.
func (f *FS) putFileName(n *node) {
	n.rec.find(atFileName, "").value = n.fn.encode()
	for i, e := range n.parent.dir.entries {
		if e.name == n.fn.name {
			n.parent.dir.entries[i] = fileEntry(n.rec.ref(), n.fn)
		}
	}
}

// Commit writes n's content: in the record while it fits there, which
// Windows tries only while the content has never left it; else in
// clusters, in place over the ones it has, extended or cut to fit, or in
// newly allocated ones when it was truncated first, the old ones freed
// with their bytes left behind. The last cluster is zeroed past the end of
// the content, as the cache manager writes it.
func (f *FS) Commit(vn *volume.Node, truncated bool) error {
	n := nodeOf(vn)
	r := n.rec
	d := r.find(atData, "")
	size := int64(len(vn.Data))
	cs := int64(f.g.ClusterSize)
	if d.resident {
		d.value = slices.Clone(vn.Data)
		if !r.fits() {
			d.resident, d.value = false, nil
		}
	} else if truncated {
		if err := f.cut(d, 0, target.ResidueOverwrite); err != nil {
			return err
		}
	}
	if !d.resident {
		need := ceil(size, cs)
		switch have := clusters(d.runs); {
		case need < have:
			if err := f.cut(d, need, target.ResidueOverwrite); err != nil {
				return err
			}
		case need > have:
			near := -1
			if k := len(d.runs); k > 0 {
				near = int(d.runs[k-1].lcn + d.runs[k-1].length)
			}
			runs, err := f.allocate(need-have, near)
			if err != nil {
				return err
			}
			for _, x := range runs {
				if k := len(d.runs) - 1; k >= 0 && d.runs[k].lcn+d.runs[k].length == x.lcn {
					d.runs[k].length += x.length
				} else {
					d.runs = append(d.runs, x)
				}
			}
		}
		padded := make([]byte, need*cs)
		copy(padded, vn.Data)
		if err := f.writeRuns(d.runs, 0, padded); err != nil {
			return err
		}
		d.alloc, d.size, d.init = need*cs, size, size
		n.fn.alloc = d.alloc
	} else {
		n.fn.alloc = int64(align8(int(size)))
	}
	n.fn.size = size
	now := f.clock()
	n.si.modified, n.si.changed = now, now
	f.putStdInfo(n)
	f.putFileName(n)
	if err := f.writeRecord(r); err != nil {
		return err
	}
	return f.writeIndex(n.parent)
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

// Remove takes name out of parent, and deletes the object as Windows does:
// its record loses its in-use flag and its sequence number goes up, but
// keeps everything else; its clusters are freed with their bytes in place.
func (f *FS) Remove(parent *volume.Node, name string, vn *volume.Node) error {
	p, n := nodeOf(parent), nodeOf(vn)
	if !p.dir.remove(n.fn.name) {
		return fmt.Errorf("record %d has no entry %q", p.rec.num, name)
	}
	if err := f.touchDir(p); err != nil {
		return err
	}
	r := n.rec
	var data []byte
	var exts []target.Extent
	if d := r.find(atData, ""); d != nil && !d.resident && d.size > 0 {
		var err error
		if data, exts, err = f.readRuns(d.runs, 0, d.size); err != nil {
			return err
		}
	}
	for _, a := range r.attrs {
		if !a.resident {
			f.release(a.runs)
		}
	}
	r.flags &^= recInUse
	r.seq++
	if r.seq == 0 {
		r.seq = 1
	}
	f.inUse[r.num] = false
	raw, err := f.putRecord(r)
	if err != nil {
		return err
	}
	off, _, err := f.at(f.mft.find(atData, "").runs, int64(r.num)*recordSize)
	if err != nil {
		return err
	}
	entry := &target.ResidueEntry{Type: "ntfs_mft_record", Number: int64(r.num), Seq: int(r.seq), Offset: f.dev.Abs(off), Length: recordSize}
	f.res.Add(target.ResidueDelete, entry, raw, exts, data)
	return nil
}

// Rename moves n to its new name: out of its old directory's index and
// into its new one's, with a $FILE_NAME that takes the times n has once
// the rename has changed its record, as NTFS writes it.
func (f *FS) Rename(from *volume.Node, oldName string, to *volume.Node, newName string, vn *volume.Node) error {
	src, dst, n := nodeOf(from), nodeOf(to), nodeOf(vn)
	if !src.dir.remove(n.fn.name) {
		return fmt.Errorf("record %d has no entry %q", src.rec.num, oldName)
	}
	n.si.changed = f.clock()
	f.putStdInfo(n)
	n.parent = dst
	n.fn.parent, n.fn.name, n.fn.t = dst.rec.ref(), newName, n.si
	n.fn.namespace = nsWin32
	if isDOSName(newName) {
		n.fn.namespace = nsWin32DOS
	}
	n.rec.find(atFileName, "").value = n.fn.encode()
	if err := f.writeRecord(n.rec); err != nil {
		return err
	}
	dst.dir.insert(fileEntry(n.rec.ref(), n.fn))
	if err := f.touchDir(src); err != nil {
		return err
	}
	if src != dst {
		return f.touchDir(dst)
	}
	return nil
}

// SetTimes stores t's non-zero times in n's $STANDARD_INFORMATION.
func (f *FS) SetTimes(vn *volume.Node, t target.Times) error {
	n := nodeOf(vn)
	for _, s := range []struct {
		to   *time.Time
		from time.Time
	}{{&n.si.accessed, t.Atime}, {&n.si.modified, t.Mtime}, {&n.si.changed, t.Ctime}, {&n.si.created, t.Btime}} {
		if !s.from.IsZero() {
			*s.to = s.from.UTC()
		}
	}
	f.putStdInfo(n)
	return f.writeRecord(n.rec)
}

// Chmod sets or clears a file's read-only attribute, as Windows maps a
// mode without the owner's write bit.
func (f *FS) Chmod(vn *volume.Node) error {
	n := nodeOf(vn)
	if n.dir != nil {
		return nil
	}
	if vn.Mode&0o200 == 0 {
		n.attrs |= faReadOnly
	} else {
		n.attrs &^= faReadOnly
	}
	n.si.changed = f.clock()
	f.putStdInfo(n)
	return f.writeRecord(n.rec)
}

// WriteSlack is refused: this writer keeps no slack yet.
func (f *FS) WriteSlack(vn *volume.Node, at int64, data []byte) error {
	return errors.ErrUnsupported
}

// mode is how a node reads back: a directory open to all, a file read-only
// or not.
func mode(dir bool, attrs uint32) fs.FileMode {
	switch {
	case dir:
		return fs.ModeDir | 0o777
	case attrs&faReadOnly != 0:
		return 0o444
	}
	return 0o666
}
