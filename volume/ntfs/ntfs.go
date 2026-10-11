package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/libntfs"
)

// Options are what an NTFS volume is formatted with.
type Options struct {
	ClusterSize int
	Label       string
	// Serial is the volume's 64-bit serial number.
	Serial uint64
	// Hidden is how many sectors of the disk come before the volume.
	Hidden uint32
	// Clock is when the volume is made, and stamps what the file system
	// does at a time the scenario does not give.
	Clock time.Time
	// Alloc is the cluster allocation policy.
	Alloc string
}

// FS is an NTFS volume being written.
type FS struct {
	dev *volume.Device
	g   Geometry
	o   Options
	// zone allocates the clusters of the MFT zone, which only $MFT grows
	// into while the rest of the volume has room, and data the rest.
	zone, data *volume.Allocator
	// recs are every record written, by number; inUse says which are in
	// use, and records is how many $MFT holds.
	recs    map[uint32]*record
	inUse   []bool
	records int64
	// mft is $MFT's record, whose runlist says where every record is.
	mft  *record
	root *node
	// secure is $Secure's record, and sdsEnd where its next descriptor
	// goes; fileSec and dirSec are the IDs of the descriptors a file and a
	// directory the scenario makes point to, 0 until the first is made.
	secure          *record
	sdsEnd          int64
	fileSec, dirSec uint32
	nextSec         uint32
	// reparse is $Extend\$Reparse, whose $R index files every reparse
	// point by its tag and record.
	reparse *node
	res     *volume.Tracker
	now     time.Time
	// gone are the index entries removed from directories, to look for in
	// what their indexes leave behind once the volume is finished.
	gone []goneEntry
}

// node is an object's record and what the driver keeps of it.
type node struct {
	rec *record
	// names are the object's names, in the order they were made.
	names []*name
	si    times
	// attrs are the file attribute flags $STANDARD_INFORMATION holds.
	attrs uint32
	// dir is a directory's index; nil for a file.
	dir *dirIndex
	// tag is a symlink's or junction's reparse tag, 0 for anything else.
	tag uint32
}

// name is one name of an object: the directory it is in, and the
// $FILE_NAME attribute that holds it.
type name struct {
	parent *node
	fn     fileName
	a      *attr
}

// Caps is what an NTFS volume holds: every time to 100 ns, each name's
// $FILE_NAME times, streams, links and slack; names that differ only in
// case are one name.
func Caps(clusterSize int) target.Caps {
	return target.Caps{
		NamedStreams: true, BirthTime: true, ChangeTime: true, FilenameTimes: true,
		Hardlinks: true, Symlinks: true, Junctions: true,
		Slack: target.SlackExact, ClusterSize: clusterSize, ResidentData: true,
		MinTime: MinTime, MaxTime: MaxTime, FoldsCase: true, ValidName: ValidName, Reserved: systemNames,
	}
}

// Granularity is how finely NTFS keeps times: to 100 ns, all four.
func Granularity() target.Granularity {
	const tick = 100 * time.Nanosecond
	return target.Granularity{Atime: tick, Mtime: tick, Ctime: tick, Btime: tick}
}

// Format lays an empty NTFS volume out on dev as mkntfs does.
func Format(dev *volume.Device, o Options, res *volume.Tracker) (*FS, error) {
	g, err := Plan(dev.Size(), o.ClusterSize)
	if err != nil {
		return nil, err
	}
	if err := ValidLabel(o.Label); err != nil {
		return nil, err
	}
	zone, err := volume.NewAllocator(0, int(g.ZoneEnd), o.Alloc)
	if err != nil {
		return nil, err
	}
	data, err := volume.NewAllocator(int(g.ZoneEnd), int(g.Clusters-g.ZoneEnd), o.Alloc)
	if err != nil {
		return nil, err
	}
	f := &FS{dev: dev, g: g, o: o, zone: zone, data: data, recs: map[uint32]*record{}, res: res, records: g.MFTRecords, nextSec: 0x102}
	if err := f.format(); err != nil {
		return nil, err
	}
	return f, nil
}

// mark takes clusters out of use where the format puts them.
func (f *FS) mark(r run) {
	for c := r.lcn; c < r.lcn+r.length; c++ {
		a := f.data
		if c < f.g.ZoneEnd {
			a = f.zone
		}
		a.Mark(volume.Run{Start: int(c), Len: 1})
	}
}

// scatter takes n clusters as mkntfs does for the files it does not place
// itself: the lowest free ones from the end of the MFT zone on, one by
// one, then from halfway into the zone, and so on.
func (f *FS) scatter(n int64) ([]run, error) {
	var runs []run
	from, end := f.g.ZoneEnd, f.g.Clusters
	for n > 0 {
		for c := from; c < end && n > 0; c++ {
			a := f.data
			if c < f.g.ZoneEnd {
				a = f.zone
			}
			if a.Used(int(c)) {
				continue
			}
			a.Mark(volume.Run{Start: int(c), Len: 1})
			if k := len(runs); k > 0 && runs[k-1].lcn+runs[k-1].length == c {
				runs[k-1].length++
			} else {
				runs = append(runs, run{c, 1})
			}
			n--
		}
		if n > 0 {
			if from == 0 {
				return nil, volume.ErrFull
			}
			end, from = from, from/2
		}
	}
	return runs, nil
}

// put writes data over runs from their first cluster, the last cluster
// padded with zeros.
func (f *FS) put(runs []run, data []byte) error {
	cs := int64(f.g.ClusterSize)
	pos := int64(0)
	for _, r := range runs {
		for c := r.lcn; c < r.lcn+r.length; c++ {
			chunk := make([]byte, cs)
			if pos < int64(len(data)) {
				copy(chunk, data[pos:])
			}
			if _, err := f.dev.WriteAt(chunk, f.g.offset(c)); err != nil {
				return err
			}
			pos += cs
		}
	}
	return nil
}

// sysRecord is system record num as mkntfs lays it out, with its
// $STANDARD_INFORMATION: NTFS 1.2's when secID is 0.
func (f *FS) sysRecord(num uint32, seq, flags uint16, attrs, secID uint32) *record {
	r := newRecord(num, seq, nil)
	r.flags = flags
	r.add(&attr{typ: libntfs.AttrTypeStandardInfo, resident: true, value: stdInfo(allAt(f.o.Clock), attrs, secID)})
	f.recs[num] = r
	return r
}

// resident and nonresident make attributes with the given ID.
func resident(typ uint32, name string, id uint16, value []byte) *attr {
	return &attr{typ: typ, name: name, id: id, resident: true, value: value}
}

func nonresident(typ uint32, name string, id uint16, runs []run, alloc, size, init int64) *attr {
	return &attr{typ: typ, name: name, id: id, runs: runs, alloc: alloc, size: size, init: init}
}

// format writes what mkntfs writes: the boot sector and its backup, the
// MFT and its mirror, $LogFile, the files mkntfs places from the end of
// the MFT zone, and the bitmaps.
func (f *FS) format() error {
	g, cs := f.g, int64(f.g.ClusterSize)
	clock := f.o.Clock
	boot := bootSector(g, f.o.Hidden, f.o.Serial)
	bootRuns := []run{{0, g.BootClusters}}
	mftRuns := []run{{g.MFT, g.mftClusters()}}
	mirrRuns := []run{{g.Mirror, g.MirrorClusters}}
	logRuns := []run{{g.Log, g.LogSize / cs}}
	for _, r := range []run{bootRuns[0], {g.MFTBitmap, 1}, mftRuns[0], mirrRuns[0], logRuns[0]} {
		f.mark(r)
	}
	if err := f.put(bootRuns, boot); err != nil {
		return err
	}
	if _, err := f.dev.WriteAt(boot, g.Sectors*sectorSize); err != nil {
		return err
	}
	logBytes := bytes.Repeat([]byte{0xFF}, int(g.LogSize))
	if err := f.put(logRuns, logBytes); err != nil {
		return err
	}
	// mkntfs places these from the end of the MFT zone, in this order.
	sd := rootSD()
	sizes := []int64{int64(len(sd)), libntfs.IndexBlockSize, 2560, g.BitmapBytes, 0x40000 + 0xFC, 2 << 16}
	placed := make([][]run, len(sizes))
	for i, n := range sizes {
		runs, err := f.scatter(ceil(n, cs))
		if err != nil {
			return fmt.Errorf("%d bytes are too small for NTFS's own files", g.Clusters*cs)
		}
		placed[i] = runs
	}
	sdRuns, rootIdx, attrDefRuns, bitmapRuns, sdsRuns, upcaseRuns := placed[0], placed[1], placed[2], placed[3], placed[4], placed[5]
	rootRef := uint64(libntfs.MFTEntryRoot) | libntfs.MFTEntryRoot<<48
	extendRef := uint64(libntfs.MFTEntryExtend) | libntfs.MFTEntryExtend<<48
	named := func(r *record, id uint16, parent uint64, alloc, size int64, flags uint32, n string) fileName {
		fn := fileName{parent: parent, t: allAt(clock), alloc: alloc, size: size, flags: flags, name: n, namespace: libntfs.NamespaceWinDOS}
		r.put(&attr{typ: libntfs.AttrTypeFileName, id: id, resident: true, indexed: true, value: fn.encode()})
		r.links++
		return fn
	}
	roundCluster := func(n int64) int64 { return (n + cs - 1) &^ (cs - 1) }
	var rootEntries []entry
	file := func(r *record, fn fileName) {
		rootEntries = append(rootEntries, fileEntry(r.ref(), fn))
	}

	mftBytes := g.MFTRecords * libntfs.RecordSize
	mft := f.sysRecord(libntfs.MFTEntryMFT, 1, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	mft.put(nonresident(libntfs.AttrTypeData, "", 1, mftRuns, g.mftClusters()*cs, mftBytes, mftBytes))
	file(mft, named(mft, 2, rootRef, ((mftBytes-1)|(cs-1))+1, mftBytes, faSysHidden, "$MFT"))
	bitmapBytes := (ceil(g.MFTRecords, 8) + 7) &^ 7
	mft.put(nonresident(libntfs.AttrTypeBitmap, "", 3, []run{{g.MFTBitmap, 1}}, cs, bitmapBytes, bitmapBytes))
	mft.next = 4
	f.mft = mft

	mirrBytes := g.MirrorClusters * cs
	mirr := f.sysRecord(libntfs.MFTEntryMFTMirr, libntfs.MFTEntryMFTMirr, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	mirr.put(nonresident(libntfs.AttrTypeData, "", 1, mirrRuns, mirrBytes, mirrBytes, mirrBytes))
	file(mirr, named(mirr, 2, rootRef, mirrBytes, mirrBytes, faSysHidden, "$MFTMirr"))
	mirr.next = 3

	logf := f.sysRecord(libntfs.MFTEntryLogFile, libntfs.MFTEntryLogFile, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	logf.put(nonresident(libntfs.AttrTypeData, "", 1, logRuns, g.LogSize, g.LogSize, g.LogSize))
	file(logf, named(logf, 2, rootRef, g.LogSize, g.LogSize, faSysHidden, "$LogFile"))
	logf.next = 3

	vol := f.sysRecord(libntfs.MFTEntryVolume, libntfs.MFTEntryVolume, libntfs.MFTFlagInUse, faSysHidden, 0)
	file(vol, named(vol, 1, rootRef, 0, 0, faSysHidden, "$Volume"))
	vol.put(resident(libntfs.AttrTypeSecurityDesc, "", 2, systemSD(libntfs.MFTEntryVolume)))
	vol.put(resident(libntfs.AttrTypeData, "", 3, nil))
	vol.put(resident(libntfs.AttrTypeVolumeName, "", 4, utf16le(f.o.Label)))
	vol.put(resident(libntfs.AttrTypeVolumeInfo, "", 5, []byte{0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 0}))
	vol.next = 6

	ad := f.sysRecord(libntfs.MFTEntryAttrDef, libntfs.MFTEntryAttrDef, libntfs.MFTFlagInUse, faSysHidden, 0)
	adBytes := attrDefBytes()
	ad.put(nonresident(libntfs.AttrTypeData, "", 1, attrDefRuns, clusters(attrDefRuns)*cs, int64(len(adBytes)), int64(len(adBytes))))
	file(ad, named(ad, 2, rootRef, roundCluster(int64(len(adBytes))), int64(len(adBytes)), faSysHidden, "$AttrDef"))
	ad.put(resident(libntfs.AttrTypeSecurityDesc, "", 3, systemSD(libntfs.MFTEntryAttrDef)))
	ad.next = 4

	root := f.sysRecord(libntfs.MFTEntryRoot, libntfs.MFTEntryRoot, libntfs.MFTFlagInUse|libntfs.MFTFlagDirectory, faSysHidden|libntfs.FileAttrArchive, 0)
	rootFN := named(root, 1, rootRef, 0, 0, faSysHidden|libntfs.FileAttrDupFileNameIndexPresent, ".")
	file(root, rootFN)
	root.put(nonresident(libntfs.AttrTypeSecurityDesc, "", 2, sdRuns, clusters(sdRuns)*cs, int64(len(sd)), int64(len(sd))))
	root.put(resident(libntfs.AttrTypeIndexRoot, "$I30", 3, nil))
	root.put(resident(libntfs.AttrTypeBitmap, "$I30", 4, []byte{1, 0, 0, 0, 0, 0, 0, 0}))
	root.put(nonresident(libntfs.AttrTypeIndexAllocation, "$I30", 5, rootIdx, clusters(rootIdx)*cs, libntfs.IndexBlockSize, libntfs.IndexBlockSize))
	root.next = 6

	bm := f.sysRecord(libntfs.MFTEntryBitmap, libntfs.MFTEntryBitmap, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	bm.put(nonresident(libntfs.AttrTypeData, "", 1, bitmapRuns, clusters(bitmapRuns)*cs, g.BitmapBytes, g.BitmapBytes))
	file(bm, named(bm, 2, rootRef, roundCluster(g.BitmapBytes), g.BitmapBytes, faSysHidden, "$Bitmap"))
	bm.next = 3

	bootRec := f.sysRecord(libntfs.MFTEntryBoot, libntfs.MFTEntryBoot, libntfs.MFTFlagInUse, faSysHidden, 0)
	bootRec.put(nonresident(libntfs.AttrTypeData, "", 1, bootRuns, g.BootClusters*cs, 8192, 8192))
	file(bootRec, named(bootRec, 2, rootRef, roundCluster(8192), 8192, faSysHidden, "$Boot"))
	bootRec.put(resident(libntfs.AttrTypeSecurityDesc, "", 3, systemSD(libntfs.MFTEntryBoot)))
	bootRec.next = 4

	bad := f.sysRecord(libntfs.MFTEntryBadClus, libntfs.MFTEntryBadClus, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	bad.put(nonresident(libntfs.AttrTypeData, "$Bad", 1, []run{{-1, g.Clusters}}, g.Clusters*cs, g.Clusters*cs, 0))
	bad.put(resident(libntfs.AttrTypeData, "", 2, nil))
	file(bad, named(bad, 3, rootRef, 0, 0, faSysHidden, "$BadClus"))
	bad.next = 4

	sec := f.sysRecord(libntfs.MFTEntrySecure, libntfs.MFTEntrySecure, libntfs.MFTFlagInUse|libntfs.MFTFlagViewIndex, faSysHidden|libntfs.FileAttrViewIndex, 0x101)
	file(sec, named(sec, 1, rootRef, 0, 0, faSysHidden|libntfs.FileAttrViewIndex, "$Secure"))
	sds := make([]byte, 0x40000+0xFC)
	var sdh, sii []entry
	for _, s := range secureSDs {
		e := sdsEntry(s.id, f.sdsEnd, s.sd)
		copy(sds[f.sdsEnd:], e)
		sdh, sii = secureEntries(sdh, sii, s.id, f.sdsEnd, s.sd)
		f.sdsEnd += align16(int64(len(e)))
	}
	copy(sds[0x40000:], sds[:0xFC])
	sec.put(nonresident(libntfs.AttrTypeData, "$SDS", 2, sdsRuns, clusters(sdsRuns)*cs, int64(len(sds)), int64(len(sds))))
	sec.put(resident(libntfs.AttrTypeIndexRoot, "$SDH", 3, indexRoot(0, libntfs.CollationSecurityHash, g, entries(sdh, -1), false)))
	sec.put(resident(libntfs.AttrTypeIndexRoot, "$SII", 4, indexRoot(0, libntfs.CollationULong, g, entries(sii, -1), false)))
	sec.next = 5
	f.secure = sec

	up := f.sysRecord(libntfs.MFTEntryUpCase, libntfs.MFTEntryUpCase, libntfs.MFTFlagInUse, faSysHidden, 0x100)
	upBytes := upcase.Bytes()
	up.put(nonresident(libntfs.AttrTypeData, "", 1, upcaseRuns, clusters(upcaseRuns)*cs, int64(len(upBytes)), int64(len(upBytes))))
	info := make([]byte, 32)
	binary.LittleEndian.PutUint32(info[0:], 32)
	binary.LittleEndian.PutUint64(info[8:], crc64(upBytes))
	up.put(resident(libntfs.AttrTypeData, "$Info", 2, info))
	file(up, named(up, 3, rootRef, roundCluster(int64(len(upBytes))), int64(len(upBytes)), faSysHidden, "$UpCase"))
	up.next = 4

	ext := f.sysRecord(libntfs.MFTEntryExtend, libntfs.MFTEntryExtend, libntfs.MFTFlagInUse|libntfs.MFTFlagDirectory, faSysHidden, 0x101)
	file(ext, named(ext, 1, rootRef, 0, 0, faSysHidden|libntfs.FileAttrDupFileNameIndexPresent, "$Extend"))
	ext.next = 3

	for i := uint32(12); i < 16; i++ {
		r := f.sysRecord(i, uint16(i), libntfs.MFTFlagInUse, faSysHidden, 0)
		r.put(resident(libntfs.AttrTypeData, "", 1, nil))
		r.put(resident(libntfs.AttrTypeSecurityDesc, "", 2, systemSD(int(i))))
		r.next = 3
	}
	for i := uint32(16); i < 24; i++ {
		r := f.sysRecord(i, uint16(i), 0, faSysHidden, 0)
		r.unnumbered = true
		r.next = 1
	}
	var extEntries []entry
	view := func(num uint32, n string, coll uint32, ix ...string) *record {
		r := f.sysRecord(num, 1, libntfs.MFTFlagInUse|libntfs.MFTFlagIsExtend|libntfs.MFTFlagViewIndex, faExtendView, 0x101)
		fn := named(r, 1, extendRef, 0, 0, faExtendView, n)
		extEntries = append(extEntries, fileEntry(r.ref(), fn))
		for i, x := range ix {
			r.put(resident(libntfs.AttrTypeIndexRoot, x, uint16(2+i), indexRoot(0, coll, g, entries(nil, -1), false)))
		}
		r.next = uint16(2 + len(ix))
		return r
	}
	quota := view(recQuota, "$Quota", libntfs.CollationULong, "$Q", "$O")
	quota.find(libntfs.AttrTypeIndexRoot, "$Q").value = indexRoot(0, libntfs.CollationULong, g, entries(quotaEntries(clock), -1), false)
	quota.find(libntfs.AttrTypeIndexRoot, "$O").value = indexRoot(0, libntfs.CollationSID, g, entries([]entry{quotaOwner()}, -1), false)
	view(recObjID, "$ObjId", libntfs.CollationULongs, "$O")
	f.reparse = &node{rec: view(recReparse, "$Reparse", libntfs.CollationULongs, "$R"), dir: newIndex("$R", 0, libntfs.CollationULongs, byULongs)}
	slices.SortFunc(extEntries, func(a, b entry) int { return collate(a.name, b.name) })
	ext.put(resident(libntfs.AttrTypeIndexRoot, "$I30", 2, indexRoot(libntfs.AttrTypeFileName, libntfs.CollationFileName, g, entries(extEntries, -1), false)))
	for i := uint32(systemRecords); i < uint32(g.MFTRecords); i++ {
		r := newRecord(i, uint16(i), nil)
		r.unnumbered = true
		f.recs[i] = r
	}

	slices.SortFunc(rootEntries, func(a, b entry) int { return collate(a.name, b.name) })
	rootIndex := newDirIndex()
	rootIndex.root.end = 0
	rootIndex.blocks[0] = &inode{es: rootEntries, end: -1, raw: make([]byte, libntfs.IndexBlockSize), usn: 2}
	rootIndex.bitmap, rootIndex.dirty[0], rootIndex.rootDirty = root.find(libntfs.AttrTypeBitmap, "$I30").value, true, true
	f.root = &node{rec: root, names: []*name{{fn: rootFN, a: root.find(libntfs.AttrTypeFileName, "")}}, si: allAt(clock), attrs: faSysHidden | libntfs.FileAttrArchive, dir: rootIndex}
	for _, fill := range []struct {
		runs []run
		data []byte
	}{{sdRuns, sd}, {attrDefRuns, adBytes}, {sdsRuns, sds}, {upcaseRuns, upBytes}, {bitmapRuns, nil}, {rootIdx, nil}, {mftRuns, nil}, {mirrRuns, nil}, {[]run{{g.MFTBitmap, 1}}, nil}} {
		if err := f.put(fill.runs, fill.data); err != nil {
			return err
		}
	}
	f.inUse = make([]bool, g.MFTRecords)
	for i := range systemRecords {
		f.inUse[i] = i < 16 || i >= 24
	}
	if err := f.writeIndex(f.root); err != nil {
		return err
	}
	for i := range uint32(g.MFTRecords) {
		r := f.recs[i]
		r.usn = 1
		if err := f.writeRecord(r); err != nil {
			return err
		}
	}
	return f.writeBitmaps()
}

func align16(n int64) int64 { return (n + 15) &^ 15 }

// sdsEntry is a security descriptor as $SDS keeps it: its hash, ID, offset
// in $SDS and length, then the descriptor.
func sdsEntry(id uint32, at int64, sd []byte) []byte {
	b := make([]byte, 20+len(sd))
	le := binary.LittleEndian
	le.PutUint32(b[0:], sdHash(sd))
	le.PutUint32(b[4:], id)
	le.PutUint64(b[8:], uint64(at))
	le.PutUint32(b[16:], uint32(len(b)))
	copy(b[20:], sd)
	return b
}

// secureEntries adds the descriptor id at offset at of $SDS to $Secure's
// two indexes: $SDH by hash, $SII by ID.
func secureEntries(sdh, sii []entry, id uint32, at int64, sd []byte) ([]entry, []entry) {
	le := binary.LittleEndian
	hash := sdHash(sd)
	data := make([]byte, 20)
	le.PutUint32(data[0:], hash)
	le.PutUint32(data[4:], id)
	le.PutUint64(data[8:], uint64(at))
	le.PutUint32(data[16:], uint32(20+len(sd)))
	hkey := make([]byte, 8)
	le.PutUint32(hkey[0:], hash)
	le.PutUint32(hkey[4:], id)
	// Windows pads each $SDH entry with "II".
	h := entry{view: true, dataOffset: 0x18, dataLength: 20, body: slices.Concat(hkey, data, []byte{'I', 0, 'I', 0})}
	i := entry{view: true, dataOffset: 0x14, dataLength: 20, body: slices.Concat(hkey[4:], data)}
	sdh = append(sdh, h)
	slices.SortFunc(sdh, func(a, b entry) int { return libntfs.CollateULongs(a.body[:8], b.body[:8]) })
	sii = append(sii, i)
	slices.SortFunc(sii, func(a, b entry) int { return libntfs.CollateULong(a.body[:4], b.body[:4]) })
	return sdh, sii
}

// quotaEntries are $Quota's $Q entries as mkntfs makes them: the defaults,
// owner 1, and the Administrators, owner 0x100, both unlimited.
func quotaEntries(clock time.Time) []entry {
	le := binary.LittleEndian
	control := func(owner uint32, sid []byte) entry {
		b := make([]byte, 4+48+len(sid))
		le.PutUint32(b[0:], owner)
		d := b[4:]
		le.PutUint32(d[0:], 2) // version
		le.PutUint32(d[4:], 1) // default limits
		le.PutUint64(d[16:], libntfs.TimeToFiletime(clock))
		le.PutUint64(d[24:], ^uint64(0))
		le.PutUint64(d[32:], ^uint64(0))
		copy(d[48:], sid)
		return entry{view: true, dataOffset: 0x14, dataLength: uint16(48 + len(sid)), body: b}
	}
	return []entry{control(1, nil), control(0x100, sidAdmins)}
}

// quotaOwner is $Quota's $O entry: the Administrators are owner 0x100.
func quotaOwner() entry {
	b := make([]byte, 16+8)
	copy(b, sidAdmins)
	binary.LittleEndian.PutUint32(b[16:], 0x100)
	binary.LittleEndian.PutUint32(b[20:], 0x20)
	return entry{view: true, dataOffset: 0x20, dataLength: 4, body: b}
}

// Caps is what the volume holds.
func (f *FS) Caps() target.Caps { return Caps(f.g.ClusterSize) }

// Granularity is how finely the volume keeps times.
func (f *FS) Granularity() target.Granularity { return Granularity() }

// Geometry is the volume's layout.
func (f *FS) Geometry() Geometry { return f.g }

// Root is the root directory's record.
func (f *FS) Root() any { return f.root }

// SetNow says when the changes that follow happen; with no time given,
// they happen at the clock.
func (f *FS) SetNow(t time.Time) { f.now = t }

func (f *FS) clock() time.Time {
	if f.now.IsZero() {
		return f.o.Clock
	}
	return f.now
}

func nodeOf(n *volume.Node) *node { return n.Sys.(*node) }

// at is where byte pos of the clusters runs map lies on the volume, and
// how many bytes from there are in the same cluster.
func (f *FS) at(runs []run, pos int64) (int64, int64, error) {
	cs := int64(f.g.ClusterSize)
	vcn := pos / cs
	for _, r := range runs {
		if vcn < r.length {
			if r.lcn < 0 {
				return 0, 0, errors.New("a read or write in a hole")
			}
			return f.g.offset(r.lcn+vcn) + pos%cs, cs - pos%cs, nil
		}
		vcn -= r.length
	}
	return 0, 0, fmt.Errorf("byte %d is past what the runlist maps", pos)
}

// writeRuns writes p at byte pos of the clusters runs map.
func (f *FS) writeRuns(runs []run, pos int64, p []byte) error {
	for len(p) > 0 {
		off, n, err := f.at(runs, pos)
		if err != nil {
			return err
		}
		n = min(n, int64(len(p)))
		if _, err := f.dev.WriteAt(p[:n], off); err != nil {
			return err
		}
		p, pos = p[n:], pos+n
	}
	return nil
}

// readRuns reads n bytes from byte pos of the clusters runs map, and where
// they lie in the image file.
func (f *FS) readRuns(runs []run, pos, n int64) ([]byte, []target.Extent, error) {
	out := make([]byte, 0, n)
	var exts []target.Extent
	for int64(len(out)) < n {
		off, k, err := f.at(runs, pos)
		if err != nil {
			return nil, nil, err
		}
		k = min(k, n-int64(len(out)))
		buf := make([]byte, k)
		if _, err := f.dev.ReadAt(buf, off); err != nil {
			return nil, nil, err
		}
		out = append(out, buf...)
		abs := f.dev.Abs(off)
		if m := len(exts); m > 0 && exts[m-1].Offset+exts[m-1].Length == abs {
			exts[m-1].Length += k
		} else {
			exts = append(exts, target.Extent{Offset: abs, Length: k})
		}
		pos += k
	}
	return out, exts, nil
}

// mirrorRecords is how many records $MFTMirr copies.
func (f *FS) mirrorRecords() uint32 {
	return uint32(f.g.MirrorClusters * int64(f.g.ClusterSize) / libntfs.RecordSize)
}

// writeRecord puts r on disk, and in the mirror too when it is one the
// mirror copies, and returns what it wrote.
func (f *FS) writeRecord(r *record) error {
	_, err := f.putRecord(r)
	return err
}

func (f *FS) putRecord(r *record) ([]byte, error) {
	b, err := r.encode()
	if err != nil {
		return nil, err
	}
	if err := f.writeRuns(f.mft.find(libntfs.AttrTypeData, "").runs, int64(r.num)*libntfs.RecordSize, b); err != nil {
		return nil, err
	}
	if r.num < f.mirrorRecords() {
		if _, err := f.dev.WriteAt(b, f.g.offset(f.g.Mirror)+int64(r.num)*libntfs.RecordSize); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// writeIndex writes what changed of directory d's index: each changed
// index block, over its last image and with the next update sequence
// number, in VCN order; then the record, if the root or the attributes
// that map the blocks changed.
func (f *FS) writeIndex(d *node) error {
	ix := d.dir
	for _, vcn := range slices.Sorted(maps.Keys(ix.dirty)) {
		b := ix.blocks[vcn]
		block, err := indexBlock(b.raw, vcn, b.body(), !b.leaf())
		if err != nil {
			return fmt.Errorf("record %d's index block %d: %w", d.rec.num, vcn, err)
		}
		b.usn = nextUSN(b.usn)
		out := slices.Clone(block)
		if err := libntfs.ProtectFixup(out, b.usn); err != nil {
			return fmt.Errorf("record %d's index block %d: %w", d.rec.num, vcn, err)
		}
		if err := f.writeRuns(d.rec.find(libntfs.AttrTypeIndexAllocation, ix.name).runs, f.blockPos(vcn), out); err != nil {
			return err
		}
	}
	clear(ix.dirty)
	if !ix.rootDirty {
		return nil
	}
	ix.rootDirty = false
	d.rec.find(libntfs.AttrTypeIndexRoot, ix.name).value = ix.rootValue(f.g)
	return f.writeRecord(d.rec)
}

// blockPos is where index block vcn starts in $INDEX_ALLOCATION: VCNs
// count clusters, or 512-byte blocks when a cluster is bigger than an
// index block.
func (f *FS) blockPos(vcn int64) int64 {
	if f.g.ClusterSize > libntfs.IndexBlockSize {
		return vcn * sectorSize
	}
	return vcn * int64(f.g.ClusterSize)
}

// cover grows directory d's $INDEX_ALLOCATION to hold index block vcn,
// with clusters after its last ones if they are free, as libntfs-3g grows
// it when it first writes the block.
func (f *FS) cover(d *node, vcn int64) error {
	ia := d.rec.find(libntfs.AttrTypeIndexAllocation, d.dir.name)
	end := f.blockPos(vcn) + libntfs.IndexBlockSize
	if end <= ia.size {
		return nil
	}
	cs := int64(f.g.ClusterSize)
	if need := ceil(end, cs) - clusters(ia.runs); need > 0 {
		near := -1
		if k := len(ia.runs); k > 0 {
			near = int(ia.runs[k-1].lcn + ia.runs[k-1].length)
		}
		runs, err := f.allocate(need, near)
		if err != nil {
			return err
		}
		ia.runs = extend(ia.runs, runs)
		ia.alloc = clusters(ia.runs) * cs
	}
	ia.size, ia.init = end, end
	return nil
}

// extend appends more to runs, joining runs that meet.
func extend(runs, more []run) []run {
	for _, x := range more {
		if k := len(runs) - 1; k >= 0 && runs[k].lcn+runs[k].length == x.lcn {
			runs[k].length += x.length
		} else {
			runs = append(runs, x)
		}
	}
	return runs
}

// allocate takes n clusters for a file's content or an index, after
// cluster near if it can (near < 0 for where the policy says): outside the
// MFT zone while there is room, as Windows keeps the zone for $MFT.
func (f *FS) allocate(n int64, near int) ([]run, error) {
	if n == 0 {
		return nil, nil
	}
	a := f.data
	if int64(a.Free()) < n {
		a = f.zone
	}
	got, err := a.Alloc(int(n), near)
	if err != nil {
		return nil, err
	}
	out := make([]run, len(got))
	for i, g := range got {
		out[i] = run{int64(g.Start), int64(g.Len)}
	}
	return out, nil
}

// release frees the clusters runs map.
func (f *FS) release(runs []run) {
	for _, c := range lcns(runs) {
		if int64(c) < f.g.ZoneEnd {
			f.zone.Release([]int{c})
		} else {
			f.data.Release([]int{c})
		}
	}
}

// writeBitmaps writes $Bitmap and $MFT's bitmap.
func (f *FS) writeBitmaps() error {
	bm := make([]byte, f.g.BitmapBytes)
	for c := int64(0); c < f.g.BitmapBytes*8; c++ {
		used := c >= f.g.Clusters
		switch {
		case used:
		case c < f.g.ZoneEnd:
			used = f.zone.Used(int(c))
		default:
			used = f.data.Used(int(c))
		}
		if used {
			bm[c/8] |= 1 << (c % 8)
		}
	}
	if err := f.writeRuns(f.recs[libntfs.MFTEntryBitmap].find(libntfs.AttrTypeData, "").runs, 0, bm); err != nil {
		return err
	}
	ba := f.mft.find(libntfs.AttrTypeBitmap, "")
	mb := make([]byte, ba.size)
	for i, u := range f.inUse {
		if u {
			mb[i/8] |= 1 << (i % 8)
		}
	}
	return f.writeRuns(ba.runs, 0, mb)
}

// Flush writes the bitmaps, and records what the index entries taken out
// left behind.
func (f *FS) Flush() error {
	if err := f.writeBitmaps(); err != nil {
		return err
	}
	return f.leftEntries()
}

// Open reads the finished volume back.
func (f *FS) Open() (target.Reader, error) { return Open(f.dev) }

var (
	_ volume.Driver         = (*FS)(nil)
	_ volume.Clocked        = (*FS)(nil)
	_ volume.LinkDriver     = (*FS)(nil)
	_ volume.StreamDriver   = (*FS)(nil)
	_ volume.FileNameDriver = (*FS)(nil)
)
