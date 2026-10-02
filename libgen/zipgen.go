package libgen

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"strings"
	"time"
)

// fsagen writes zip archives itself rather than through archive/zip, for two
// reasons. archive/zip always emits a data descriptor after each member and
// leaves the sizes out of the local header, which no ordinary tool produces
// and which makes an archive's length depend on the library; and a corpus
// needs its member order, timestamps and total length to be exactly what the
// scenario asked for. Stored members are therefore byte-identical on every Go
// release. Deflated members are not: their bytes come from compress/flate and
// are only pinned by the toolchain in go.mod.

const (
	zipLocalSig    = 0x04034b50
	zipCentralSig  = 0x02014b50
	zipEOCDSig     = 0x06054b50
	zipLocalLen    = 30
	zipCentralLen  = 46
	zipEOCDLen     = 22
	zipVersion     = 20     // 2.0: store and deflate, no zip64
	zipUTF8Flag    = 0x0800 // the name is UTF-8, not CP437
	zipAttrArchive = 0x20   // MS-DOS FILE_ATTRIBUTE_ARCHIVE
	zipAttrDir     = 0x10   // MS-DOS FILE_ATTRIBUTE_DIRECTORY
	// MaxZipComment is the longest archive comment the format can record: the
	// end-of-central-directory field that holds its length is 16-bit.
	MaxZipComment = 0xffff
	zipMax        = 1 << 32 // without zip64 every offset and size is 32-bit
)

// ZipEntry is one member of an archive.
type ZipEntry struct {
	// Name is the stored name, slash-separated and relative. A directory
	// entry's name ends in "/" and carries no data.
	Name     string
	Data     []byte
	Modified time.Time
	// Deflate compresses the member. Its bytes are only reproducible for one
	// Go toolchain, so store is the default everywhere in fsagen.
	Deflate bool
}

// BuildZip writes the entries in the order given, with a central directory in
// the same order and an optional archive comment.
func BuildZip(entries []ZipEntry, comment string) ([]byte, error) {
	if len(comment) > MaxZipComment {
		return nil, fmt.Errorf("zip comment is %d bytes; the format allows %d", len(comment), MaxZipComment)
	}
	if len(entries) > MaxZipEntries {
		return nil, fmt.Errorf("zip has %d members; without zip64 the format records at most %d", len(entries), MaxZipEntries)
	}
	seen := make(map[string]bool, len(entries))
	var body, central bytes.Buffer
	for _, e := range entries {
		m, err := zipMemberOf(e, body.Len(), seen)
		if err != nil {
			return nil, err
		}
		m.writeLocal(&body)
		m.writeCentral(&central)
	}

	var out bytes.Buffer
	out.Write(body.Bytes())
	out.Write(central.Bytes())
	writeEOCD(&out, len(entries), central.Len(), body.Len(), comment)
	return out.Bytes(), nil
}

// zipMember is one entry as the archive records it. Every field is written
// twice, in the local header before the data and again in the central
// directory, and a reader that finds the two disagreeing calls the archive
// corrupt — so they are worked out once, here, rather than at each of the two
// places they are emitted.
type zipMember struct {
	name        string
	stored      []byte // the bytes that go into the archive
	size        int    // the member's own length, before any compression
	offset      int    // where its local header begins
	method      uint16
	flags       uint16
	date, clock uint16
	crc         uint32
	attrs       uint32
}

// zipMemberOf checks one entry and works out what the archive will record for
// it, at offset bytes into the member body. seen carries the names already
// used, which it adds to.
func zipMemberOf(e ZipEntry, offset int, seen map[string]bool) (zipMember, error) {
	name := strings.TrimPrefix(e.Name, "./")
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return zipMember{}, fmt.Errorf("zip member %q: names are relative and slash-separated", e.Name)
	}
	if seen[name] {
		return zipMember{}, fmt.Errorf("zip member %q appears twice", name)
	}
	seen[name] = true

	dir := strings.HasSuffix(name, "/")
	if dir && len(e.Data) > 0 {
		return zipMember{}, fmt.Errorf("zip member %q is a directory and cannot hold data", name)
	}
	stored, method, err := storedBytes(e.Data, e.Deflate && !dir)
	if err != nil {
		return zipMember{}, err
	}
	if offset >= zipMax || len(stored) >= zipMax || len(e.Data) >= zipMax {
		return zipMember{}, fmt.Errorf("zip member %q crosses the 4 GiB limit of the zip format", name)
	}

	m := zipMember{
		name:   name,
		stored: stored,
		size:   len(e.Data),
		offset: offset,
		method: method,
		crc:    crc32.ChecksumIEEE(e.Data),
		attrs:  zipAttrArchive,
	}
	if !isASCII(name) {
		m.flags |= zipUTF8Flag
	}
	m.date, m.clock = dosTime(e.Modified)
	if dir {
		m.attrs = zipAttrDir
	}
	return m, nil
}

// writeLocal writes the member's local header and its data.
func (m zipMember) writeLocal(b *bytes.Buffer) {
	putLE32(b, zipLocalSig)
	putLE16(b, zipVersion)
	putLE16(b, m.flags)
	putLE16(b, m.method)
	putLE16(b, m.clock)
	putLE16(b, m.date)
	putLE32(b, m.crc)
	putLE32(b, uint32(len(m.stored)))
	putLE32(b, uint32(m.size))
	putLE16(b, uint16(len(m.name)))
	putLE16(b, 0)
	b.WriteString(m.name)
	b.Write(m.stored)
}

// writeCentral writes the member's central directory entry, which repeats the
// local header and adds where to find it.
func (m zipMember) writeCentral(b *bytes.Buffer) {
	putLE32(b, zipCentralSig)
	putLE16(b, zipVersion) // made by MS-DOS, so no Unix permission bits
	putLE16(b, zipVersion)
	putLE16(b, m.flags)
	putLE16(b, m.method)
	putLE16(b, m.clock)
	putLE16(b, m.date)
	putLE32(b, m.crc)
	putLE32(b, uint32(len(m.stored)))
	putLE32(b, uint32(m.size))
	putLE16(b, uint16(len(m.name)))
	putLE16(b, 0)
	putLE16(b, 0)
	putLE16(b, 0)
	putLE16(b, 0)
	putLE32(b, m.attrs)
	putLE32(b, uint32(m.offset))
	b.WriteString(m.name)
}

// writeEOCD writes the end-of-central-directory record, which says how many
// members there are and where the directory describing them starts.
func writeEOCD(out *bytes.Buffer, entries, centralLen, bodyLen int, comment string) {
	putLE32(out, zipEOCDSig)
	// The counts and offsets below are 16- and 32-bit, so an archive past those
	// limits would record a wrong member count or a wrong directory offset and
	// read as a smaller archive than it is. BuildZip rejects both before here.
	putLE16(out, 0)
	putLE16(out, 0)
	putLE16(out, uint16(entries))
	putLE16(out, uint16(entries))
	putLE32(out, uint32(centralLen))
	putLE32(out, uint32(bodyLen))
	putLE16(out, uint16(len(comment)))
	out.WriteString(comment)
}

// StoredZipOverhead is the length BuildZip adds to the members' own bytes when
// nothing is deflated: enough to work out the member size that gives an
// archive of a wanted length.
func StoredZipOverhead(names []string, comment string) int {
	n := zipEOCDLen + len(comment)
	for _, name := range names {
		n += zipLocalLen + zipCentralLen + 2*len(name)
	}
	return n
}

// dosTime converts t to the MS-DOS date and time the zip format stores:
// two-second resolution, no zone, and nothing before 1980.
func dosTime(t time.Time) (date, clock uint16) {
	t = t.UTC()
	if t.Year() < 1980 {
		return 1<<5 | 1, 0 // 1980-01-01 00:00:00
	}
	date = uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	clock = uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	return date, clock
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// putLE16 and putLE32 are the only byte-order helpers left in this package:
// everywhere else that assembles a binary format appends through
// encoding/binary at the call site, naming the order there. A zip header is
// seventeen consecutive fields written into a buffer, which reads better
// through these — so they name the order they write instead, because the
// mistake worth preventing is one of these being read as the other way round.
func putLE16(b *bytes.Buffer, v uint16) { b.Write(binary.LittleEndian.AppendUint16(nil, v)) }

func putLE32(b *bytes.Buffer, v uint32) { b.Write(binary.LittleEndian.AppendUint32(nil, v)) }

// ZipFiller returns a zip holding one member of n filler bytes: what
// "format: zip" writes when the scenario only wants a real archive of about a
// given size, rather than an archive of named files (that is action: archive).
func ZipFiller(name string, data []byte, modified time.Time) ([]byte, error) {
	return BuildZip([]ZipEntry{{Name: name, Data: data, Modified: modified}}, "")
}

// zlibStored wraps data in a zlib stream of uncompressed deflate blocks. PNG
// needs a zlib stream, and compress/flate's output is not promised to stay the
// same across Go releases; stored blocks are fixed by the deflate
// specification, so a PNG fsagen writes has the same bytes on every toolchain.
func zlibStored(data []byte) []byte {
	out := []byte{0x78, 0x01} // deflate, 32 KiB window, fastest
	sum := adler32.Checksum(data)
	for rest, first := data, true; len(rest) > 0 || first; first = false {
		n := min(len(rest), 0xffff)
		final := byte(0)
		if n == len(rest) {
			final = 1
		}
		out = append(out, final, byte(n), byte(n>>8), byte(^uint16(n)), byte(^uint16(n)>>8))
		out = append(out, rest[:n]...)
		rest = rest[n:]
	}
	return append(out, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
}

// The zip compression methods this writer uses.
const (
	zipMethodStore   uint16 = 0
	zipMethodDeflate uint16 = 8
)

// deflate compresses a member's bytes. The result is only reproducible for the
// one Go toolchain go.mod pins, which is why store is the default everywhere.
func deflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// storedBytes is what goes into the archive for one member, with the method code
// that says how it got there. A directory entry is never compressed.
func storedBytes(data []byte, compress bool) ([]byte, uint16, error) {
	if !compress {
		return data, zipMethodStore, nil
	}
	stored, err := deflate(data)
	if err != nil {
		return nil, 0, err
	}
	return stored, zipMethodDeflate, nil
}

// MaxZipEntries is how many members the end-of-central-directory record can
// count: the field that holds the number is 16-bit.
const MaxZipEntries = 0xffff
