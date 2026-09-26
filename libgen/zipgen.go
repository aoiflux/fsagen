package libgen

import (
	"bytes"
	"compress/flate"
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
	zipVersion     = 20      // 2.0: store and deflate, no zip64
	zipUTF8Flag    = 0x0800  // the name is UTF-8, not CP437
	zipAttrArchive = 0x20    // MS-DOS FILE_ATTRIBUTE_ARCHIVE
	zipAttrDir     = 0x10    // MS-DOS FILE_ATTRIBUTE_DIRECTORY
	zipMaxComment  = 0xffff  // the end-of-central-directory comment is 16-bit
	zipMax         = 1 << 32 // without zip64 every offset and size is 32-bit
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
	if len(comment) > zipMaxComment {
		return nil, fmt.Errorf("zip comment is %d bytes; the format allows %d", len(comment), zipMaxComment)
	}
	seen := make(map[string]bool, len(entries))
	var body, central bytes.Buffer
	for _, e := range entries {
		name := strings.TrimPrefix(e.Name, "./")
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("zip member %q: names are relative and slash-separated", e.Name)
		}
		if seen[name] {
			return nil, fmt.Errorf("zip member %q appears twice", name)
		}
		seen[name] = true

		dir := strings.HasSuffix(name, "/")
		data := e.Data
		if dir && len(data) > 0 {
			return nil, fmt.Errorf("zip member %q is a directory and cannot hold data", name)
		}
		stored := data
		method := uint16(0)
		if e.Deflate && !dir {
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
			stored, method = buf.Bytes(), 8
		}

		offset := body.Len()
		if offset >= zipMax || len(stored) >= zipMax || len(data) >= zipMax {
			return nil, fmt.Errorf("zip member %q crosses the 4 GiB limit of the zip format", name)
		}
		flags := uint16(0)
		if !isASCII(name) {
			flags |= zipUTF8Flag
		}
		date, clock := dosTime(e.Modified)
		crc := crc32.ChecksumIEEE(data)
		attrs := uint32(zipAttrArchive)
		if dir {
			attrs = zipAttrDir
		}

		put32(&body, zipLocalSig)
		put16(&body, zipVersion)
		put16(&body, flags)
		put16(&body, method)
		put16(&body, clock)
		put16(&body, date)
		put32(&body, crc)
		put32(&body, uint32(len(stored)))
		put32(&body, uint32(len(data)))
		put16(&body, uint16(len(name)))
		put16(&body, 0)
		body.WriteString(name)
		body.Write(stored)

		put32(&central, zipCentralSig)
		put16(&central, zipVersion) // made by MS-DOS, so no Unix permission bits
		put16(&central, zipVersion)
		put16(&central, flags)
		put16(&central, method)
		put16(&central, clock)
		put16(&central, date)
		put32(&central, crc)
		put32(&central, uint32(len(stored)))
		put32(&central, uint32(len(data)))
		put16(&central, uint16(len(name)))
		put16(&central, 0)
		put16(&central, 0)
		put16(&central, 0)
		put16(&central, 0)
		put32(&central, attrs)
		put32(&central, uint32(offset))
		central.WriteString(name)
	}

	var out bytes.Buffer
	out.Write(body.Bytes())
	out.Write(central.Bytes())
	put32(&out, zipEOCDSig)
	put16(&out, 0)
	put16(&out, 0)
	put16(&out, uint16(len(entries)))
	put16(&out, uint16(len(entries)))
	put32(&out, uint32(central.Len()))
	put32(&out, uint32(body.Len()))
	put16(&out, uint16(len(comment)))
	out.WriteString(comment)
	return out.Bytes(), nil
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

func put16(b *bytes.Buffer, v uint16) { b.Write([]byte{byte(v), byte(v >> 8)}) }

func put32(b *bytes.Buffer, v uint32) {
	b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

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
