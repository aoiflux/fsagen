package libgen

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/libntfs"
)

// The encodings Windows binary formats share: UTF-16LE strings, the range
// of FILETIMEs (libntfs encodes them), MS-DOS dates and GUIDs in their
// mixed-endian layout.

// utf16z is s as NUL-terminated UTF-16LE.
func utf16z(s string) []byte {
	return append(utf16le(s), 0, 0)
}

// utf16le is s as UTF-16LE, with no terminator.
func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// MinFiletime and MaxFiletime bound the times FILETIMEs are written for, with
// libntfs.TimeToFiletime: nothing before its epoch, and nothing a signed
// 64-bit count of 100 ns ticks cannot hold, which is what every parser reads
// it as. The zero time is written as 0, which Windows reads as "not set".
var (
	MinFiletime = libntfs.FiletimeToTime(0)
	MaxFiletime = libntfs.FiletimeToTime(1<<63 - 1)
)

// dosTime converts t to an MS-DOS date and time, as zip headers and shell
// items store them: two-second resolution, no zone, and nothing before 1980.
func dosTime(t time.Time) (date, clock uint16) {
	t = t.UTC()
	if t.Year() < 1980 {
		return 1<<5 | 1, 0 // 1980-01-01 00:00:00
	}
	date = uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	clock = uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	return date, clock
}

// GUID is a GUID in its canonical order, the order it is written in text:
// {00021401-0000-0000-C000-000000000046} is 00 02 14 01 00 00 ... 46.
type GUID [16]byte

// MustGUID parses a GUID written as text, with or without braces. It is for
// the constants the formats fix, so a malformed one is a programming error.
func MustGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

// ParseGUID parses a GUID written as text, with or without braces.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	t := strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	parts := strings.Split(t, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return g, fmt.Errorf("%q is not a GUID (want {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx})", s)
	}
	b, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return g, fmt.Errorf("%q is not a GUID: %v", s, err)
	}
	copy(g[:], b)
	return g, nil
}

// String is the GUID as Windows prints it, upper case in braces.
func (g GUID) String() string {
	h := strings.ToUpper(hex.EncodeToString(g[:]))
	return "{" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:] + "}"
}

// appendGUID writes g as Windows stores a GUID on disk: the first three
// fields little-endian, the last eight bytes as they are.
func appendGUID(b []byte, g GUID) []byte {
	b = binary.LittleEndian.AppendUint32(b, binary.BigEndian.Uint32(g[0:4]))
	b = binary.LittleEndian.AppendUint16(b, binary.BigEndian.Uint16(g[4:6]))
	b = binary.LittleEndian.AppendUint16(b, binary.BigEndian.Uint16(g[6:8]))
	return append(b, g[8:]...)
}

// gregorianToUnix is the number of 100 ns ticks between the start of the
// Gregorian calendar (1582-10-15), which a version 1 GUID counts from, and
// 1970.
const gregorianToUnix = 0x01B21DD213814000

// guidV1 is a time-based (version 1) GUID for when, with a clock sequence and
// node drawn from s. Windows' link tracking writes its object ids this way,
// and tools decode the time and the MAC address from them, so the time is a
// scenario time. The node is a locally administered unicast MAC, which no
// real adapter has.
func guidV1(when time.Time, s *prng.Stream) GUID {
	var g GUID
	ticks := uint64(0)
	if !when.IsZero() {
		u := when.UTC()
		ticks = uint64(u.Unix())*10_000_000 + uint64(u.Nanosecond()/100) + gregorianToUnix
	}
	binary.BigEndian.PutUint32(g[0:4], uint32(ticks))
	binary.BigEndian.PutUint16(g[4:6], uint16(ticks>>32))
	binary.BigEndian.PutUint16(g[6:8], uint16(ticks>>48)&0x0FFF|0x1000)
	seq := uint16(s.Uint64())
	binary.BigEndian.PutUint16(g[8:10], seq&0x3FFF|0x8000)
	node := s.Bytes(6)
	node[0] = node[0]&^0x01 | 0x02
	copy(g[10:], node)
	return g
}
