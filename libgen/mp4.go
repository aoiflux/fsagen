package libgen

import (
	"bytes"
	"time"
)

// mp4Epoch is where the MP4 container counts time from, which is neither the
// Unix epoch nor anything else a tool would guess.
var mp4Epoch = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)

// mp4Timescale is the ticks per second every duration here is expressed in.
const mp4Timescale = 1000

// MP4 returns an ISO base media file: a file type box, a movie box describing
// one video track of the given size and duration, and a media data box holding
// payload. The track declares no samples, so the file carries no picture; it
// exists so that a tool reading container metadata (duration, dimensions,
// creation time) has a real file to read.
func MP4(created time.Time, duration time.Duration, w, h int, payload []byte) []byte {
	secs := uint32(0)
	if !created.IsZero() && created.After(mp4Epoch) {
		secs = uint32(created.UTC().Sub(mp4Epoch) / time.Second)
	}
	ticks := uint32(duration / (time.Second / mp4Timescale))

	ftyp := mp4Box("ftyp", concat([]byte("isom"), be32(512), []byte("isomiso2mp41")))

	mvhd := mp4Box("mvhd", concat(
		be32(0), // version 0, no flags
		be32(secs), be32(secs), be32(mp4Timescale), be32(ticks),
		be32(0x00010000), // rate 1.0
		be16(0x0100),     // volume 1.0
		make([]byte, 10), // reserved
		mp4Matrix(),
		make([]byte, 24), // pre-defined
		be32(2),          // next track id
	))

	tkhd := mp4Box("tkhd", concat(
		[]byte{0, 0, 0, 3}, // version 0; enabled and in the movie
		be32(secs), be32(secs), be32(1), be32(0), be32(ticks),
		make([]byte, 8),  // reserved
		be16(0), be16(0), // layer, alternate group
		be16(0), be16(0), // volume (video has none), reserved
		mp4Matrix(),
		be32(uint32(w)<<16), be32(uint32(h)<<16),
	))

	mdhd := mp4Box("mdhd", concat(
		be32(0), be32(secs), be32(secs), be32(mp4Timescale), be32(ticks),
		be16(0x55c4), // language "und"
		be16(0),
	))
	hdlr := mp4Box("hdlr", concat(
		be32(0), be32(0), []byte("vide"), make([]byte, 12), []byte("VideoHandler\x00"),
	))

	vmhd := mp4Box("vmhd", concat([]byte{0, 0, 0, 1}, be16(0), be16(0), be16(0), be16(0)))
	dref := mp4Box("dref", concat(be32(0), be32(1), mp4Box("url ", []byte{0, 0, 0, 1})))
	dinf := mp4Box("dinf", dref)

	// An empty sample table: the track is described but holds no frames.
	stbl := mp4Box("stbl", concat(
		mp4Box("stsd", concat(be32(0), be32(0))),
		mp4Box("stts", concat(be32(0), be32(0))),
		mp4Box("stsc", concat(be32(0), be32(0))),
		mp4Box("stsz", concat(be32(0), be32(0), be32(0))),
		mp4Box("stco", concat(be32(0), be32(0))),
	))

	minf := mp4Box("minf", concat(vmhd, dinf, stbl))
	mdia := mp4Box("mdia", concat(mdhd, hdlr, minf))
	trak := mp4Box("trak", concat(tkhd, mdia))
	moov := mp4Box("moov", concat(mvhd, trak))
	mdat := mp4Box("mdat", payload)

	return concat(ftyp, moov, mdat)
}

// mp4Matrix is the identity transform every unrotated track carries.
func mp4Matrix() []byte {
	return concat(
		be32(0x00010000), be32(0), be32(0),
		be32(0), be32(0x00010000), be32(0),
		be32(0), be32(0), be32(0x40000000),
	)
}

func mp4Box(kind string, body []byte) []byte {
	var b bytes.Buffer
	b.Write(be32(uint32(len(body) + 8)))
	b.WriteString(kind)
	b.Write(body)
	return b.Bytes()
}

func be32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
