package libgen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"

	"github.com/aoiflux/fsagen/prng"
)

// DefaultImageSize is the edge of the images fsagen invents. They exist so a
// tool has a real image to parse, not to look like a photograph.
const DefaultImageSize = 64

// pngMagic is the signature every PNG starts with.
var pngMagic = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// padChunk is the PNG chunk fsagen puts filler in. The case of each letter is
// what the format uses to classify a chunk: ancillary (a decoder may ignore
// it), private (not registered), valid, and safe to copy.
const padChunk = "fsAg"

// PNG returns an 8-bit truecolour PNG of w by h pixels holding a two-tone
// pattern drawn from s, with pad appended in a private ancillary chunk. Its
// image data is a zlib stream of uncompressed blocks, so the bytes are the
// same whatever Go release built fsagen.
func PNG(w, h int, s *prng.Stream, pad []byte) ([]byte, error) {
	if w < 1 || h < 1 {
		return nil, fmt.Errorf("png: %dx%d is not an image", w, h)
	}
	if len(pad) > 0 && len(pad) >= 1<<31 {
		return nil, fmt.Errorf("png: %d bytes of filler is more than a chunk holds", len(pad))
	}
	fg, bg := s.Bytes(3), s.Bytes(3)

	raw := make([]byte, 0, h*(1+w*3))
	for y := 0; y < h; y++ {
		raw = append(raw, 0) // filter type 0: none
		for x := 0; x < w; x++ {
			raw = append(raw, checker(x, y, fg, bg)...)
		}
	}

	var out bytes.Buffer
	out.Write(pngMagic)
	var ihdr bytes.Buffer
	ihdr.Write(binary.BigEndian.AppendUint32(nil, uint32(w)))
	ihdr.Write(binary.BigEndian.AppendUint32(nil, uint32(h)))
	ihdr.Write([]byte{8, 2, 0, 0, 0}) // depth 8, truecolour, deflate, adaptive filtering, no interlace
	pngChunk(&out, "IHDR", ihdr.Bytes())
	pngChunk(&out, "IDAT", zlibStored(raw))
	if len(pad) > 0 {
		pngChunk(&out, padChunk, pad)
	}
	pngChunk(&out, "IEND", nil)
	return out.Bytes(), nil
}

func pngChunk(w *bytes.Buffer, kind string, data []byte) {
	w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(data))))
	w.WriteString(kind)
	w.Write(data)
	h := crc32.NewIEEE()
	h.Write([]byte(kind))
	h.Write(data)
	w.Write(binary.BigEndian.AppendUint32(nil, h.Sum32()))
}

// jpegQuality is fixed so the bytes depend on nothing but the pixels.
const jpegQuality = 80

// JPEG returns a baseline JPEG of w by h pixels holding a two-tone pattern
// drawn from s, with pad carried in comment segments after the start marker.
// Unlike PNG, the entropy-coded data comes from image/jpeg, so its bytes are
// only pinned by the Go toolchain in go.mod.
func JPEG(w, h int, s *prng.Stream, pad []byte) ([]byte, error) {
	if w < 1 || h < 1 {
		return nil, fmt.Errorf("jpeg: %dx%d is not an image", w, h)
	}
	fg, bg := s.Bytes(3), s.Bytes(3)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			rgb := checker(x, y, fg, bg)
			img.SetRGBA(x, y, color.RGBA{rgb[0], rgb[1], rgb[2], 0xff})
		}
	}
	var body bytes.Buffer
	if err := jpeg.Encode(&body, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return nil, err
	}
	data := body.Bytes()
	if len(pad) == 0 {
		return data, nil
	}
	// The comment segments go straight after SOI, where every decoder skips
	// them and every carver still finds the image.
	var out bytes.Buffer
	out.Write(data[:2])
	const maxComment = 0xffff - 2
	for rest := pad; len(rest) > 0; {
		n := min(len(rest), maxComment)
		out.Write([]byte{0xff, 0xfe, byte((n + 2) >> 8), byte(n + 2)})
		out.Write(rest[:n])
		rest = rest[n:]
	}
	out.Write(data[2:])
	return out.Bytes(), nil
}

// checkerTile is the side of one square of the checkerboard, in pixels. A
// pattern rather than noise keeps the image small once deflated and makes it
// obvious to the eye that nothing was photographed.
const checkerTile = 8

// checker is the colour of one pixel of the checkerboard.
func checker(x, y int, fg, bg []byte) []byte {
	if (x+y)/checkerTile%2 == 0 {
		return fg
	}
	return bg
}
