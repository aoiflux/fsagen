package libgen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/prng"
)

// xpressDecode is the [MS-XCA] LZ77+Huffman decoder, written from the
// specification's pseudo-code rather than from the encoder, so the two can
// disagree. It is stricter than Windows: every block's code must be complete,
// the stream must end with the end-of-stream symbol, and nothing may follow
// the stream's final word.
func xpressDecode(in []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	pos := 0
	le16 := func(p int) (uint32, error) {
		if p+2 > len(in) {
			return 0, fmt.Errorf("input ends at %d, inside a 16-bit word", len(in))
		}
		return uint32(binary.LittleEndian.Uint16(in[p:])), nil
	}
	for first := true; first || len(out) < size; first = false {
		if pos+256 > len(in) {
			return nil, fmt.Errorf("block at %d: no room for the 256-byte table", pos)
		}
		table, err := xpressDecodeTable(in[pos : pos+256])
		if err != nil {
			return nil, fmt.Errorf("block at %d: %v", pos, err)
		}
		pos += 256
		hi, err := le16(pos)
		if err != nil {
			return nil, err
		}
		lo, err := le16(pos + 2)
		if err != nil {
			return nil, err
		}
		next, extra := hi<<16|lo, 16
		pos += 4
		consume := func(n int) error {
			next <<= n
			extra -= n
			if extra < 0 {
				w, err := le16(pos)
				if err != nil {
					return err
				}
				next |= w << -extra
				extra += 16
				pos += 2
			}
			return nil
		}
		symbol := func() (int, error) {
			e := table[next>>17]
			return e.sym, consume(e.len)
		}

		end := min(len(out)+xpressBlock, size)
		for len(out) < end {
			sym, err := symbol()
			if err != nil {
				return nil, err
			}
			if sym < 256 {
				out = append(out, byte(sym))
				continue
			}
			sym -= 256
			length, high := sym&15, sym>>4
			if length == 15 {
				if pos >= len(in) {
					return nil, fmt.Errorf("input ends inside a match length")
				}
				length = int(in[pos]) + 15
				pos++
				if length == 270 {
					return nil, fmt.Errorf("a two-byte match length, which this encoder never writes")
				}
			}
			length += xpressMinMatch
			dist := int(next>>(32-high)) | 1<<high
			if err := consume(high); err != nil {
				return nil, err
			}
			if dist > len(out) {
				return nil, fmt.Errorf("a match reaches %d bytes back from %d", dist, len(out))
			}
			if len(out)+length > end {
				return nil, fmt.Errorf("a match at %d runs past the block's end at %d", len(out), end)
			}
			for range length {
				out = append(out, out[len(out)-dist])
			}
		}
		if len(out) == size {
			if sym, err := symbol(); err != nil || sym != xpressEOF {
				return nil, fmt.Errorf("the stream does not end with the end-of-stream symbol (got %d, %v)", sym, err)
			}
			if pos != len(in) {
				return nil, fmt.Errorf("%d bytes follow the end of the stream", len(in)-pos)
			}
		}
	}
	return out, nil
}

type xpressEntry struct{ sym, len int }

// xpressDecodeTable turns a block's code lengths into a 15-bit lookup table,
// assigning canonical codes as the specification does, and refuses a code
// that leaves any 15-bit pattern undecodable.
func xpressDecodeTable(b []byte) ([]xpressEntry, error) {
	var lengths [xpressSymbols]int
	for i, v := range b {
		lengths[2*i], lengths[2*i+1] = int(v&15), int(v>>4)
	}
	table := make([]xpressEntry, 1<<15)
	filled, code := 0, 0
	for l := 1; l <= 15; l++ {
		for s := range xpressSymbols {
			if lengths[s] != l {
				continue
			}
			span := 1 << (15 - l)
			start := code << (15 - l)
			if start+span > len(table) {
				return nil, fmt.Errorf("the code lengths oversubscribe the code")
			}
			for i := start; i < start+span; i++ {
				table[i] = xpressEntry{s, l}
			}
			filled += span
			code++
		}
		code <<= 1
	}
	if filled != len(table) {
		return nil, fmt.Errorf("the code is incomplete: %d of %d patterns decode", filled, len(table))
	}
	return table, nil
}

// xpressInputs are inputs that exercise every path of the encoder: nothing,
// one byte, text, bytes that do not compress, long runs that cross block
// boundaries, sizes on either side of a block, and every literal at once.
func xpressInputs() map[string][]byte {
	s := prng.Root(7).Derive("xpress").Stream()
	all := make([]byte, 0, 512)
	for i := range 512 {
		all = append(all, byte(i))
	}
	mixed := make([]byte, 0, 300_000)
	for len(mixed) < 300_000 {
		switch s.IntN(4) {
		case 0:
			mixed = append(mixed, s.Bytes(1+s.IntN(300))...)
		case 1:
			mixed = append(mixed, bytes.Repeat([]byte{byte(s.IntN(256))}, 1+s.IntN(2000))...)
		default:
			if len(mixed) > 0 {
				from := s.IntN(len(mixed))
				n := 1 + s.IntN(400)
				for i := range n {
					mixed = append(mixed, mixed[from+i%max(1, len(mixed)-from)])
				}
			}
		}
	}
	return map[string][]byte{
		"empty":      {},
		"one byte":   {'A'},
		"text":       []byte(strings.Repeat("The prefetcher records what a program loads. ", 300)),
		"random":     s.Bytes(100_000),
		"zeros":      make([]byte, 200_000),
		"block":      bytes.Repeat([]byte("abc"), xpressBlock/3+1)[:xpressBlock],
		"block + 1":  bytes.Repeat([]byte("abc"), xpressBlock/3+1)[:xpressBlock+1],
		"every byte": all,
		"mixed":      mixed,
	}
}

// TestXpressRoundTrip: what the encoder writes decodes back to its input
// under the specification's decoder, block by block, with complete codes and
// exact framing; and it is the same bytes every time.
func TestXpressRoundTrip(t *testing.T) {
	for name, in := range xpressInputs() {
		t.Run(name, func(t *testing.T) {
			c := XpressHuffman(in)
			got, err := xpressDecode(c, len(in))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, in) {
				t.Fatalf("decoded %d bytes that differ from the %d given", len(got), len(in))
			}
			if !bytes.Equal(XpressHuffman(in), c) {
				t.Error("two encodings of the same input differ")
			}
			if len(in) >= 100_000 && name != "random" && len(c) > len(in)/2 {
				t.Errorf("%d bytes compressed to %d; the matcher is not finding repeats", len(in), len(c))
			}
		})
	}
}

// TestHuffmanLengthsAreLimited: Fibonacci frequencies make the deepest
// unrestricted Huffman tree there is; the lengths still stop at 15 bits and
// still form a complete code.
func TestHuffmanLengthsAreLimited(t *testing.T) {
	freq := make([]int, xpressSymbols)
	a, b := 1, 1
	for i := range 40 {
		freq[i] = a
		a, b = b, a+b
	}
	lengths := huffmanLengths(freq, xpressMaxCode)
	kraft := 0
	for s, l := range lengths {
		if freq[s] > 0 && (l == 0 || l > xpressMaxCode) {
			t.Fatalf("symbol %d (frequency %d) has length %d", s, freq[s], l)
		}
		if l > 0 {
			kraft += 1 << (xpressMaxCode - int(l))
		}
	}
	if kraft != 1<<xpressMaxCode {
		t.Errorf("Kraft sum %d/%d: the code is not complete", kraft, 1<<xpressMaxCode)
	}
}
