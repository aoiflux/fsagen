package libgen

import (
	"encoding/binary"
	"math/bits"
	"slices"
)

// LZ77+Huffman as [MS-XCA] defines it, the compression Windows calls
// COMPRESSION_FORMAT_XPRESS_HUFF and writes Windows 10 and 11 prefetch files
// with. The input is cut into 64 KiB blocks; each block starts with a table
// of 512 four-bit code lengths and then carries its literals and matches as
// canonical Huffman codes, with the extra length bytes and offset bits a
// match needs interleaved in the bit stream exactly where the decoder reads
// them. The last block ends with the end-of-stream symbol.
//
// The encoder is greedy and deterministic: the same input gives the same
// bytes on every platform, which is all the generator needs from it. It
// trades a little ratio for simplicity by never using the two-byte match
// length, so a match is at most 272 bytes long.

const (
	xpressBlock    = 1 << 16 // output bytes covered by one Huffman table
	xpressSymbols  = 512     // 256 literals, then 16 offset sizes x 16 lengths
	xpressMaxCode  = 15      // the longest code a four-bit length can say
	xpressEOF      = 256     // the end-of-stream symbol
	xpressMinMatch = 3
	// xpressMaxMatch is the longest match whose length fits the symbol's
	// nibble and one extra byte: 3 + 15 + 254.
	xpressMaxMatch = xpressMinMatch + 15 + 254
	xpressWindow   = 1<<16 - 1 // the farthest back a match can reach
	xpressChain    = 64        // candidates tried per position
	xpressHashBits = 15
)

// xpressToken is a literal (length 0) or a match.
type xpressToken struct {
	length, dist int
	lit          byte
}

// XpressHuffman compresses data as [MS-XCA] LZ77+Huffman.
func XpressHuffman(data []byte) []byte {
	tokens := xpressParse(data)
	out := make([]byte, 0, len(data)/2+256)
	next := 0
	for start := 0; ; start += xpressBlock {
		end := min(start+xpressBlock, len(data))
		var block []xpressToken
		for pos := start; pos < end; next++ {
			block = append(block, tokens[next])
			pos += max(tokens[next].length, 1)
		}
		out = xpressBlockBytes(out, block, end == len(data))
		if end == len(data) {
			return out
		}
	}
}

// xpressParse finds the literals and matches, greedily, with hash chains.
// A match never runs past the end of the block it starts in, because each
// block's decoder stops at its 64 KiB.
func xpressParse(data []byte) []xpressToken {
	var tokens []xpressToken
	head := make([]int32, 1<<xpressHashBits)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int32, len(data))
	hash := func(p int) uint32 {
		v := uint32(data[p])<<16 | uint32(data[p+1])<<8 | uint32(data[p+2])
		return v * 2654435761 >> (32 - xpressHashBits)
	}
	insert := func(p int) {
		if p+xpressMinMatch <= len(data) {
			h := hash(p)
			prev[p] = head[h]
			head[h] = int32(p)
		}
	}
	for pos := 0; pos < len(data); {
		limit := min(xpressMaxMatch, xpressBlock-pos%xpressBlock, len(data)-pos)
		best, bestDist := 0, 0
		if limit >= xpressMinMatch {
			cand := head[hash(pos)]
			for tries := 0; cand >= 0 && tries < xpressChain && pos-int(cand) <= xpressWindow; tries++ {
				c := int(cand)
				n := 0
				for n < limit && data[c+n] == data[pos+n] {
					n++
				}
				if n > best {
					best, bestDist = n, pos-c
					if n == limit {
						break
					}
				}
				cand = prev[c]
			}
		}
		if best >= xpressMinMatch {
			tokens = append(tokens, xpressToken{length: best, dist: bestDist})
			for i := range best {
				insert(pos + i)
			}
			pos += best
			continue
		}
		tokens = append(tokens, xpressToken{lit: data[pos]})
		insert(pos)
		pos++
	}
	return tokens
}

// xpressSymbol is the Huffman symbol of a token.
func xpressSymbol(t xpressToken) int {
	if t.length == 0 {
		return int(t.lit)
	}
	return 256 + min(t.length-xpressMinMatch, 15) + 16*(bits.Len(uint(t.dist))-1)
}

// xpressBlockBytes appends one block: its code-length table and its tokens.
// The end-of-stream symbol is given a code in every block, so a block always
// has at least two symbols and a complete code, though only the last one
// writes it.
func xpressBlockBytes(out []byte, block []xpressToken, last bool) []byte {
	freq := make([]int, xpressSymbols)
	for _, t := range block {
		freq[xpressSymbol(t)]++
	}
	freq[xpressEOF]++
	if len(block) == 0 {
		freq[0]++ // an empty input still needs two symbols for a code
	}
	lengths := huffmanLengths(freq, xpressMaxCode)
	codes := canonicalCodes(lengths)
	for i := 0; i < xpressSymbols; i += 2 {
		out = append(out, lengths[i]|lengths[i+1]<<4)
	}

	w := xpressWriter{out: out}
	w.start()
	put := func(sym int) { w.bits(uint(lengths[sym]), codes[sym]) }
	for _, t := range block {
		put(xpressSymbol(t))
		if t.length == 0 {
			continue
		}
		if extra := t.length - xpressMinMatch; extra >= 15 {
			w.byte(byte(extra - 15))
		}
		high := uint(bits.Len(uint(t.dist)) - 1)
		w.bits(high, uint32(t.dist)-1<<high)
	}
	if last {
		put(xpressEOF)
	}
	return w.flush()
}

// xpressWriter is the encoder's half of the bit stream. Bits fill 16-bit
// little-endian words, and the decoder always holds the next two words, so
// the writer reserves each word's place two words ahead; a byte written
// meanwhile (a long match's length) lands after the reserved words, where the
// decoder reads it.
type xpressWriter struct {
	out          []byte
	slot1, slot2 int
	free         uint
	acc          uint32
}

func (w *xpressWriter) start() {
	w.slot1 = len(w.out)
	w.slot2 = w.slot1 + 2
	w.out = append(w.out, 0, 0, 0, 0)
	w.free, w.acc = 16, 0
}

func (w *xpressWriter) bits(n uint, v uint32) {
	if n == 0 {
		return
	}
	if w.free >= n {
		w.free -= n
		w.acc = w.acc<<n | v
		return
	}
	n -= w.free
	w.acc = w.acc<<w.free | v>>n
	binary.LittleEndian.PutUint16(w.out[w.slot1:], uint16(w.acc))
	w.slot1, w.slot2 = w.slot2, len(w.out)
	w.out = append(w.out, 0, 0)
	w.free = 16 - n
	w.acc = v & (1<<n - 1)
}

func (w *xpressWriter) byte(b byte) { w.out = append(w.out, b) }

// flush writes the last partly filled word; the word reserved after it stays
// zero, which is the two zero bytes a stream ends with.
func (w *xpressWriter) flush() []byte {
	binary.LittleEndian.PutUint16(w.out[w.slot1:], uint16(w.acc<<w.free))
	return w.out
}

// huffmanLengths are optimal code lengths of at most maxLen bits for the
// symbols with a non-zero frequency, by package-merge. Ties are broken by
// symbol, so the lengths are the same on every run. The code is complete
// whenever two or more symbols are used.
func huffmanLengths(freq []int, maxLen int) []uint8 {
	type item struct {
		weight, sym int
		a, b        *item
	}
	var leaves []*item
	for s, f := range freq {
		if f > 0 {
			leaves = append(leaves, &item{weight: f, sym: s})
		}
	}
	slices.SortStableFunc(leaves, func(x, y *item) int { return x.weight - y.weight })
	lengths := make([]uint8, len(freq))
	if len(leaves) == 1 {
		lengths[leaves[0].sym] = 1
		return lengths
	}

	list := leaves
	for range maxLen - 1 {
		var packages []*item
		for i := 0; i+1 < len(list); i += 2 {
			packages = append(packages, &item{weight: list[i].weight + list[i+1].weight, a: list[i], b: list[i+1]})
		}
		merged := make([]*item, 0, len(leaves)+len(packages))
		i, j := 0, 0
		for i < len(leaves) || j < len(packages) {
			if j == len(packages) || i < len(leaves) && leaves[i].weight <= packages[j].weight {
				merged = append(merged, leaves[i])
				i++
			} else {
				merged = append(merged, packages[j])
				j++
			}
		}
		list = merged
	}

	var count func(*item)
	count = func(it *item) {
		if it.a == nil {
			lengths[it.sym]++
			return
		}
		count(it.a)
		count(it.b)
	}
	for _, it := range list[:2*len(leaves)-2] {
		count(it)
	}
	return lengths
}

// canonicalCodes assigns canonical Huffman codes: shorter codes first, and
// within a length, in symbol order.
func canonicalCodes(lengths []uint8) []uint32 {
	codes := make([]uint32, len(lengths))
	code, prevLen := uint32(0), uint8(0)
	for l := uint8(1); l <= 15; l++ {
		for s, sl := range lengths {
			if sl != l {
				continue
			}
			if prevLen != 0 {
				code <<= l - prevLen
			}
			codes[s] = code
			code++
			prevLen = l
		}
	}
	return codes
}
