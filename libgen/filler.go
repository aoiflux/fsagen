package libgen

import (
	"strings"

	"github.com/aoiflux/fsagen/prng"
)

// The content kinds: what the bytes fsagen invents look like when a scenario
// gives no content of its own. Text is the default and is what every fsagen
// release has written, so a scenario that does not ask keeps its bytes.
const (
	KindText    = "text"    // base32 characters
	KindBytes   = "bytes"   // uniform random bytes
	KindZeros   = "zeros"   // 0x00
	KindPattern = "pattern" // a repeating 0..255 ramp
	KindLorem   = "lorem"   // lorem ipsum words, wrapped
)

// Filler returns exactly n bytes of the named kind, drawn from s. An empty
// kind means text; compile has already checked the name against
// compile.ContentKinds.
func Filler(kind string, n int, s *prng.Stream) []byte {
	if n <= 0 {
		return nil
	}
	switch kind {
	case "", KindText:
		return []byte(s.Text(n))
	case KindBytes:
		return s.Bytes(n)
	case KindZeros:
		return make([]byte, n)
	case KindPattern:
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(i)
		}
		return out
	case KindLorem:
		return lorem(n, s)
	}
	panic("libgen: unchecked content kind " + kind)
}

// loremWords is the classic passage's vocabulary. A fixed list keeps the text
// recognisable as filler rather than as anything a person wrote.
var loremWords = strings.Fields(`lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis
nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis
aute irure in reprehenderit voluptate velit esse cillum eu fugiat nulla pariatur
excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt
mollit anim id est laborum`)

// lorem returns exactly n bytes of wrapped lorem ipsum. The last word is cut
// where it has to be: the length is what the scenario asked for.
func lorem(n int, s *prng.Stream) []byte {
	const wrap = 72
	out := make([]byte, 0, n+16)
	col := 0
	for len(out) < n {
		w := loremWords[s.IntN(len(loremWords))]
		switch {
		case col == 0:
		case col+1+len(w) > wrap:
			out = append(out, '\n')
			col = 0
		default:
			out = append(out, ' ')
			col++
		}
		out = append(out, w...)
		col += len(w)
	}
	return out[:n]
}
