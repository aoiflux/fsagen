package volume

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"

	"github.com/aoiflux/fsagen/target"
)

// Tracker records the residue a driver's writes leave, and once the image
// is finished works out how much of it survived.
type Tracker struct {
	op   int
	path string
	recs []record
}

// record is one piece of residue and the bytes it held when it was left.
type record struct {
	r     target.Residue
	entry []byte
	data  []byte
}

// Begin names the operation and path the next residue comes from.
func (t *Tracker) Begin(op int, path string) { t.op, t.path = op, path }

// Source is the operation and path residue now comes from, for a driver
// that works out later what that operation left.
func (t *Tracker) Source() (int, string) { return t.op, t.path }

// Add records residue: the entry left behind as it then read (nil if none),
// and the content freed, as image-file extents and the bytes they held.
func (t *Tracker) Add(cause string, entry *target.ResidueEntry, entryBytes []byte, extents []target.Extent, data []byte) {
	t.AddFrom(t.op, t.path, cause, entry, entryBytes, extents, data)
}

// AddFrom records residue that operation op left from path, as Add does.
func (t *Tracker) AddFrom(op int, path, cause string, entry *target.ResidueEntry, entryBytes []byte, extents []target.Extent, data []byte) {
	r := target.Residue{N: op, Path: path, Cause: cause, Entry: entry, Extents: extents}
	if len(extents) > 0 {
		sum := sha256.Sum256(data)
		r.Size, r.SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
	}
	t.recs = append(t.recs, record{r: r, entry: bytes.Clone(entryBytes), data: bytes.Clone(data)})
}

// Resolve compares every record with the finished image, read from img (the
// whole image file), and returns the residue in the order of the operations
// that left it, and as it was recorded within one.
func (t *Tracker) Resolve(img io.ReaderAt) ([]target.Residue, error) {
	out := make([]target.Residue, 0, len(t.recs))
	recs := slices.Clone(t.recs)
	slices.SortStableFunc(recs, func(a, b record) int { return a.r.N - b.r.N })
	for _, rec := range recs {
		r := rec.r
		if r.Entry != nil {
			now := make([]byte, len(rec.entry))
			if _, err := img.ReadAt(now, r.Entry.Offset); err != nil {
				return nil, err
			}
			e := *r.Entry
			e.Overwritten = !bytes.Equal(now, rec.entry)
			r.Entry = &e
		}
		if len(r.Extents) > 0 {
			over, err := overwritten(img, r.Extents, rec.data)
			if err != nil {
				return nil, err
			}
			r.Overwritten = over
			var lost int64
			for _, o := range over {
				lost += o.Length
			}
			switch lost {
			case 0:
				r.Recoverable = target.RecoverableFull
			case r.Size:
				r.Recoverable = target.RecoverableNone
			default:
				r.Recoverable = target.RecoverablePartial
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// overwritten lists the ranges of extents that no longer hold data, byte by
// byte, merged where they touch.
func overwritten(img io.ReaderAt, extents []target.Extent, data []byte) ([]target.Extent, error) {
	var out []target.Extent
	pos := 0
	for _, e := range extents {
		now := make([]byte, e.Length)
		if _, err := img.ReadAt(now, e.Offset); err != nil {
			return nil, err
		}
		was := data[pos : pos+int(e.Length)]
		pos += int(e.Length)
		for i := 0; i < len(now); i++ {
			if now[i] == was[i] {
				continue
			}
			j := i
			for j < len(now) && now[j] != was[j] {
				j++
			}
			at := e.Offset + int64(i)
			if n := len(out); n > 0 && out[n-1].Offset+out[n-1].Length == at {
				out[n-1].Length += int64(j - i)
			} else {
				out = append(out, target.Extent{Offset: at, Length: int64(j - i)})
			}
			i = j
		}
	}
	return out, nil
}
