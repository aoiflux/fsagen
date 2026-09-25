package compile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/aoiflux/fsagen/prng"
)

// An operation's random key is derived from what the operation is, never
// from where it sits: its explicit id, or else a hash of its own YAML, plus
// the iteration and batch it belongs to. Inserting, removing or reordering
// an unrelated action therefore leaves every other file's bytes alone.
//
// Two operations with the same identity (identical YAML in the same step
// and iteration) are told apart by an occurrence counter in compile order.
type opKeys struct {
	root prng.Key
	seen map[string]int
}

func newOpKeys(seed int64) *opKeys {
	return &opKeys{root: prng.Root(seed), seen: map[string]int{}}
}

// key returns the operation key for the given identity parts.
func (k *opKeys) key(parts ...string) prng.Key {
	h := sha256.New()
	for _, p := range parts {
		writeLP(h, p)
	}
	id := string(h.Sum(nil))
	n := k.seen[id]
	k.seen[id] = n + 1
	return k.root.Derive(append([]string{"op"}, append(parts, "occurrence", strconv.Itoa(n))...)...)
}

// identity names an action: its explicit id, or else the hash of its YAML.
func identity(id string, n *yaml.Node) (kind, value string) {
	if id != "" {
		return "id", id
	}
	return "yaml", nodeHash(n)
}

// nodeHash is a hash of a YAML node's content that ignores key order,
// comments, quoting style and position.
func nodeHash(n *yaml.Node) string {
	h := sha256.New()
	canon(h, n)
	return hex.EncodeToString(h.Sum(nil))
}

func canon(h hash.Hash, n *yaml.Node) {
	n = resolve(n)
	if n == nil {
		writeLP(h, "nil")
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			canon(h, n.Content[0])
			return
		}
		writeLP(h, "nil")
	case yaml.ScalarNode:
		writeLP(h, "s")
		writeLP(h, n.ShortTag())
		writeLP(h, n.Value)
	case yaml.SequenceNode:
		writeLP(h, "q")
		writeLP(h, strconv.Itoa(len(n.Content)))
		for _, c := range n.Content {
			canon(h, c)
		}
	case yaml.MappingNode:
		type pair struct{ k, v string }
		var pairs []pair
		for i := 0; i+1 < len(n.Content); i += 2 {
			kh, vh := sha256.New(), sha256.New()
			canon(kh, n.Content[i])
			canon(vh, n.Content[i+1])
			pairs = append(pairs, pair{string(kh.Sum(nil)), string(vh.Sum(nil))})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
		writeLP(h, "m")
		writeLP(h, strconv.Itoa(len(pairs)))
		for _, p := range pairs {
			writeLP(h, p.k)
			writeLP(h, p.v)
		}
	}
}

func writeLP(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}
