package compile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// mergeKey is YAML's merge key, which brings another mapping's keys into this
// one. Keys given here directly win over the ones it supplies.
const mergeKey = "<<"

// keys maps each YAML key present on a mapping to its key node, which gives
// both presence (a zero value and an absent key differ) and position.
type keys map[string]*yaml.Node

func (k keys) has(name string) bool { return k[name] != nil }

// fillFrom adds the keys of m that are not already present, so a key given
// directly wins over one a merge key supplies.
func (k keys) fillFrom(m keys) {
	for name, node := range m {
		if _, ok := k[name]; !ok {
			k[name] = node
		}
	}
}

// pairs iterates a mapping node's key and value nodes. A malformed mapping with
// an odd number of children stops after the last complete pair.
func pairs(n *yaml.Node) iter.Seq2[*yaml.Node, *yaml.Node] {
	return func(yield func(*yaml.Node, *yaml.Node) bool) {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if !yield(n.Content[i], n.Content[i+1]) {
				return
			}
		}
	}
}

// decodeFile parses data strictly into v and returns the document's root node
// for positions. Unknown and duplicate keys are reported with their line,
// column and the list of valid keys before the decoder's own KnownFields
// check runs as a backstop.
func decodeFile(file string, data []byte, v any) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("%s: file is empty", file)
	}
	root := doc.Content[0]
	if err := checkKeys(file, root, reflect.TypeOf(v), ""); err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: only one YAML document is allowed", file)
	}
	return root, nil
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// mappingKeys lists a mapping's keys, including those brought in by a merge
// key.
func mappingKeys(n *yaml.Node) keys {
	out := keys{}
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	var merged []keys
	for k, v := range pairs(n) {
		if k.Value == mergeKey {
			merged = append(merged, mergedKeys(v)...)
			continue
		}
		out[k.Value] = k
	}
	for _, m := range merged {
		out.fillFrom(m)
	}
	return out
}

// mergedKeys is the key set of each mapping a merge key brings in.
func mergedKeys(v *yaml.Node) []keys {
	var out []keys
	for _, src := range mergeSources(v) {
		out = append(out, mappingKeys(src))
	}
	return out
}

// mappingValue returns the value node for key, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for k, v := range pairs(n) {
		if k.Value == key {
			return resolve(v)
		}
	}
	// Only a mapping that does not give the key itself takes it from a merge.
	return mergedValue(n, key)
}

// mergedValue looks key up in each mapping a merge key on n brings in.
func mergedValue(n *yaml.Node, key string) *yaml.Node {
	for k, v := range pairs(n) {
		if k.Value != mergeKey {
			continue
		}
		if found := firstValue(mergeSources(v), key); found != nil {
			return found
		}
	}
	return nil
}

// firstValue is key's value in the first of these mappings that has it.
func firstValue(sources []*yaml.Node, key string) *yaml.Node {
	for _, src := range sources {
		if v := mappingValue(src, key); v != nil {
			return v
		}
	}
	return nil
}

// seqItems returns a sequence's items, or nil.
func seqItems(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func mergeSources(v *yaml.Node) []*yaml.Node {
	v = resolve(v)
	if v == nil {
		return nil
	}
	if v.Kind == yaml.SequenceNode {
		out := make([]*yaml.Node, 0, len(v.Content))
		for _, c := range v.Content {
			out = append(out, resolve(c))
		}
		return out
	}
	return []*yaml.Node{v}
}

// checkKeys walks the node tree alongside the Go type it decodes into and
// rejects any key the type does not have, and any key given twice.
func checkKeys(file string, n *yaml.Node, t reflect.Type, where string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	n = resolve(n)
	if n == nil {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		return checkStructKeys(file, n, t, where)
	case reflect.Slice:
		return checkSliceKeys(file, n, t, where)
	case reflect.Map:
		return checkMapKeys(file, n, where)
	}
	return nil
}

// checkStructKeys rejects a key the struct does not have, or that is given
// twice, then recurses into each value. A node of the wrong shape is left to
// the decoder, which reports the type mismatch with its own position.
func checkStructKeys(file string, n *yaml.Node, t reflect.Type, where string) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	sk := structKeys{
		file:   file,
		where:  where,
		typ:    t,
		fields: yamlFields(t),
		seen:   map[string]*yaml.Node{},
	}
	for k, v := range pairs(n) {
		if err := sk.check(k, v); err != nil {
			return err
		}
	}
	return nil
}

// structKeys checks the keys of one struct mapping, remembering which it has
// seen so that a key given twice is reported.
type structKeys struct {
	file   string
	where  string
	typ    reflect.Type
	fields map[string]reflect.Type
	seen   map[string]*yaml.Node
}

// check validates one key and value: a merge key brings in another mapping of
// the same type, and anything else has to be a field the struct declares.
func (s structKeys) check(k, v *yaml.Node) error {
	if k.Value == mergeKey {
		return checkMergedKeys(s.file, v, s.typ, s.where)
	}
	if err := markSeen(s.file, s.seen, k, s.where); err != nil {
		return err
	}
	ft, ok := s.fields[k.Value]
	if !ok {
		return fmt.Errorf("%s:%d:%d: %sunknown field %q; valid fields: %s", s.file, k.Line, k.Column, prefix(s.where), k.Value, strings.Join(sortedNames(s.fields), ", "))
	}
	return checkKeys(s.file, v, ft, join(s.where, k.Value))
}

// checkMergedKeys checks each mapping a merge key brings in against the same
// type, so a key it supplies is as strictly checked as one given directly.
func checkMergedKeys(file string, v *yaml.Node, t reflect.Type, where string) error {
	for _, src := range mergeSources(v) {
		if err := checkKeys(file, src, t, where); err != nil {
			return err
		}
	}
	return nil
}

// markSeen records a key and rejects a second use of the same one.
func markSeen(file string, seen map[string]*yaml.Node, k *yaml.Node, where string) error {
	if prev, dup := seen[k.Value]; dup {
		return fmt.Errorf("%s:%d:%d: %sduplicate key %q (first given at line %d)", file, k.Line, k.Column, prefix(where), k.Value, prev.Line)
	}
	seen[k.Value] = k
	return nil
}

func checkSliceKeys(file string, n *yaml.Node, t reflect.Type, where string) error {
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	for i, c := range n.Content {
		if err := checkKeys(file, c, t.Elem(), fmt.Sprintf("%s[%d]", where, i)); err != nil {
			return err
		}
	}
	return nil
}

// checkMapKeys rejects a key given twice. A map takes any key name, so a
// duplicate is the only thing wrong one can be.
func checkMapKeys(file string, n *yaml.Node, where string) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	seen := map[string]*yaml.Node{}
	for k := range pairs(n) {
		if err := markSeen(file, seen, k, where); err != nil {
			return err
		}
	}
	return nil
}

func prefix(where string) string {
	if where == "" {
		return ""
	}
	return where + ": "
}

func join(where, key string) string {
	if where == "" {
		return key
	}
	return where + "." + key
}

// yamlFields maps each yaml tag name of t to the field's type. An embedded
// struct tagged inline is flattened into its parent, as the decoder flattens it,
// so its keys are checked as though they were written on the parent.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if f.Anonymous && strings.Contains(opts, "inline") {
			maps.Copy(out, yamlFields(f.Type))
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

func sortedNames(m map[string]reflect.Type) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
