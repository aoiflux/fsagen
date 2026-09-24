package compile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// keys maps each YAML key present on a mapping to its key node, which gives
// both presence (a zero value and an absent key differ) and position.
type keys map[string]*yaml.Node

func (k keys) has(name string) bool { return k[name] != nil }

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

// mappingKeys lists a mapping's keys, including those brought in by "<<"
// merge keys (explicit keys win, as they do when decoding).
func mappingKeys(n *yaml.Node) keys {
	out := keys{}
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	var merged []keys
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "<<" {
			for _, src := range mergeSources(v) {
				merged = append(merged, mappingKeys(src))
			}
			continue
		}
		out[k.Value] = k
	}
	for _, m := range merged {
		for name, k := range m {
			if _, ok := out[name]; !ok {
				out[name] = k
			}
		}
	}
	return out
}

// mappingValue returns the value node for key, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return resolve(n.Content[i+1])
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "<<" {
			for _, src := range mergeSources(n.Content[i+1]) {
				if v := mappingValue(src, key); v != nil {
					return v
				}
			}
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
		if n.Kind != yaml.MappingNode {
			return nil // the decoder reports the type mismatch with its position
		}
		fields := yamlFields(t)
		seen := map[string]*yaml.Node{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "<<" {
				for _, src := range mergeSources(v) {
					if err := checkKeys(file, src, t, where); err != nil {
						return err
					}
				}
				continue
			}
			if prev, dup := seen[k.Value]; dup {
				return fmt.Errorf("%s:%d:%d: %sduplicate key %q (first given at line %d)", file, k.Line, k.Column, prefix(where), k.Value, prev.Line)
			}
			seen[k.Value] = k
			ft, ok := fields[k.Value]
			if !ok {
				return fmt.Errorf("%s:%d:%d: %sunknown field %q; valid fields: %s", file, k.Line, k.Column, prefix(where), k.Value, strings.Join(sortedNames(fields), ", "))
			}
			if err := checkKeys(file, v, ft, join(where, k.Value)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return nil
		}
		for i, c := range n.Content {
			if err := checkKeys(file, c, t.Elem(), fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return nil
		}
		seen := map[string]*yaml.Node{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if prev, dup := seen[k.Value]; dup {
				return fmt.Errorf("%s:%d:%d: %sduplicate key %q (first given at line %d)", file, k.Line, k.Column, prefix(where), k.Value, prev.Line)
			}
			seen[k.Value] = k
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

// yamlFields maps each yaml tag name of t to the field's type.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
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
