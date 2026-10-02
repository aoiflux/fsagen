package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/spec"
)

// The checked-in schemas must be exactly what the generator produces, so a
// field added to the spec or the field matrix cannot leave them stale.
func TestSchemaDrift(t *testing.T) {
	for name, build := range map[string]func() ([]byte, error){
		"manifest-schema.json": BuildManifestSchema,
		"playbook-schema.json": BuildPlaybookSchema,
	} {
		got, err := build()
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("..", "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
			t.Errorf("schemas/%s is stale; regenerate with: fsagen --generate-schema", name)
		}
	}
}

// Each action's allowed keys in the schema are exactly the validator's.
func TestSchemaAllowsExactlyTheFieldMatrix(t *testing.T) {
	for _, tc := range []struct {
		build    func() ([]byte, error)
		def      string
		playbook bool
	}{
		{BuildManifestSchema, "Operation", false},
		{BuildPlaybookSchema, "Action", true},
	} {
		raw, err := tc.build()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Defs map[string]struct {
				Properties map[string]any `json:"properties"`
				AllOf      []struct {
					If struct {
						Properties struct {
							Action struct {
								Const string `json:"const"`
							} `json:"action"`
						} `json:"properties"`
					} `json:"if"`
					Then struct {
						PropertyNames struct {
							Enum []string `json:"enum"`
						} `json:"propertyNames"`
					} `json:"then"`
				} `json:"allOf"`
			} `json:"$defs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		def := doc.Defs[tc.def]
		seen := map[string]bool{}
		for _, c := range def.AllOf {
			action := c.If.Properties.Action.Const
			if action == "" {
				continue
			}
			seen[action] = true
			if want := compile.AllowedFields(spec.ActionName(action), tc.playbook); !reflect.DeepEqual(c.Then.PropertyNames.Enum, want) {
				t.Errorf("%s %s: schema allows %v, validator allows %v", tc.def, action, c.Then.PropertyNames.Enum, want)
			}
			for _, key := range c.Then.PropertyNames.Enum {
				if _, ok := def.Properties[key]; !ok {
					t.Errorf("%s %s: allowed key %q has no property schema", tc.def, action, key)
				}
			}
		}
		var missing []string
		for _, a := range spec.Actions {
			if !seen[string(a)] {
				missing = append(missing, string(a))
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: no field rules for %v", tc.def, missing)
		}
	}
}

// The top-level keys the schema allows are exactly the fields of the Go type
// the input decodes into (the root schemas are written by hand).
func TestSchemaRootKeysMatchSpec(t *testing.T) {
	for _, tc := range []struct {
		build func() ([]byte, error)
		typ   reflect.Type
	}{
		{BuildManifestSchema, reflect.TypeOf(spec.Manifest{})},
		{BuildPlaybookSchema, reflect.TypeOf(spec.Playbook{})},
	} {
		raw, err := tc.build()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		var got, want []string
		for k := range doc.Properties {
			got = append(got, k)
		}
		for i := 0; i < tc.typ.NumField(); i++ {
			name, _, _ := strings.Cut(tc.typ.Field(i).Tag.Get("yaml"), ",")
			want = append(want, name)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: schema root keys %v, spec fields %v", tc.typ.Name(), got, want)
		}
	}
}

// TestNestedDefsRefineRealFields: nestedDefs generates each $defs entry from a
// struct and then refines individual properties by name. def.prop writes the
// name it is given whether or not the struct has a field for it, so a renamed
// or misspelled field would publish a property the tool ignores and drop the
// constraint that was meant to be added — silently, where the hand-written
// chains of type assertions it replaced at least panicked. Every refined name
// is therefore checked back against reflection, and the table below against the
// generated defs, so a definition added without a table entry fails rather
// than going unchecked.
func TestNestedDefsRefineRealFields(t *testing.T) {
	structs := map[string]any{
		"PeVersion":       spec.PeVersion{},
		"HistorySpec":     spec.HistorySpec{},
		"EditInsert":      spec.EditInsert{},
		"Header":          spec.Header{},
		"PdfSpec":         spec.PdfSpec{},
		"DocxSpec":        spec.DocxSpec{},
		"EmailSpec":       spec.EmailSpec{},
		"Attachment":      spec.Attachment{},
		"VaultSpec":       spec.VaultSpec{},
		"PeSpec":          spec.PeSpec{},
		"PeSection":       spec.PeSection{},
		"HistoryVisit":    spec.HistoryVisit{},
		"HistoryDownload": spec.HistoryDownload{},
		"ArchiveSpec":     spec.ArchiveSpec{},
		"EditSpec":        spec.EditSpec{},
		"EditReplace":     spec.EditReplace{},
	}

	defs := map[string]any{}
	nestedDefs(defs)

	for name := range defs {
		if _, ok := structs[name]; !ok {
			t.Errorf("$defs.%s is not in this test's table, so nothing checks its properties", name)
		}
	}

	for name, v := range structs {
		entry, ok := defs[name]
		if !ok {
			t.Errorf("nestedDefs registered no $defs.%s", name)
			continue
		}
		got := propertiesOf(t, name, entry)
		want := propertiesOf(t, name, objectSchemaFromStruct(v, nil))
		for prop := range got {
			if _, ok := want[prop]; !ok {
				t.Errorf("$defs.%s has property %q, which %T has no field for", name, prop, v)
			}
		}
		for prop := range want {
			if _, ok := got[prop]; !ok {
				t.Errorf("$defs.%s is missing property %q, which %T has a field for", name, prop, v)
			}
		}
	}
}

// propertiesOf is the properties map of a $defs entry, or a failure saying
// which entry was not the object the rest of the test assumes.
func propertiesOf(t *testing.T, name string, entry any) map[string]any {
	t.Helper()
	schema, ok := entry.(map[string]any)
	if !ok {
		t.Fatalf("$defs.%s is %T, want an object", name, entry)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("$defs.%s has no properties object", name)
	}
	return props
}
