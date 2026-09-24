package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/aoiflux/fsagen/compile"
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
			if want := compile.AllowedFields(action, tc.playbook); !reflect.DeepEqual(c.Then.PropertyNames.Enum, want) {
				t.Errorf("%s %s: schema allows %v, validator allows %v", tc.def, action, c.Then.PropertyNames.Enum, want)
			}
			for _, key := range c.Then.PropertyNames.Enum {
				if _, ok := def.Properties[key]; !ok {
					t.Errorf("%s %s: allowed key %q has no property schema", tc.def, action, key)
				}
			}
		}
		var missing []string
		for _, a := range compile.Actions {
			if !seen[a] {
				missing = append(missing, a)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: no field rules for %v", tc.def, missing)
		}
	}
}
