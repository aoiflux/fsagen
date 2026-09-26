// Package schema generates the JSON Schemas for manifests and playbooks. They
// are documentation for editors, never the validator: the per-action field
// rules come from compile.Fields, the same table compile validates against,
// so the schema cannot accept a key the runtime rejects or the reverse.
package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

const idBase = "https://raw.githubusercontent.com/aoiflux/fsagen/main/schemas/"

func BuildManifestSchema() ([]byte, error) {
	defs := baseDefs()
	nestedDefs(defs)

	operation := objectSchemaFromStruct(spec.Operation{}, []string{"action"})
	commonOperationProps(operation["properties"].(map[string]any))
	operation["allOf"] = operationConditionals(false)
	defs["Operation"] = operation

	root := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         idBase + "manifest-schema.json",
		"title":       "FSAGen Manifest Schema",
		"description": "Documents fsagen manifest input files. fsagen validates input itself; this schema mirrors those rules for editors.",
		"type":        "object",
		"properties": map[string]any{
			"start": map[string]any{
				"description": "Reference time for operations without an mtime (${DATE}, unpinned pdf and email dates): RFC 3339, or \"now\" for a run that cannot be reproduced.",
				"oneOf": []any{
					map[string]any{"const": "now"},
					map[string]any{"$ref": "#/$defs/Rfc3339Time"},
				},
			},
			"variables": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
			},
			"operations": map[string]any{
				"type":     "array",
				"items":    map[string]any{"$ref": "#/$defs/Operation"},
				"minItems": 1,
			},
		},
		"required":             []string{"operations"},
		"additionalProperties": false,
		"$defs":                defs,
	}
	return marshalSchema(root)
}

func BuildPlaybookSchema() ([]byte, error) {
	defs := baseDefs()
	defs["Condition"] = map[string]any{
		"type":        "string",
		"enum":        compile.Conditions,
		"description": "A step condition tests the iteration index; an action condition tests the batch index.",
	}
	defs["Template"] = map[string]any{"type": "string", "enum": compile.Templates}
	defs["Duration"] = map[string]any{
		"type":        "string",
		"description": "Go duration with day (d) and week (w) units, for example 15m, 2h, 2d6h.",
	}

	actor := objectSchemaFromStruct(spec.Actor{}, []string{"name"})
	defs["Actor"] = actor

	nestedDefs(defs)

	action := objectSchemaFromStruct(spec.Action{}, []string{"action"})
	actionProps := action["properties"].(map[string]any)
	commonOperationProps(actionProps)
	actionProps["template"] = map[string]any{"$ref": "#/$defs/Template"}
	actionProps["condition"] = map[string]any{"$ref": "#/$defs/Condition"}
	actionProps["offset"] = map[string]any{"$ref": "#/$defs/Duration"}
	action["allOf"] = operationConditionals(true)
	defs["Action"] = action

	step := objectSchemaFromStruct(spec.Step{}, []string{"actor", "actions"})
	stepProps := step["properties"].(map[string]any)
	stepProps["offset"] = map[string]any{"$ref": "#/$defs/Duration"}
	stepProps["every"] = map[string]any{"$ref": "#/$defs/Duration"}
	stepProps["condition"] = map[string]any{"$ref": "#/$defs/Condition"}
	stepProps["repeat"] = map[string]any{"type": "integer", "minimum": 1}
	stepProps["batch_count"] = map[string]any{"type": "integer", "minimum": 1}
	stepProps["actions"] = map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/Action"}, "minItems": 1}
	// repeat > 1 without every would stack every occurrence on one instant.
	step["allOf"] = []any{map[string]any{
		"if":   map[string]any{"properties": map[string]any{"repeat": map[string]any{"minimum": 2}}, "required": []string{"repeat"}},
		"then": map[string]any{"required": []string{"every"}},
	}}
	defs["Step"] = step

	root := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         idBase + "playbook-schema.json",
		"title":       "FSAGen Playbook Schema",
		"description": "Documents fsagen playbook input files. fsagen validates input itself; this schema mirrors those rules for editors.",
		"type":        "object",
		"properties": map[string]any{
			"start": map[string]any{
				"description": "RFC 3339 start of the scenario, or \"now\" for a run that cannot be reproduced.",
				"oneOf": []any{
					map[string]any{"const": "now"},
					map[string]any{"$ref": "#/$defs/Rfc3339Time"},
				},
			},
			"variables": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
			},
			"subsecond_jitter": map[string]any{
				"type":        "boolean",
				"description": "Add a seeded fraction of a second to every time derived from the schedule, never to an explicit one.",
			},
			"actors": map[string]any{
				"type":     "array",
				"items":    map[string]any{"$ref": "#/$defs/Actor"},
				"minItems": 1,
			},
			"steps": map[string]any{
				"type":     "array",
				"items":    map[string]any{"$ref": "#/$defs/Step"},
				"minItems": 1,
			},
		},
		"required":             []string{"start", "actors", "steps"},
		"additionalProperties": false,
		"$defs":                defs,
	}
	return marshalSchema(root)
}

func baseDefs() map[string]any {
	return map[string]any{
		"Rfc3339Time": map[string]any{
			"type":        "string",
			"description": "Timestamp in RFC 3339 format, fractional seconds allowed",
			"format":      "date-time",
		},
		"OperationAction": map[string]any{
			"type": "string",
			"enum": compile.Actions,
		},
	}
}

func objectSchemaFromStruct(v any, required []string) map[string]any {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	properties := map[string]any{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		jsonName, ok := jsonFieldName(f)
		if !ok {
			continue
		}
		properties[jsonName] = typeToSchema(f.Type)
	}
	out := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func typeToSchema(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Slice, reflect.Array:
		elem := t.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			return map[string]any{
				"type":  "array",
				"items": map[string]any{"$ref": fmt.Sprintf("#/$defs/%s", elem.Name())},
			}
		}
		return map[string]any{
			"type":  "array",
			"items": typeToSchema(elem),
		}
	case reflect.Map:
		if t.Key().Kind() == reflect.String {
			return map[string]any{
				"type":                 "object",
				"additionalProperties": typeToSchema(t.Elem()),
			}
		}
		return map[string]any{"type": "object"}
	case reflect.Struct:
		return map[string]any{"$ref": fmt.Sprintf("#/$defs/%s", t.Name())}
	default:
		return map[string]any{}
	}
}

func jsonFieldName(f reflect.StructField) (string, bool) {
	tag := f.Tag.Get("json")
	if tag == "" {
		return "", false
	}
	parts := strings.Split(tag, ",")
	name := strings.TrimSpace(parts[0])
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}

func marshalSchema(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// nestedDefs registers the schemas for the structs that Operation and Action
// reference by pointer. typeToSchema emits a $ref for each, so every one needs
// a matching entry in $defs.
func nestedDefs(defs map[string]any) {
	defs["PdfSpec"] = objectSchemaFromStruct(spec.PdfSpec{}, nil)
	defs["DocxSpec"] = objectSchemaFromStruct(spec.DocxSpec{}, nil)
	defs["PeSpec"] = objectSchemaFromStruct(spec.PeSpec{}, nil)
	defs["PeSection"] = objectSchemaFromStruct(spec.PeSection{}, []string{"name"})
	defs["PeVersion"] = objectSchemaFromStruct(spec.PeVersion{}, nil)
	defs["HistorySpec"] = objectSchemaFromStruct(spec.HistorySpec{}, nil)
	defs["HistoryVisit"] = objectSchemaFromStruct(spec.HistoryVisit{}, []string{"url"})
	defs["HistoryDownload"] = objectSchemaFromStruct(spec.HistoryDownload{}, []string{"url", "target_path"})
	defs["ArchiveSpec"] = objectSchemaFromStruct(spec.ArchiveSpec{}, nil)
	defs["EditSpec"] = objectSchemaFromStruct(spec.EditSpec{}, nil)
	defs["EditReplace"] = objectSchemaFromStruct(spec.EditReplace{}, []string{"pattern"})
	defs["EditInsert"] = objectSchemaFromStruct(spec.EditInsert{}, []string{"pattern", "text"})
	defs["Header"] = objectSchemaFromStruct(spec.Header{}, []string{"name"})
	defs["Attachment"] = objectSchemaFromStruct(spec.Attachment{}, nil)
	defs["EmailSpec"] = objectSchemaFromStruct(spec.EmailSpec{}, nil)
	defs["VaultSpec"] = objectSchemaFromStruct(spec.VaultSpec{}, []string{"password"})

	pdf := defs["PdfSpec"].(map[string]any)["properties"].(map[string]any)
	pdf["created"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	pdf["modified"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	pdf["page_size"] = map[string]any{"type": "string", "enum": []string{"A4", "A3", "A5", "Letter"}}

	em := defs["EmailSpec"].(map[string]any)["properties"].(map[string]any)
	em["date"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}

	att := defs["Attachment"].(map[string]any)
	attProps := att["properties"].(map[string]any)
	attProps["disposition"] = map[string]any{"type": "string", "enum": []string{"attachment", "inline"}}
	att["oneOf"] = []any{
		map[string]any{"required": []string{"source_file"}},
		map[string]any{"required": []string{"source_root"}},
		map[string]any{"required": []string{"content"}},
	}
	vault := defs["VaultSpec"].(map[string]any)["properties"].(map[string]any)
	vault["salt"] = map[string]any{"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}

	doc := defs["DocxSpec"].(map[string]any)["properties"].(map[string]any)
	doc["created"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	doc["modified"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}

	pe := defs["PeSpec"].(map[string]any)["properties"].(map[string]any)
	pe["machine"] = map[string]any{"type": "string", "enum": libgen.PEMachines}
	pe["subsystem"] = map[string]any{"type": "string", "enum": libgen.PESubsystems}
	pe["timestamp"] = map[string]any{
		"type":        "string",
		"description": "RFC 3339, or \"0\" for the zero stamp a reproducible build writes. Defaults to the operation time.",
	}
	pe["imports"] = map[string]any{
		"type":        "array",
		"items":       map[string]any{"type": "string", "pattern": "^[^!]+![^!]+$"},
		"description": "Imported functions as dll!function, for example kernel32.dll!CreateFileW.",
	}
	sec := defs["PeSection"].(map[string]any)["properties"].(map[string]any)
	sec["name"] = map[string]any{"type": "string", "maxLength": 8}
	sec["size"] = map[string]any{"type": "integer", "minimum": 0}
	sec["flags"] = map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": libgen.PESectionFlags}}

	visit := defs["HistoryVisit"].(map[string]any)["properties"].(map[string]any)
	visit["time"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	visit["transition"] = map[string]any{"type": "string", "enum": libgen.Transitions}
	visit["from_visit"] = map[string]any{"type": "integer", "minimum": 0}
	down := defs["HistoryDownload"].(map[string]any)["properties"].(map[string]any)
	down["start"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	down["end"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	down["received_bytes"] = map[string]any{"type": "integer", "minimum": 0}
	down["total_bytes"] = map[string]any{"type": "integer", "minimum": 0}

	arc := defs["ArchiveSpec"].(map[string]any)
	arcProps := arc["properties"].(map[string]any)
	arcProps["method"] = map[string]any{
		"type":        "string",
		"enum":        compile.ArchiveMethods,
		"description": "store (the default) is byte-identical on every toolchain; deflate is not.",
	}
	arcProps["comment"] = map[string]any{"type": "string", "maxLength": 65535}
	arc["anyOf"] = []any{
		map[string]any{"required": []string{"members"}},
		map[string]any{"required": []string{"member_refs"}},
	}

	ed := defs["EditSpec"].(map[string]any)
	edProps := ed["properties"].(map[string]any)
	edProps["delete_lines"] = map[string]any{
		"type":        "string",
		"pattern":     "^[0-9]+(-[0-9]+)?$",
		"description": "A 1-based inclusive line or range of lines, for example 40-60.",
	}
	ed["anyOf"] = []any{
		map[string]any{"required": []string{"delete_lines"}},
		map[string]any{"required": []string{"delete_matching"}},
		map[string]any{"required": []string{"replace"}},
		map[string]any{"required": []string{"insert_after"}},
	}
	defs["EditReplace"].(map[string]any)["properties"].(map[string]any)["count"] =
		map[string]any{"type": "integer", "minimum": 0, "description": "0 means every match."}
}

// commonOperationProps applies the value constraints shared by manifest
// operations and playbook actions.
func commonOperationProps(props map[string]any) {
	props["action"] = map[string]any{"$ref": "#/$defs/OperationAction"}
	props["type"] = map[string]any{"type": "string", "enum": compile.Types}
	props["atime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	props["mtime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	props["ctime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time", "description": "Metadata change time. Windows on NTFS or ReFS only; elsewhere a pre-flight error unless --on-unsupported=skip."}
	props["crtime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time", "description": "Creation (birth) time. Windows only; elsewhere a pre-flight error unless --on-unsupported=skip."}
	props["zone_id"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 4}
	props["content_len"] = map[string]any{"type": "integer", "minimum": 1}
	props["format"] = map[string]any{"type": "string", "enum": allFormats()}
	props["content_kind"] = map[string]any{
		"type":        "string",
		"enum":        compile.ContentKinds,
		"description": "What the invented bytes look like. Only applies when fsagen invents them.",
	}
	props["mode"] = map[string]any{
		"type":        "string",
		"pattern":     "^0?[0-7]{3,4}$",
		"description": "Octal file permissions, for example 0600",
	}
	props["ext"] = map[string]any{"type": "string", "pattern": `^\.[^/\\:]+$`}
	props["id"] = map[string]any{"type": "string", "description": "Names what this action creates or renames, for later ref/refs."}
	props["ref"] = map[string]any{"type": "string", "description": "Instead of path: the one live path created under this id."}
	props["refs"] = map[string]any{"type": "string", "description": "Instead of path: every live path created under this id."}
	props["missing_ok"] = map[string]any{"type": "boolean", "description": "delete: a missing path is a recorded no-op."}
}

// operationConditionals expresses the field matrix: per action, which keys
// may appear, which are required, and which values format takes.
func operationConditionals(playbook bool) []any {
	var out []any
	for _, action := range compile.Actions {
		then := map[string]any{
			"propertyNames": map[string]any{"enum": compile.AllowedFields(action, playbook)},
		}
		required := append([]string(nil), compile.Required[action]...)
		if contains(compile.Fields[action], "ref") {
			var targets []any
			for _, t := range []string{"path", "ref", "refs"} {
				if contains(compile.Fields[action], t) {
					targets = append(targets, map[string]any{"required": []string{t}})
				}
			}
			then["oneOf"] = targets
		} else {
			required = append(required, "path")
		}
		if len(required) > 0 {
			then["required"] = required
		}
		if formats, ok := compile.Formats[action]; ok {
			then["properties"] = map[string]any{"format": map[string]any{"enum": formats}}
		}
		if action == "mace" {
			var anyTime []any
			for _, f := range compile.TimeFields {
				anyTime = append(anyTime, map[string]any{"required": []string{f}})
			}
			then["anyOf"] = anyTime
		}
		out = append(out, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"action": map[string]any{"const": action}},
				"required":   []string{"action"},
			},
			"then": then,
		})
	}
	// Two ways to say the same thing, or a template that would silently
	// replace explicit content, are refused.
	for _, pair := range [][]string{{"content", "content_file"}, {"template", "content"}, {"template", "content_file"}, {"content_len", "content"}} {
		if !playbook && pair[0] == "template" {
			continue
		}
		out = append(out, map[string]any{"not": map[string]any{"required": pair}})
	}
	return out
}

// allFormats is every format value any action accepts, for the property
// schema; the per-action allOf narrows it to the ones that action takes.
func allFormats() []string {
	seen := map[string]bool{}
	var out []string
	for _, action := range compile.Actions {
		for _, f := range compile.Formats[action] {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
