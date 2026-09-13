package schema

import (
	"encoding/json"
	"fmt"
	"fsagen/spec"
	"reflect"
	"strings"
)

func BuildManifestSchema() ([]byte, error) {
	defs := map[string]any{
		"Rfc3339Time": map[string]any{
			"type":        "string",
			"description": "Timestamp in RFC3339 format",
			"format":      "date-time",
		},
		"OperationAction": map[string]any{
			"type": "string",
			"enum": []string{"create", "update", "append", "delete", "mace", "rename", "copy", "truncate", "rotate", "ads", "motw", "email", "ansible-vault"},
		},
	}

	nestedDefs(defs)

	operation := objectSchemaFromStruct(spec.Operation{}, nil)
	commonOperationProps(operation["properties"].(map[string]any))
	operation["required"] = []string{"action", "path"}
	operation["allOf"] = operationConditionals()
	defs["Operation"] = operation

	root := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://generator.local/manifest-schema.json",
		"title":       "FSAGen Manifest Schema",
		"description": "Validates fsagen manifest input files.",
		"type":        "object",
		"properties": map[string]any{
			"variables": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
			},
			"operations": map[string]any{
				"type":  "array",
				"items": map[string]any{"$ref": "#/$defs/Operation"},
			},
		},
		"required":             []string{"operations"},
		"additionalProperties": false,
		"$defs":                defs,
	}

	return marshalSchema(root)
}

func BuildPlaybookSchema() ([]byte, error) {
	defs := map[string]any{
		"Rfc3339Time": map[string]any{
			"type":        "string",
			"description": "Timestamp in RFC3339 format",
			"format":      "date-time",
		},
		"Condition": map[string]any{
			"type": "string",
			"enum": []string{"", "odd", "even", "first", "last"},
		},
		"OperationAction": map[string]any{
			"type": "string",
			"enum": []string{"create", "update", "append", "delete", "mace", "rename", "copy", "truncate", "rotate", "ads", "motw", "email", "ansible-vault"},
		},
		"Template": map[string]any{
			"type": "string",
			"enum": []string{"email", "log", "script", "doc"},
		},
	}

	actor := objectSchemaFromStruct(spec.Actor{}, []string{"name"})
	defs["Actor"] = actor

	nestedDefs(defs)

	action := objectSchemaFromStruct(spec.Action{}, []string{"action", "path"})
	actionProps := action["properties"].(map[string]any)
	commonOperationProps(actionProps)
	actionProps["template"] = map[string]any{"$ref": "#/$defs/Template"}
	actionProps["condition"] = map[string]any{"$ref": "#/$defs/Condition"}
	actionProps["offset"] = map[string]any{"type": "string", "description": "Go duration string (for example: 15m, 2h, 30s)"}
	action["allOf"] = operationConditionals()
	defs["Action"] = action

	step := objectSchemaFromStruct(spec.Step{}, []string{"actor", "actions"})
	stepProps := step["properties"].(map[string]any)
	stepProps["offset"] = map[string]any{"type": "string", "description": "Go duration string"}
	stepProps["every"] = map[string]any{"type": "string", "description": "Go duration string"}
	stepProps["condition"] = map[string]any{"$ref": "#/$defs/Condition"}
	stepProps["repeat"] = map[string]any{"type": "integer", "minimum": 1}
	stepProps["batch_count"] = map[string]any{"type": "integer", "minimum": 1}
	defs["Step"] = step

	root := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://generator.local/playbook-schema.json",
		"title":       "FSAGen Playbook Schema",
		"description": "Validates fsagen playbook input files.",
		"type":        "object",
		"properties": map[string]any{
			"start": map[string]any{
				"oneOf": []any{
					map[string]any{"const": "now"},
					map[string]any{"$ref": "#/$defs/Rfc3339Time"},
				},
			},
			"variables": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
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
		"required":             []string{"actors", "steps"},
		"additionalProperties": false,
		"$defs":                defs,
	}

	return marshalSchema(root)
}

func conditionalRequire(fieldName string, fieldValue string, requiredField string) map[string]any {
	return map[string]any{
		"if": map[string]any{
			"properties": map[string]any{fieldName: map[string]any{"const": fieldValue}},
			"required":   []string{fieldName},
		},
		"then": map[string]any{
			"required": []string{requiredField},
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

	att := defs["Attachment"].(map[string]any)["properties"].(map[string]any)
	att["disposition"] = map[string]any{"type": "string", "enum": []string{"attachment", "inline"}}
}

// commonOperationProps applies the constraints shared by manifest Operations
// and playbook Actions.
func commonOperationProps(props map[string]any) {
	props["action"] = map[string]any{"$ref": "#/$defs/OperationAction"}
	props["type"] = map[string]any{"type": "string", "enum": []string{"file", "dir"}}
	props["atime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	props["mtime"] = map[string]any{"$ref": "#/$defs/Rfc3339Time"}
	props["zone_id"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 4}
	props["format"] = map[string]any{"type": "string", "enum": []string{"raw", "text", "pdf", "eml", "mbox"}}
	props["mode"] = map[string]any{
		"type":        "string",
		"pattern":     "^0?[0-7]{3,4}$",
		"description": "Octal file permissions, for example 0600",
	}
}

// operationConditionals lists the per-action required fields.
func operationConditionals() []any {
	return []any{
		conditionalRequire("action", "rename", "new_path"),
		conditionalRequire("action", "rotate", "new_path"),
		conditionalRequire("action", "copy", "new_path"),
		conditionalRequire("action", "ads", "stream"),
		conditionalRequire("action", "email", "email"),
		conditionalRequire("action", "ansible-vault", "vault"),
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"action": map[string]any{"const": "motw"}},
				"required":   []string{"action"},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"zone_id": map[string]any{"type": "integer", "minimum": 0, "maximum": 4},
				},
			},
		},
		// content and content_file are two ways to say the same thing.
		map[string]any{
			"not": map[string]any{"required": []string{"content", "content_file"}},
		},
	}
}
