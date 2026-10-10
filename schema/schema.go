// Package schema generates the JSON Schemas for manifests and playbooks. They
// are documentation for editors, never the validator: the per-action field
// rules come from compile.Fields, the same table compile validates against,
// so the schema cannot accept a key the runtime rejects or the reverse.
package schema

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
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
	stepProps["mitre"] = map[string]any{"$ref": "#/$defs/Mitre", "description": "MITRE technique IDs every action in the step exhibits, on top of its own."}
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
			"enum": spec.ActionNames(),
		},
		"Mitre": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string", "pattern": compile.TechniquePattern},
			"minItems":    1,
			"uniqueItems": true,
			"description": "MITRE technique IDs (T1234 or T1234.001) the action exhibits. Annotation only: it changes no byte written. The shape is checked, not the MITRE catalogue.",
		},
	}
}

func objectSchemaFromStruct(v any, required []string) map[string]any {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]any{
		"type":                 "object",
		"properties":           structProperties(t),
		"additionalProperties": false,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// structProperties is the schema for every field a struct exposes. An embedded
// struct is flattened into its parent, as the decoders flatten it, so a type
// composed of another describes the same keys as the one it is built from.
func structProperties(t reflect.Type) map[string]any {
	props := map[string]any{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			maps.Copy(props, structProperties(f.Type))
			continue
		}
		if name, ok := jsonFieldName(f); ok {
			props[name] = typeToSchema(f.Type)
		}
	}
	return props
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
	}
	// An empty schema accepts anything, so a kind this does not understand
	// would silently stop constraining the field. Nothing in spec reaches here;
	// a type added that does should be handled rather than waved through.
	panic("schema: no schema for " + t.Kind().String() + " (" + t.String() + ")")
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
//
// Reflection gets the shape of each struct right but cannot see the constraints
// on its values, so each entry is registered and then refined.
func nestedDefs(defs map[string]any) {
	register(defs, "PeVersion", spec.PeVersion{})
	register(defs, "HistorySpec", spec.HistorySpec{})
	register(defs, "EditInsert", spec.EditInsert{}, "pattern", "text")
	register(defs, "Header", spec.Header{}, "name")

	register(defs, "PdfSpec", spec.PdfSpec{}).
		prop("created", rfc3339()).
		prop("modified", rfc3339()).
		prop("page_size", enumOf([]string{"A4", "A3", "A5", "Letter"}))

	register(defs, "DocxSpec", spec.DocxSpec{}).
		prop("created", rfc3339()).
		prop("modified", rfc3339())

	register(defs, "EmailSpec", spec.EmailSpec{}).
		prop("date", rfc3339())

	register(defs, "Attachment", spec.Attachment{}).
		prop("disposition", enumOf([]string{"attachment", "inline"})).
		oneOf("source_file", "source_root", "content")

	register(defs, "VaultSpec", spec.VaultSpec{}, "password").
		prop("salt", map[string]any{"type": "string", "pattern": "^[0-9a-fA-F]{64}$"})

	register(defs, "LnkSpec", spec.LnkSpec{}, "target").
		prop("target", map[string]any{
			"type":        "string",
			"pattern":     `^[A-Za-z]:\\`,
			"description": `The Windows path the link points at, on a drive letter: C:\Users\Public\tool.exe.`,
		}).
		prop("target_type", enumOf(compile.Types)).
		prop("show_command", enumOf(libgen.LNKShowCommands)).
		prop("drive_type", enumOf(libgen.LNKDriveTypes)).
		prop("volume_serial", map[string]any{"type": "string", "pattern": "^[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}$"}).
		prop("machine_id", map[string]any{"type": "string", "maxLength": libgen.MaxLNKMachineID}).
		prop("volume_label", map[string]any{"type": "string", "maxLength": 32}).
		prop("target_crtime", rfc3339()).
		prop("target_atime", rfc3339()).
		prop("target_mtime", rfc3339()).
		prop("target_size", nonNegative()).
		prop("target_attributes", map[string]any{"type": "array", "items": enumOf(libgen.LNKAttributes), "uniqueItems": true})

	register(defs, "PrefetchSpec", spec.PrefetchSpec{}, "executable").
		prop("executable", map[string]any{
			"type":        "string",
			"pattern":     `^[A-Za-z]:\\`,
			"description": `The Windows path of the program that ran: C:\Windows\System32\cmd.exe.`,
		}).
		prop("version", enumOf(libgen.PrefetchVersions)).
		prop("run_count", nonNegative()).
		prop("last_run_times", map[string]any{"type": "array", "items": rfc3339(), "maxItems": libgen.MaxPrefetchRuns, "uniqueItems": true}).
		prop("referenced_files", map[string]any{"type": "array", "items": map[string]any{"type": "string", "pattern": `^[A-Za-z]:\\`}}).
		prop("harddisk_volume", map[string]any{"type": "integer", "minimum": 0, "description": `The number N of the executable's volume, \Device\HarddiskVolumeN, which the prefetch hash is computed over; 3 by default.`})

	register(defs, "PrefetchVolume", spec.PrefetchVolume{}, "drive").
		prop("drive", map[string]any{"type": "string", "pattern": "^[A-Za-z]:?$"}).
		prop("serial", map[string]any{"type": "string", "pattern": "^[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}$"}).
		prop("created", rfc3339())

	register(defs, "EvtxSpec", spec.EvtxSpec{}, "events").
		prop("first_record_id", nonNegative()).
		prop("events", map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/EvtxEvent"}, "minItems": 1})

	builtins := make([]string, 0, len(libgen.EvtxBuiltinIDs))
	for _, id := range libgen.EvtxBuiltinIDs {
		builtins = append(builtins, strconv.Itoa(id))
	}
	register(defs, "EvtxEvent", spec.EvtxEvent{}, "event_id").
		prop("event_id", map[string]any{
			"type": "integer", "minimum": 0, "maximum": 0xFFFF,
			"description": "The event's id. Built in, with Windows' own provider, channel and data: " + strings.Join(builtins, ", ") + ".",
		}).
		prop("time", rfc3339()).
		prop("provider_guid", map[string]any{"type": "string", "pattern": "^\\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}?$"}).
		prop("version", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFF}).
		prop("level", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFF}).
		prop("task", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFFFF}).
		prop("opcode", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFF}).
		prop("process_id", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFF}).
		prop("thread_id", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFF}).
		prop("user_sid", map[string]any{"type": "string", "pattern": "^S-1-[0-9]+(-[0-9]+)*$"}).
		prop("data", map[string]any{
			"type":                 "object",
			"additionalProperties": map[string]any{"type": []string{"string", "number", "boolean"}},
			"description":          "The event's data values by name.",
		})

	register(defs, "RegistrySpec", spec.RegistrySpec{})
	register(defs, "RegistryKey", spec.RegistryKey{}, "path").
		prop("last_written", rfc3339())
	register(defs, "RegistryValue", spec.RegistryValue{}).
		prop("type", enumOf(libgen.RegTypes)).
		prop("data", map[string]any{
			"type":        []string{"string", "integer"},
			"description": "Text for REG_SZ and REG_EXPAND_SZ, a number for REG_DWORD and REG_QWORD, hex bytes for REG_BINARY and REG_NONE.",
		})
	register(defs, "RegistryRun", spec.RegistryRun{}, "name", "command")
	register(defs, "RegistryUserAssist", spec.RegistryUserAssist{}, "path").
		prop("run_count", nonNegative()).
		prop("focus_count", nonNegative()).
		prop("focus_time_ms", nonNegative()).
		prop("last_run", rfc3339())
	register(defs, "RegistryUSB", spec.RegistryUSB{}, "vendor", "product", "revision", "serial").
		prop("vendor", map[string]any{"type": "string", "minLength": 1, "maxLength": libgen.USBLimits[0]}).
		prop("product", map[string]any{"type": "string", "minLength": 1, "maxLength": libgen.USBLimits[1]}).
		prop("revision", map[string]any{"type": "string", "minLength": 1, "maxLength": libgen.USBLimits[2]}).
		prop("first_install", rfc3339()).
		prop("last_arrival", rfc3339()).
		prop("last_removal", rfc3339())

	register(defs, "UtmpSpec", spec.UtmpSpec{}, "records")
	register(defs, "UtmpRecord", spec.UtmpRecord{}, "type").
		prop("type", enumOf(libgen.UtmpKinds)).
		prop("user", map[string]any{"type": "string", "maxLength": 32}).
		prop("line", map[string]any{"type": "string", "maxLength": 32}).
		prop("host", map[string]any{"type": "string", "maxLength": 256}).
		prop("pid", map[string]any{"type": "integer", "minimum": 0, "maximum": 0x7FFFFFFF}).
		prop("session", map[string]any{"type": "integer", "minimum": 0, "maximum": 0x7FFFFFFF}).
		prop("time", rfc3339())
	register(defs, "AuditdSpec", spec.AuditdSpec{}, "events").
		prop("first_serial", nonNegative())
	register(defs, "AuditdEvent", spec.AuditdEvent{}, "type").
		prop("type", enumOf(libgen.AuditKinds)).
		prop("time", rfc3339()).
		prop("uid", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFF}).
		prop("auid", map[string]any{"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFF}).
		prop("exe", map[string]any{"type": "string", "pattern": "^/"})

	register(defs, "SlackSpec", spec.SlackSpec{}).
		prop("kind", enumOf(compile.SlackKinds)).
		prop("cluster_size", map[string]any{
			"type":        "integer",
			"enum":        []int{512, 1024, 2048, 4096, 8192, 16384, 32768, 65536},
			"description": "The cluster size the slack is planned for; 4096 by default. On a live volume it must be the volume's own.",
		})

	register(defs, "PeSpec", spec.PeSpec{}).
		prop("machine", enumOf(libgen.PEMachines)).
		prop("subsystem", enumOf(libgen.PESubsystems)).
		prop("timestamp", map[string]any{
			"type":        "string",
			"description": "RFC 3339, or \"0\" for the zero stamp a reproducible build writes. Defaults to the operation time.",
		}).
		prop("imports", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string", "pattern": "^[^!]+![^!]+$"},
			"description": "Imported functions as dll!function, for example kernel32.dll!CreateFileW.",
		})

	register(defs, "PeSection", spec.PeSection{}, "name").
		prop("name", map[string]any{"type": "string", "maxLength": libgen.MaxPESectionName}).
		prop("size", nonNegative()).
		prop("flags", map[string]any{"type": "array", "items": enumOf(libgen.PESectionFlags)})

	register(defs, "HistoryVisit", spec.HistoryVisit{}, "url").
		prop("time", rfc3339()).
		prop("transition", enumOf(libgen.Transitions)).
		prop("from_visit", nonNegative())

	register(defs, "HistoryDownload", spec.HistoryDownload{}, "url", "target_path").
		prop("start", rfc3339()).
		prop("end", rfc3339()).
		prop("received_bytes", nonNegative()).
		prop("total_bytes", nonNegative())

	register(defs, "ArchiveSpec", spec.ArchiveSpec{}).
		prop("method", map[string]any{
			"type":        "string",
			"enum":        compile.ArchiveMethods,
			"description": "store (the default) is byte-identical on every toolchain; deflate is not.",
		}).
		prop("comment", map[string]any{"type": "string", "maxLength": libgen.MaxZipComment}).
		anyOf("members", "member_refs")

	register(defs, "EditSpec", spec.EditSpec{}).
		prop("delete_lines", map[string]any{
			"type":        "string",
			"pattern":     "^[0-9]+(-[0-9]+)?$",
			"description": "A 1-based inclusive line or range of lines, for example 40-60.",
		}).
		anyOf("delete_lines", "delete_matching", "replace", "insert_after")

	register(defs, "EditReplace", spec.EditReplace{}, "pattern").
		prop("count", map[string]any{"type": "integer", "minimum": 0, "description": "0 means every match."})
}

// def is one $defs entry under construction: the schema, and the properties map
// inside it, so refining a property never has to assert its way back in.
type def struct {
	schema map[string]any
	props  map[string]any
}

// register generates a $defs entry from a struct and returns it for refining.
func register(defs map[string]any, name string, v any, required ...string) def {
	schema := objectSchemaFromStruct(v, required)
	defs[name] = schema
	return def{schema: schema, props: schema["properties"].(map[string]any)}
}

// prop replaces one property's schema, for a constraint reflection cannot see:
// a closed value set, a pattern, a bound, a shared definition.
func (d def) prop(name string, schema map[string]any) def {
	d.props[name] = schema
	return d
}

// oneOf requires exactly one of these keys to be given.
func (d def) oneOf(keys ...string) def {
	d.schema["oneOf"] = requireEach(keys)
	return d
}

// anyOf requires at least one of these keys to be given.
func (d def) anyOf(keys ...string) def {
	d.schema["anyOf"] = requireEach(keys)
	return d
}

// requireEach is one "required" clause per key, for a oneOf or an anyOf.
func requireEach(keys []string) []any {
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"required": []string{k}})
	}
	return out
}

// rfc3339 points at the shared RFC 3339 time definition, so every time field in
// the schema is described in one place.
func rfc3339() map[string]any {
	return map[string]any{"$ref": "#/$defs/Rfc3339Time"}
}

// enumOf is a string limited to a closed set of values.
func enumOf(values []string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}

// nonNegative is an integer that cannot go below zero.
func nonNegative() map[string]any {
	return map[string]any{"type": "integer", "minimum": 0}
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
	props["mitre"] = map[string]any{"$ref": "#/$defs/Mitre"}
}

func operationConditionals(playbook bool) []any {
	var out []any
	for _, action := range spec.Actions {
		then := map[string]any{
			"propertyNames": map[string]any{"enum": compile.AllowedFields(action, playbook)},
		}
		required := append([]string(nil), compile.Required[action]...)
		if slices.Contains(compile.Fields[action], "ref") {
			then["oneOf"] = targetChoices(action)
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
	seen := map[spec.Format]bool{}
	var out []string
	for _, action := range spec.Actions {
		for _, f := range compile.Formats[action] {
			if !seen[f] {
				seen[f] = true
				out = append(out, string(f))
			}
		}
	}
	return out
}

// targetChoices is the schema for "exactly one of path, ref and refs", listing
// only the ones this action takes.
func targetChoices(action spec.ActionName) []any {
	var out []any
	for _, t := range []string{"path", "ref", "refs"} {
		if slices.Contains(compile.Fields[action], t) {
			out = append(out, map[string]any{"required": []string{t}})
		}
	}
	return out
}
