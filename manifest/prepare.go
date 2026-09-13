package manifest

import (
	"fmt"
	"fsagen/render"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// contentFieldName is handled explicitly rather than by the reflective walk,
// because whether it gets templated depends on where it came from.
const contentFieldName = "Content"

// PrepareOperation resolves an operation into a form the executor can run
// directly: every ${...} token substituted, and content_file loaded from disk.
//
// baseDir is the directory holding the manifest or playbook, so content_file
// paths are relative to the YAML that names them rather than to the process
// working directory.
//
// Templating of the content body defaults differently depending on its source.
// Inline content: templated, matching existing manifest and playbook behaviour.
// content_file: NOT templated, because shell scripts, PEM keys and source code
// routinely contain ${...} sequences of their own that must survive verbatim.
// An explicit render: true or render: false overrides either default.
func PrepareOperation(op Operation, baseDir string, rctx render.Context) (Operation, error) {
	renderStringFields(reflect.ValueOf(&op).Elem(), rctx)

	renderContent := op.ContentFile == ""
	if op.Render != nil {
		renderContent = *op.Render
	}

	if op.ContentFile != "" {
		if strings.TrimSpace(op.Content) != "" {
			return op, fmt.Errorf("content and content_file are mutually exclusive")
		}
		data, err := os.ReadFile(resolveSource(baseDir, op.ContentFile))
		if err != nil {
			return op, fmt.Errorf("content_file: %w", err)
		}
		op.Content = string(data)
	}

	if renderContent {
		op.Content = render.Apply(op.Content, rctx)
		for i := range attachmentsOf(&op) {
			a := &attachmentsOf(&op)[i]
			a.Content = render.Apply(a.Content, rctx)
		}
	}

	op.ContentFile = ""
	return op, nil
}

func attachmentsOf(op *Operation) []Attachment {
	if op.Email == nil {
		return nil
	}
	return op.Email.Attachments
}

// renderStringFields walks the operation and templates every string and
// []string it finds, skipping content bodies. Reflection keeps the new nested
// specs (pdf, email, vault) from each needing their own hand-written pass.
func renderStringFields(v reflect.Value, rctx render.Context) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			renderStringFields(v.Elem(), rctx)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).Name == contentFieldName {
				continue
			}
			if !v.Field(i).CanSet() {
				continue
			}
			renderStringFields(v.Field(i), rctx)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			renderStringFields(v.Index(i), rctx)
		}
	case reflect.Map:
		// Variable maps are the source of substitution, not a target of it.
	case reflect.String:
		if s := v.String(); s != "" {
			v.SetString(render.Apply(s, rctx))
		}
	}
}

// resolveSource interprets a path from a YAML file. Absolute paths are taken
// as-is; everything else is relative to the YAML file's own directory.
func resolveSource(baseDir, p string) string {
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) || baseDir == "" {
		return p
	}
	return filepath.Join(baseDir, p)
}
