package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/constant"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/spec"
	timelinepkg "github.com/aoiflux/fsagen/timeline"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/fsagen/volume/container"
	imagepkg "github.com/aoiflux/fsagen/volume/image"
)

// featuresCmd names the subcommand that lists what this build can do; an
// output directory of that name is written ./features.
const featuresCmd = "features"

// behaviours are what this build does that no field, format or option
// names, each named once and for good. A consumer tests for one rather
// than for the version that brought it.
var behaviours = []string{
	// A scheduled mace or timestomp moves the change time to when it ran.
	"model.stomp_changes_ctime",
}

// features lists what this build can do, by names that stay as they are
// from one release to the next; a name removed is a breaking change. They
// come from the tables the build itself checks its input against, so the
// list cannot claim what the build would refuse.
//
//	action:NAME            an action a manifest or playbook may take
//	field:PATH             a key of an action, nested keys joined by dots
//	                       (field:history.visits.redirect)
//	format:NAME            a value of format: (chrome_cookies, eml, ...)
//	content_kind:KIND      a value of content_kind:
//	archive.method:M       a value of archive.method:
//	playbook:PATH          a key of a playbook, outside its actions
//	manifest:PATH          a key of a manifest, outside its operations
//	image.fs:FS            --image-fs FS
//	image.format:F         an image file format (raw, vhd)
//	image.partition:P      --partition P
//	image.alloc:A          --alloc A
//	image.ntfs.usn_journal an NTFS image's change journal (--no-usn-journal)
//	timeline.format:F      --timeline-format F
//	timeline.source:S      --timeline-source S
//	command:NAME           a subcommand
//	model.NAME, ...        a behaviour (see behaviours)
func features() []string {
	set := map[string]bool{}
	add := func(prefix string, names ...string) {
		for _, n := range names {
			set[prefix+n] = true
		}
	}
	for action, keys := range compile.Fields {
		add("action:", string(action))
		add("field:", keys...)
	}
	add("field:", "mitre")
	walkFields(reflect.TypeFor[spec.Operation](), "", func(p string) { set["field:"+p] = true })
	walkFields(reflect.TypeFor[spec.Playbook](), "", func(p string) { set["playbook:"+p] = true })
	walkFields(reflect.TypeFor[spec.Manifest](), "", func(p string) { set["manifest:"+p] = true })
	for _, formats := range compile.Formats {
		for _, f := range formats {
			add("format:", string(f))
		}
	}
	add("content_kind:", compile.ContentKinds...)
	add("archive.method:", compile.ArchiveMethods...)
	add("image.fs:", imagepkg.FileSystems...)
	add("image.format:", slices.Collect(maps.Values(container.Extensions))...)
	add("image.partition:", container.Partitions...)
	add("image.alloc:", volume.Policies...)
	add("", "image.ntfs.usn_journal")
	add("timeline.format:", timelinepkg.Formats...)
	add("timeline.source:", timelinepkg.SourceObserved, timelinepkg.SourceModelled)
	add("command:", diffOracle, featuresCmd)
	add("", behaviours...)
	return slices.Sorted(maps.Keys(set))
}

// walkFields calls fn with the dotted YAML path of every key of t and of
// the structures under it; a list's items add nothing to the path. The
// operations of a manifest and the actions of a playbook are left out, as
// they are listed as fields.
func walkFields(t reflect.Type, prefix string, fn func(string)) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for f := range t.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch {
		case name == "-":
			continue
		case opts == "inline":
			if f.Type != reflect.TypeFor[spec.Operation]() {
				walkFields(f.Type, prefix, fn)
			}
			continue
		case name == "" || !f.IsExported():
			continue
		}
		p := prefix + name
		fn(p)
		if el := f.Type; el.Kind() == reflect.Slice && el.Elem() == reflect.TypeFor[spec.Operation]() {
			continue
		}
		walkFields(f.Type, p+".", fn)
	}
}

// runFeatures prints the features, one a line, or with --json as an object
// that also gives the build's version and generator version.
func runFeatures(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet(featuresCmd, flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	asJSON := fl.Bool("json", false, "print a JSON object")
	if err := fl.Parse(args); err != nil || fl.NArg() > 0 {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "usage: fsagen features [--json]\n\nList what this build can do, one stable name a line: actions, fields,\nformats, image and timeline options and behaviours. --json prints an object\nwith the version and generator version as well.")
			return exitOK
		}
		fmt.Fprintln(stderr, "fsagen features: usage: fsagen features [--json]")
		return exitUsage
	}
	list := features()
	if !*asJSON {
		for _, f := range list {
			fmt.Fprintln(stdout, f)
		}
		return exitOK
	}
	module, _, _ := runinfo.Build()
	out, err := json.MarshalIndent(struct {
		Version          string   `json:"version"`
		GeneratorVersion int      `json:"generator_version"`
		Features         []string `json:"features"`
	}{module, constant.GeneratorVersion, list}, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "fsagen features: %v\n", err)
		return exitRuntime
	}
	fmt.Fprintf(stdout, "%s\n", out)
	return exitOK
}
