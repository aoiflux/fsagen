package compile

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// checkRecycle validates a recycle block against what a $I file can record.
func checkRecycle(op *Op, at func(string, string, ...any)) {
	r := op.Recycle
	switch {
	case strings.TrimSpace(r.OriginalPath) == "":
		at("recycle", `original_path is required: the Windows path the file had before it was deleted, for example C:\Users\user1\Documents\report.docx`)
	case libgen.CheckWindowsPath(r.OriginalPath) != nil:
		at("recycle", "original_path: %v", libgen.CheckWindowsPath(r.OriginalPath))
	case len(strings.TrimSuffix(r.OriginalPath, `\`)) <= 2:
		at("recycle", "original_path %q is a drive's root, not a file", r.OriginalPath)
	}
	if r.Size < 0 {
		at("recycle", "size %d is negative", r.Size)
	}
	if r.Version != "" && !slices.Contains(libgen.RecycleVersions, r.Version) {
		at("recycle", "version %q (want one of: %s)", r.Version, strings.Join(libgen.RecycleVersions, ", "))
	}
	checkFiletimeField(at, "recycle", field{"deleted", r.Deleted})
}

// reRecycleIndex is the name Windows gives a $I file: $I, six characters,
// then the deleted file's own extension.
var reRecycleIndex = regexp.MustCompile(`(?i)^\$I[0-9A-Z]{6}(\..*)?$`)

// checkRecycleName refuses a $I file that Windows could not have named: it
// starts $I, then six characters, then the original file's extension, which
// RBCmd and Autopsy pair it with its $R file by.
func checkRecycleName(op *Op, r reporter) {
	rec := op.Recycle
	if op.Format != spec.FormatRecycleBin || rec == nil || op.Path == "" {
		return
	}
	base := path.Base(op.Path)
	m := reRecycleIndex.FindStringSubmatch(base)
	if m == nil {
		r.at("path", "%s is not named as Windows names a Recycle Bin index file: $I, six letters or digits, then the deleted file's extension (for example $IA1B2C3.docx)", base)
		return
	}
	orig := rec.OriginalPath[strings.LastIndexByte(rec.OriginalPath, '\\')+1:]
	if want := path.Ext(orig); !strings.EqualFold(m[1], want) {
		r.at("path", "%s has extension %q, but the deleted file %s has %q; Windows keeps the original's", base, m[1], orig, want)
	}
}

// WipePatterns are what a wipe overwrites the content with.
var WipePatterns = []string{"zeros", "random"}

// MaxWipeRenames is how many renames a wipe can make: one per letter, A to Z.
const MaxWipeRenames = 26

func checkWipe(op *Op, at func(string, string, ...any)) {
	w := op.Wipe
	if w.Pattern != "" && !slices.Contains(WipePatterns, w.Pattern) {
		at("wipe", "pattern %q (want one of: %s)", w.Pattern, strings.Join(WipePatterns, ", "))
	}
	if w.Renames != nil && (*w.Renames < 0 || *w.Renames > MaxWipeRenames) {
		at("wipe", "renames %d (want 0 to %d, one per letter A to Z)", *w.Renames, MaxWipeRenames)
	}
}

// WipeNames are the names a wipe of a file called base renames it through,
// in order, as SDelete does: every character but a dot replaced by A, then by
// B, and so on. A name that matches the one before it, ignoring case, is
// skipped, since renaming to it would change nothing.
func WipeNames(base string, w *spec.WipeSpec) []string {
	n := MaxWipeRenames
	if w.Renames != nil {
		n = *w.Renames
	}
	var out []string
	prev := base
	for i := range n {
		letter := rune('A' + i)
		name := strings.Map(func(r rune) rune {
			if r == '.' {
				return r
			}
			return letter
		}, base)
		if strings.EqualFold(name, prev) {
			continue
		}
		out = append(out, name)
		prev = name
	}
	return out
}
