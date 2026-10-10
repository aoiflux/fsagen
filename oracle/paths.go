package oracle

import (
	"errors"
	"slices"
	"strings"
)

// pathIndex finds the path of the run that a reported path names.
type pathIndex struct {
	known map[string]bool
	// alias maps the other forms a tool may write a path in to the path:
	// lower case on a volume that ignores case, commas as spaces in Plaso's
	// CSVs. A form two paths share maps to "", and names neither.
	alias        map[string]string
	fold, commas bool
}

func newPathIndex(x *Expected, fold, commas bool) *pathIndex {
	ix := &pathIndex{known: map[string]bool{}, alias: map[string]string{}, fold: fold, commas: commas}
	for p := range x.present {
		ix.known[p] = true
	}
	for p := range x.deleted {
		ix.known[p] = true
	}
	for p := range x.history {
		ix.known[p] = true
	}
	for p := range ix.known {
		for _, k := range ix.forms(p) {
			if q, ok := ix.alias[k]; ok && q != p {
				ix.alias[k] = ""
			} else {
				ix.alias[k] = p
			}
		}
	}
	return ix
}

// forms are the ways a tool may write p other than as it is.
func (ix *pathIndex) forms(p string) []string {
	var out []string
	if ix.commas {
		out = append(out, strings.ReplaceAll(p, ",", " "))
	}
	if ix.fold {
		for _, q := range append([]string{p}, out...) {
			out = append(out, strings.ToLower(q))
		}
	}
	return out
}

// lookup is the path of the run that p names, if any.
func (ix *pathIndex) lookup(p string) (string, bool) {
	if ix.known[p] {
		return p, true
	}
	for _, k := range []string{p, strings.ToLower(p)} {
		if q := ix.alias[k]; q != "" {
			return q, true
		}
		if !ix.fold {
			break
		}
	}
	return "", false
}

// sameName compares two names, ignoring case where the volume does.
func (ix *pathIndex) sameName(a, b string) bool {
	if ix.fold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// components splits a reported path into its names, dropping empty ones and
// ".", so "/a//b/" and "a/b" are the same.
func components(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// prefix is the path a tool gives the output root.
type prefix struct {
	comps []string
	// absolute says the tool writes paths from a root, so the prefix is
	// shown with a leading slash.
	absolute bool
	// votes is how many rows named something in the run under it, when it
	// was detected.
	votes int
}

func (p prefix) String() string {
	s := strings.Join(p.comps, "/")
	if p.absolute {
		return "/" + s
	}
	if s == "" {
		return "."
	}
	return s
}

// parsePrefix reads --strip-prefix.
func parsePrefix(s string, backslashes bool) prefix {
	if backslashes {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	return prefix{comps: components(s), absolute: strings.HasPrefix(s, "/")}
}

// strip is the path relative to the output root, and whether p is under it.
func (p prefix) strip(ix *pathIndex, comps []string) (string, bool) {
	if len(comps) < len(p.comps) {
		return "", false
	}
	for i, c := range p.comps {
		if !ix.sameName(c, comps[i]) {
			return "", false
		}
	}
	return strings.Join(comps[len(p.comps):], "/"), true
}

// errNoPrefix is returned when no reported path names anything in the run.
var errNoPrefix = errors.New("no path the tool reports names anything the run made; check --meta, or give --strip-prefix")

// detectPrefix finds the path the tool gives the output root: the leading
// part that, taken off, leaves the most rows naming something in the run.
// A tie goes to the shorter prefix, then to the first in byte order, so the
// choice does not depend on the order the rows came in.
func detectPrefix(rows []Row, ix *pathIndex, backslashes bool) (prefix, error) {
	votes := map[string]int{}
	cands := map[string]prefix{}
	for _, r := range rows {
		path := reportedPath(r.Path, backslashes)
		comps := components(path)
		for k := range comps {
			if !ix.names(strings.Join(comps[k:], "/"), r.Whole) {
				continue
			}
			key := strings.Join(comps[:k], "/")
			if _, ok := cands[key]; !ok {
				cands[key] = prefix{comps: comps[:k], absolute: strings.HasPrefix(path, "/")}
			}
			votes[key]++
		}
	}
	if len(votes) == 0 {
		return prefix{}, errNoPrefix
	}
	keys := make([]string, 0, len(votes))
	for k := range votes {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if votes[a] != votes[b] {
			return votes[b] - votes[a]
		}
		if d := len(cands[a].comps) - len(cands[b].comps); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	best := cands[keys[0]]
	best.votes = votes[keys[0]]
	return best, nil
}

// names says whether rel names something in the run, itself or, for a
// format that appends streams to paths, through the file a stream is on.
func (ix *pathIndex) names(rel string, whole bool) bool {
	if _, ok := ix.lookup(rel); ok {
		return true
	}
	if whole {
		if base, stream := splitStream(rel); stream != "" {
			_, ok := ix.lookup(base)
			return ok
		}
	}
	return false
}

// reportedPath makes a reported path's separators forward slashes, unless
// the run's own names hold backslashes, when they cannot be told apart.
func reportedPath(p string, backslashes bool) string {
	if backslashes {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return p
}

// volumeFurniture says whether an entry no scenario made is one the file
// system keeps for itself: NTFS's metadata files and the entries The Sleuth
// Kit adds to every listing ($MFT, $OrphanFiles, $FAT1 and the like),
// System Volume Information, and ext4's lost+found.
func volumeFurniture(rel string) bool {
	top, _, _ := strings.Cut(rel, "/")
	return strings.HasPrefix(top, "$") || strings.EqualFold(top, "System Volume Information") || top == "lost+found"
}

// streamFurniture says whether a stream is one NTFS keeps for itself, such
// as a directory's $I30 index, which a tool may list beside the named
// streams a scenario writes.
func streamFurniture(stream string) bool { return strings.HasPrefix(stream, "$") }
