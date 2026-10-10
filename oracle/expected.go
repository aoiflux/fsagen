package oracle

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/spec"
)

// The four times, in the order every array of them here keeps them.
const (
	atime = iota
	mtime
	ctime
	crtime
)

// timeNames are the four times as the ledger and the scorecard name them.
var timeNames = [4]string{"atime", "mtime", "ctime", "crtime"}

// times are an object's four times; a zero one is not known, so not scored.
type times [4]time.Time

// Kinds of object, as the ledger names them.
const (
	kindFile     = "file"
	kindDir      = "dir"
	kindSymlink  = "symlink"
	kindJunction = "junction"
)

// object is one object of the run as the ledger leaves it.
type object struct {
	kind string
	// names are its present paths: more than one for a hard-linked file.
	names []string
	// times are the ones the scenario controls and the ledger records. A
	// directory's are left unknown: every entry added to or taken from it
	// moves them, at a time the ledger does not record.
	times       times
	md5, sha256 string
	streams     []ledger.Stream
	target      string
	// op is, for an object deleted, the ledger entry that deleted it.
	op int
}

// Expected is what a tool examining a run's output should find there.
type Expected struct {
	// present maps every path in the output to the object there.
	present map[string]*object
	// deleted maps every path an object was deleted from to each object
	// deleted there, in order, as it was then.
	deleted map[string][]*object
	// history is every path any object had during the run. A tool that
	// reports a deleted entry under an old name has found a real trace.
	history map[string]bool
	// fold says the volume treats names that differ only in case as one.
	fold bool
	// namedStreams says the volume keeps named streams, so a ":" in a name
	// can start one.
	namedStreams bool
	// ops and sums count what the state was built from, for the report.
	ops, sums int
}

func newExpected() *Expected {
	return &Expected{present: map[string]*object{}, deleted: map[string][]*object{}, history: map[string]bool{}}
}

// LoadExpected reads the expected state from a run's sidecar directory:
// the ledger, folded operation by operation, and SHA256SUMS, which lists
// every file and stream the run left (including any that were there before
// it, and every file of a bulk corpus, which has no ledger). A run that did
// not complete is refused: its output is not what its records describe.
func LoadExpected(meta string) (*Expected, error) {
	var rm runinfo.Manifest
	if err := readJSON(filepath.Join(meta, runinfo.FileName), &rm); err != nil {
		return nil, fmt.Errorf("%s is not a run's sidecar directory: %w", meta, err)
	}
	if rm.Status != runinfo.StatusComplete {
		return nil, fmt.Errorf("the run recorded in %s did not complete (status %q), so its output is not what its records describe", meta, rm.Status)
	}
	var info runinfo.Info
	if err := readJSON(filepath.Join(meta, runinfo.InfoFileName), &info); err != nil {
		return nil, err
	}
	x := newExpected()
	x.fold = caseInsensitive(info.Filesystem, info.OS)
	x.namedStreams = rm.Capabilities.NamedStreams

	entries, err := readLedger(filepath.Join(meta, ledger.FileName))
	if err != nil && !(errors.Is(err, fs.ErrNotExist) && rm.Mode == "bulk") {
		return nil, err
	}
	x.foldLedger(entries)
	sums, err := os.ReadFile(filepath.Join(meta, runinfo.SumsFileName))
	if err != nil {
		return nil, err
	}
	if err := x.addSums(sums); err != nil {
		return nil, fmt.Errorf("%s: %w", runinfo.SumsFileName, err)
	}
	return x, nil
}

func readJSON(name string, v any) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// readLedger reads ledger.jsonl.
func readLedger(name string) ([]ledger.Entry, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return parseLedger(data)
}

// parseLedger reads ledger lines. Lines starting with # are skipped, as the
// golden copies the tests keep carry one.
func parseLedger(data []byte) ([]ledger.Entry, error) {
	var out []ledger.Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxLine)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		var e ledger.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", ledger.FileName, n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// caseInsensitive says whether names on the volume a run wrote to are
// compared without regard to case. The file-system name decides when it is
// known; otherwise the platform's default does.
func caseInsensitive(filesystem, goos string) bool {
	switch strings.ToLower(filesystem) {
	case "ntfs", "refs", "fat", "fat12", "fat16", "fat32", "vfat", "msdos", "exfat", "apfs", "hfs", "hfs+":
		return true
	case "":
		return goos == "windows" || goos == "darwin"
	}
	return false
}

// foldLedger folds the ledger into the final state: which object each path
// names, what each object holds and the times it ends with, and what was
// deleted.
func (x *Expected) foldLedger(entries []ledger.Entry) {
	objects := map[int]*object{}
	obj := func(serial int) *object {
		o := objects[serial]
		if o == nil {
			o = &object{}
			objects[serial] = o
		}
		return o
	}
	for _, e := range entries {
		if e.Outcome != ledger.Done || e.Object == 0 {
			continue
		}
		x.ops++
		o := obj(e.Object)
		switch e.Action {
		case spec.ActionDelete:
			x.remove(e.Path)
			if e.Links > 0 {
				// The file keeps a name, so nothing was deleted, and losing
				// one changed its metadata at a time the ledger does not
				// record.
				o.times[ctime] = time.Time{}
				continue
			}
			gone := *o
			gone.kind, gone.times, gone.op = e.Kind, entryTimes(e), e.N
			x.deleted[e.Path] = append(x.deleted[e.Path], &gone)
			continue
		case spec.ActionCopy:
			x.add(e.NewPath, o)
		case spec.ActionHardlink:
			x.add(e.NewPath, o)
		case spec.ActionRename:
			x.move(e.Path, e.NewPath)
		case spec.ActionRotate:
			x.move(e.Path, e.NewPath)
			// The moved file's change time moved with the rename, at a time
			// the ledger does not record.
			obj(e.Moved).times[ctime] = time.Time{}
			x.add(e.Path, o)
		default:
			if x.present[e.Path] != o {
				x.add(e.Path, o)
			}
		}
		o.update(e)
	}
}

// update records what an operation left the object holding.
func (o *object) update(e ledger.Entry) {
	if e.Kind != "" {
		o.kind = e.Kind
	}
	if e.Size != nil {
		o.sha256, o.md5 = e.SHA256After, e.MD5After
	}
	o.streams = e.Streams
	if e.Target != "" {
		o.target = e.Target
	}
	o.times = entryTimes(e)
	if o.kind == kindDir {
		o.times = times{}
	}
}

// entryTimes are the times an entry records that the scenario controls.
func entryTimes(e ledger.Entry) times {
	var t times
	if e.Times == nil {
		return t
	}
	for i, s := range [4]string{e.Times.Atime, e.Times.Mtime, e.Times.Ctime, e.Times.Crtime} {
		if s == "" || slices.Contains(e.Uncontrolled, timeNames[i]) {
			continue
		}
		if v, err := time.Parse(time.RFC3339Nano, s); err == nil {
			t[i] = v.UTC()
		}
	}
	return t
}

// add gives o the name p, making any missing parent directories, as the run
// does.
func (x *Expected) add(p string, o *object) {
	x.parents(p)
	if x.present[p] == o {
		return
	}
	x.present[p] = o
	o.names = append(o.names, p)
	x.history[p] = true
}

// parents makes the missing directories above p.
func (x *Expected) parents(p string) {
	d := path.Dir(p)
	if d == "." || d == "/" || x.present[d] != nil {
		return
	}
	x.add(d, &object{kind: kindDir})
}

// remove takes the name p away from its object.
func (x *Expected) remove(p string) *object {
	o := x.present[p]
	if o == nil {
		return nil
	}
	delete(x.present, p)
	o.names = slices.DeleteFunc(o.names, func(n string) bool { return n == p })
	return o
}

// move renames oldp, and everything under it, to newp.
func (x *Expected) move(oldp, newp string) {
	var moved []string
	for p := range x.present {
		if p == oldp || strings.HasPrefix(p, oldp+"/") {
			moved = append(moved, p)
		}
	}
	slices.Sort(moved)
	objs := make([]*object, len(moved))
	for i, p := range moved {
		objs[i] = x.remove(p)
	}
	for i, p := range moved {
		x.add(newp+strings.TrimPrefix(p, oldp), objs[i])
	}
}

// addSums checks the folded state against SHA256SUMS and adds what only
// SHA256SUMS knows: files the run found already there, and every file of a
// bulk corpus. The two must agree on every file the ledger made; when they
// do not, the records are from different runs.
func (x *Expected) addSums(data []byte) error {
	listed := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxLine)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			continue
		}
		if len(line) < 67 || line[64:66] != "  " {
			return fmt.Errorf("line %d is not \"<sha256>  <path>\"", n)
		}
		sum, name := line[:64], line[66:]
		x.sums++
		p, stream := name, ""
		if x.namedStreams {
			p, stream = splitStream(name)
		}
		o := x.present[p]
		if stream == "" {
			if o == nil {
				o = &object{kind: kindFile}
				x.add(p, o)
			}
			if o.sha256 != "" && o.sha256 != sum {
				return fmt.Errorf("%s has SHA-256 %s, but the ledger says %s: these records are not from one run", p, sum, o.sha256)
			}
			o.sha256 = sum
			listed[p] = true
			continue
		}
		if o == nil {
			// Files are listed before their streams, so this is a stream of
			// a directory.
			o = &object{kind: kindDir}
			x.add(p, o)
		}
		i := slices.IndexFunc(o.streams, func(s ledger.Stream) bool { return s.Name == stream })
		switch {
		case i < 0:
			o.streams = append(o.streams, ledger.Stream{Name: stream, SHA256: sum})
		case o.streams[i].SHA256 != sum:
			return fmt.Errorf("%s has SHA-256 %s, but the ledger says %s: these records are not from one run", name, sum, o.streams[i].SHA256)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	for p, o := range x.present {
		if o.kind == kindFile && o.sha256 != "" && !listed[p] {
			return fmt.Errorf("the ledger leaves a file at %s, which is not listed: these records are not from one run", p)
		}
	}
	return nil
}

// UseModel takes directory times from a modelled timeline of the same run
// (fsagen --timeline-source modelled), which has them where the ledger does
// not. The model must list exactly the names the run left, and only
// deletions the run made: a model of another run is refused rather than
// scored against.
func (x *Expected) UseModel(rows []Row) error {
	listed := map[string]bool{}
	for _, r := range rows {
		p := strings.Join(components(r.Path), "/")
		if r.FileName || r.Stream != "" || p == "" {
			continue
		}
		if r.Whole && x.present[p] == nil && x.deleted[p] == nil {
			if base, stream := splitStream(p); stream != "" && (x.present[base] != nil || x.deleted[base] != nil) {
				continue
			}
		}
		if r.Deleted {
			if x.deleted[p] == nil {
				return fmt.Errorf("it lists %s as deleted, and this run deleted nothing there: it is another run's model", p)
			}
			continue
		}
		o := x.present[p]
		if o == nil {
			return fmt.Errorf("it lists %s, which this run did not leave: it is another run's model", p)
		}
		listed[p] = true
		if o.kind == kindDir {
			o.times = r.Times
		}
	}
	for p := range x.present {
		if !listed[p] {
			return fmt.Errorf("it does not list %s, which this run left: it is another run's model", p)
		}
	}
	return nil
}

// splitStream separates "name:stream" into its parts. Only the last element
// can name a stream, so a drive letter or a directory holding a colon is
// left alone.
func splitStream(p string) (string, string) {
	dir, last := "", p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		dir, last = p[:i+1], p[i+1:]
	}
	i := strings.Index(last, ":")
	if i <= 0 || i == len(last)-1 {
		return p, ""
	}
	return dir + last[:i], last[i+1:]
}
