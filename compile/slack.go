package compile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/fsagen/model"
	"github.com/aoiflux/fsagen/spec"
	"github.com/aoiflux/fsagen/target"
)

// Slack is the space between the end of a file's content and the end of its
// last cluster. Nothing reading the file sees it; a carver reading the volume
// does. A scenario can ask for that space to hold something findable.

// Slack kinds: a canary is a marker naming the object, then seeded text; a
// pattern is the marker repeated; a fragment is the start of another file.
const (
	SlackCanary   = "canary"
	SlackPattern  = "pattern"
	SlackFragment = "fragment"
)

// SlackKinds is the closed set of slack kinds.
var SlackKinds = []string{SlackCanary, SlackPattern, SlackFragment}

// DefaultClusterSize is the cluster size a slack block assumes when it gives
// none: what NTFS, ext4 and FAT32 of any moderate size use.
const DefaultClusterSize = 4096

// SlackSupport is how far a target can be trusted to keep slack bytes (see
// target.SlackSupport).
type SlackSupport = target.SlackSupport

// The slack a target keeps.
const (
	SlackNone       = target.SlackNone
	SlackBestEffort = target.SlackBestEffort
	SlackExact      = target.SlackExact
)

// MinResidentSafe is the smallest file whose slack a live NTFS volume is
// trusted to keep. A smaller one may live inside its MFT record, with no
// cluster and so no slack; the true limit depends on the record, so this is
// set conservatively at a whole record.
const MinResidentSafe = 1024

// ClusterOf is the cluster size a slack block asks for.
func ClusterOf(s *spec.SlackSpec) int {
	if s == nil || s.ClusterSize == 0 {
		return DefaultClusterSize
	}
	return s.ClusterSize
}

// LogicalSize is the size of what an operation writes, when that is known
// before the run: its filler, or its literal content. A structured format is
// built during the run, so it has no size here; checkSlack refuses slack on
// one for that reason.
func LogicalSize(op *Op) int {
	if op.Random > 0 {
		return op.Random
	}
	return len(op.Content)
}

// SlackRange is where an operation's slack lies in its last cluster: from
// the end of its content to the cluster's end.
func SlackRange(op *Op) (offset, length int) {
	c := ClusterOf(op.Slack)
	offset = LogicalSize(op)
	return offset, c - offset%c
}

// checkSlack validates what a slack block says on its own: a kind it knows,
// a cluster size a file system uses, a fragment source exactly when the kind
// needs one, and content whose size is known before the run.
func checkSlack(op *Op, at func(string, string, ...any)) {
	s := op.Slack
	if s.Kind != "" && !slices.Contains(SlackKinds, s.Kind) {
		at("slack", "kind %q (want one of: %s)", s.Kind, strings.Join(SlackKinds, ", "))
	}
	if c := s.ClusterSize; c != 0 && (c < 512 || c > 64<<10 || c&(c-1) != 0) {
		at("slack", "cluster_size %d is not a cluster size: a power of two from 512 to 65536", c)
	}
	switch {
	case s.Kind == SlackFragment && strings.TrimSpace(s.FragmentOf) == "":
		at("slack", "kind fragment needs fragment_of: the id of the file whose bytes fill the slack")
	case s.Kind != SlackFragment && s.FragmentOf != "":
		at("slack", "fragment_of only applies with kind: fragment")
	}
	if Structured(op.Format) {
		at("slack", "a %s is built during the run, so where its last cluster ends is not known beforehand; give slack to plain content or filler", op.Format)
	}
}

// placeSlack checks, once the operation's target and content are settled, that
// its content leaves slack at all, and resolves the file a fragment comes
// from. It runs in simulation, against the tree as it stands at that moment.
func placeSlack(t *model.Tree, op *Op) error {
	size, c := LogicalSize(op), ClusterOf(op.Slack)
	switch {
	case size == 0:
		return fmt.Errorf("slack: an empty file has no cluster, so no slack")
	case size%c == 0:
		return fmt.Errorf("slack: %d bytes fill whole %d-byte clusters exactly, leaving no slack", size, c)
	}
	if op.Slack.Kind != SlackFragment {
		return nil
	}
	live, known := t.Live(op.Slack.FragmentOf)
	switch {
	case !known:
		return fmt.Errorf("slack: unknown id %q in fragment_of (ids are declared with id: on an earlier action)", op.Slack.FragmentOf)
	case len(live) != 1:
		return fmt.Errorf("slack: fragment_of %q names %d live files, want exactly one", op.Slack.FragmentOf, len(live))
	}
	if o := t.Get(live[0]); o == nil || o.Kind != model.File {
		return fmt.Errorf("slack: fragment_of %q names %s, which is not a file", op.Slack.FragmentOf, live[0])
	}
	op.FragmentPath = live[0]
	return nil
}

// slackUnsupported explains why caps cannot keep op's slack, or returns "".
func slackUnsupported(op *Op, caps Caps) string {
	if op.Slack == nil {
		return ""
	}
	c := ClusterOf(op.Slack)
	switch {
	case caps.Slack == "" || caps.Slack == SlackNone:
		return "slack needs a target that keeps bytes past the end of a file: live NTFS (best effort) or a disk image"
	case caps.ClusterSize != 0 && caps.ClusterSize != c:
		return fmt.Sprintf("slack is planned for %d-byte clusters, and this volume's are %d bytes; set cluster_size: %d", c, caps.ClusterSize, caps.ClusterSize)
	case caps.Slack == SlackBestEffort && LogicalSize(op) <= MinResidentSafe:
		return fmt.Sprintf("a %d-byte file may be kept inside its NTFS MFT record, with no cluster and so no slack; slack on a live volume needs more than %d bytes", LogicalSize(op), MinResidentSafe)
	}
	return ""
}
