package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
)

// sectorSize is the unit a disk writes in. When Windows shrinks a file it may
// zero the rest of the sector holding the new end of the file (the "RAM
// slack" of the old literature), but it leaves the sectors after it alone
// ("drive slack"); so a canary starts again at every sector boundary, where a
// carver will find it whichever part survives.
const sectorSize = 512

// slackMarker begins every canary: it names the object whose slack it is, so
// a carver's hit can be traced back through the answer key.
func slackMarker(object int) []byte { return fmt.Appendf(nil, "FSAGEN-SLACK:%d:", object) }

// slackBytes is what fills the operation's slack.
//   - canary: the marker, then seeded base32 text, with the marker again at
//     every sector boundary;
//   - pattern: the marker, repeated;
//   - fragment: the first bytes of another file, then zeros if it is shorter.
func slackBytes(ctx ExecContext, op compile.Op) ([]byte, error) {
	offset, length := compile.SlackRange(&op)
	marker := slackMarker(op.Object)
	out := make([]byte, length)
	switch op.Slack.Kind {
	case compile.SlackFragment:
		src, err := ctx.FS.ReadFile(op.FragmentPath)
		if err != nil {
			return nil, fmt.Errorf("slack fragment from %s: %w", op.FragmentPath, err)
		}
		copy(out, src)
	case compile.SlackPattern:
		for i := 0; i < length; i += len(marker) {
			copy(out[i:], marker)
		}
	default:
		copy(out, op.Rand.Derive("slack").Stream().Text(length))
		copy(out, marker)
		for i := sectorSize - offset%sectorSize; i < length; i += sectorSize {
			copy(out[i:], marker)
		}
	}
	return out, nil
}

// writeSlack leaves the operation's slack bytes past the end of its file and
// records them. On a live volume they are left for the file system to keep,
// so the record says they are not verified.
func writeSlack(ctx ExecContext, op compile.Op) (*ledger.Slack, error) {
	data, err := slackBytes(ctx, op)
	if err != nil {
		return nil, err
	}
	offset, length := compile.SlackRange(&op)
	if err := ctx.FS.WriteSlack(op.Path, int64(offset), data); err != nil {
		return nil, fmt.Errorf("slack: %w", err)
	}
	sum := sha256.Sum256(data)
	kind := op.Slack.Kind
	if kind == "" {
		kind = compile.SlackCanary
	}
	return &ledger.Slack{
		Kind:        kind,
		ClusterSize: compile.ClusterOf(op.Slack),
		Offset:      offset,
		Length:      length,
		SHA256:      hex.EncodeToString(sum[:]),
		Verified:    ctx.Caps.Slack == compile.SlackExact,
	}, nil
}
