package util

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParseFileMode parses an octal permission string such as "0600" or "755".
// An empty string yields ok=false so callers can fall back to their default.
func ParseFileMode(s string) (os.FileMode, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, false, fmt.Errorf("invalid mode %q (expected octal, e.g. 0600): %w", s, err)
	}
	return os.FileMode(v), true, nil
}
