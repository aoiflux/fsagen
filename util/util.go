package util

import (
	"encoding/base32"
	"fmt"
	"github.com/aoiflux/fsagen/constant"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var (
	rng  *rand.Rand
	mu   sync.Mutex
	once sync.Once
)

// Seed initializes the deterministic PRNG with the provided seed.
// Call early (from main) to ensure reproducibility.
func Seed(seed int64) {
	mu.Lock()
	defer mu.Unlock()
	rng = rand.New(rand.NewSource(seed))
}

// ensureRNG lazily initializes the PRNG with a default seed when Seed was
// never called explicitly.
func ensureRNG() {
	if rng == nil {
		once.Do(func() {
			mu.Lock()
			defer mu.Unlock()
			rng = rand.New(rand.NewSource(1))
		})
	}
}

func GetRandomString(length int) string {
	ensureRNG()
	mu.Lock()
	defer mu.Unlock()
	randomBytes := make([]byte, length)
	for i := range randomBytes {
		randomBytes[i] = byte(rng.Intn(256))
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}

func GetFilePath(basedir string, ext string) string {
	filename := GetRandomString(constant.FileNameLen) + ext
	return filepath.Join(basedir, filename)
}

// GetRandomHex returns a deterministic lowercase hex string of the requested
// length, drawn from the seeded PRNG. Used for artifact values that must look
// like real digests (base32 output is an immediate tell in a hash field).
func GetRandomHex(length int) string {
	if length <= 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	ensureRNG()
	mu.Lock()
	defer mu.Unlock()
	out := make([]byte, length)
	for i := range out {
		out[i] = hexdigits[rng.Intn(16)]
	}
	return string(out)
}

// GetRandomUUID returns a deterministic RFC 4122 version 4 UUID drawn from the
// seeded PRNG. The value is well-formed (correct version and variant nibbles)
// so it survives inspection by tools that parse UUIDs.
func GetRandomUUID() string {
	ensureRNG()
	mu.Lock()
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	mu.Unlock()

	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

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

// GetRandomBytes returns n deterministic bytes from the seeded PRNG.
func GetRandomBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	ensureRNG()
	mu.Lock()
	defer mu.Unlock()
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}
