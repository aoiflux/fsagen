package util

import (
	"encoding/base32"
	"errors"
	"fmt"
	"fsagen/constant"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
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

func GetAbsPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	finfo, err := os.Stat(absPath)
	if err != nil {
		return "", err
	}

	if finfo.IsDir() {
		return absPath, nil
	}

	return filepath.Dir(absPath), nil
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

// SetTimes sets the modified and access times for a file or directory.
// On Unix systems, ctime cannot be set directly; this sets mtime/atime only.
func SetTimes(path string, atime, mtime time.Time) error {
	return os.Chtimes(path, atime, mtime)
}

// Touch updates or creates a file with provided content and times.
func Touch(path string, data []byte, atime, mtime time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, os.ModePerm); err != nil {
		return err
	}
	return SetTimes(path, atime, mtime)
}

// RemoveFile deletes a file and optionally sets directory times after deletion
// to emulate skew around deletion events. Skips silently if file doesn't exist.
func RemoveFile(path string, dirAtime, dirMtime *time.Time) error {
	// Check if file exists first
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// File doesn't exist, nothing to delete - skip silently
		return nil
	}

	if err := os.Remove(path); err != nil {
		return err
	}
	if dirAtime != nil && dirMtime != nil {
		_ = SetTimes(filepath.Dir(path), *dirAtime, *dirMtime)
	}
	return nil
}

// IsWindows reports whether the current OS is Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// WriteADS writes data to an NTFS Alternate Data Stream for the given file path.
// The base file will be created if it does not exist. Windows-only.
func WriteADS(basePath, stream string, data []byte) error {
	if !IsWindows() {
		return errors.New("ADS not supported on non-Windows platforms")
	}
	if err := os.MkdirAll(filepath.Dir(basePath), os.ModePerm); err != nil {
		return err
	}
	// Ensure base file exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		if err := os.WriteFile(basePath, []byte{}, os.ModePerm); err != nil {
			return err
		}
	}
	streamPath := fmt.Sprintf("%s:%s", basePath, stream)
	return os.WriteFile(streamPath, data, os.ModePerm)
}

// WriteMOTW writes a Mark-of-the-Web Zone.Identifier ADS with optional URLs.
// zoneID: 0 (My Computer), 1 (Local Intranet), 2 (Trusted), 3 (Internet), 4 (Restricted)
func WriteMOTW(basePath string, zoneID int, hostURL, referrerURL string) error {
	if !IsWindows() {
		return errors.New("MOTW not supported on non-Windows platforms")
	}
	content := "[ZoneTransfer]\r\n" + fmt.Sprintf("ZoneId=%d\r\n", zoneID)
	if referrerURL != "" {
		content += fmt.Sprintf("ReferrerUrl=%s\r\n", referrerURL)
	}
	if hostURL != "" {
		content += fmt.Sprintf("HostUrl=%s\r\n", hostURL)
	}
	return WriteADS(basePath, "Zone.Identifier", []byte(content))
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
