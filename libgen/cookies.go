package libgen

import (
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// A Chromium cookie jar is the profile's "Cookies" file: one SQLite table a
// tool reads for which sites knew the browser was there. What a tool reads
// without the profile's key is the host, name, path and the times; the value
// itself Chrome stores encrypted.

// Cookie is one cookie in the jar.
type Cookie struct {
	Host, Name, Value, Path string
	Created, Expires        time.Time // a zero Expires is a session cookie
	LastAccess              time.Time // zero means Created
	Secure, HTTPOnly        bool
	SameSite                string // one of SameSites; empty means unspecified
}

// CookieJar is what a jar holds and how its values are stored.
type CookieJar struct {
	Cookies []Cookie
	// Plaintext writes each value as is. Otherwise value is empty and
	// encrypted_value holds bytes shaped as Chrome's own: "v10", a 12-byte
	// nonce, the AES-GCM ciphertext and a 16-byte tag. There is no key behind
	// them, which is what a jar copied without its Local State gives a tool.
	Plaintext bool
}

// SameSites are the SameSite attributes a cookie can carry.
var SameSites = []string{"unspecified", "none", "lax", "strict"}

// sameSiteCodes is Chromium's stored encoding of SameSite (DBCookieSameSite).
var sameSiteCodes = map[string]int{"unspecified": -1, "none": 0, "lax": 1, "strict": 2}

// Chromium's stored encodings of the remaining cookie attributes: priority
// medium; the source scheme (unset, non-secure, secure); a port it does not
// know; and a cookie set by an HTTP response.
const (
	cookiePriorityMedium   = 1
	cookieSchemeNonSecure  = 1
	cookieSchemeSecure     = 2
	cookieSourceTypeHTTP   = 1
	chromeCookieDBVersion  = "24"
	encryptedValuePrefix   = "v10"
	encryptedValueNonceLen = 12
	encryptedValueTagLen   = 16
)

// cookieSchema is Chromium's cookie store at version 24
// (net/extras/sqlite/sqlite_persistent_cookie_store.cc).
var cookieSchema = []string{
	`CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)`,
	`CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL)`,
	`CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port)`,
}

// ChromeCookies writes a Chromium "Cookies" database.
func ChromeCookies(jar CookieJar, s *prng.Stream) ([]byte, error) {
	if err := validateCookies(jar); err != nil {
		return nil, err
	}
	return buildSQLite(func(db *sql.DB) error {
		if err := execAll(db, cookieSchema...); err != nil {
			return err
		}
		for _, kv := range [][2]string{{"version", chromeCookieDBVersion}, {"last_compatible_version", chromeCookieDBVersion}} {
			if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES(?,?)`, kv[0], kv[1]); err != nil {
				return err
			}
		}
		const q = `INSERT INTO cookies VALUES(?,?,'',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`
		for _, c := range jar.Cookies {
			value, encrypted := c.Value, []byte{}
			if !jar.Plaintext {
				value, encrypted = "", encryptedValue(c.Value, s)
			}
			scheme, port := cookieSchemeNonSecure, 80
			if c.Secure {
				scheme, port = cookieSchemeSecure, 443
			}
			persistent := btoi(!c.Expires.IsZero())
			lastAccess := c.LastAccess
			if lastAccess.IsZero() {
				lastAccess = c.Created
			}
			if _, err := db.Exec(q,
				chromeTime(c.Created), c.Host, c.Name, value, encrypted, or(c.Path, "/"),
				chromeTime(c.Expires), btoi(c.Secure), btoi(c.HTTPOnly), chromeTime(lastAccess),
				persistent, persistent, cookiePriorityMedium, sameSiteCodes[or(c.SameSite, "unspecified")],
				scheme, port, chromeTime(c.Created), cookieSourceTypeHTTP); err != nil {
				return err
			}
		}
		return nil
	})
}

// encryptedValue is what Chrome stores for value: deterministic bytes from the
// seed in the shape of its AES-GCM output, the ciphertext as long as the value.
func encryptedValue(value string, s *prng.Stream) []byte {
	out := []byte(encryptedValuePrefix)
	return append(out, s.Bytes(encryptedValueNonceLen+len(value)+encryptedValueTagLen)...)
}

// validateCookies rejects a cookie Chrome could not have stored: one with no
// host or name, a SameSite it does not know, one expiring before it was set,
// and two that its unique index would refuse.
func validateCookies(jar CookieJar) error {
	seen := map[string]int{}
	for i, c := range jar.Cookies {
		if err := CheckCookie(c); err != nil {
			return fmt.Errorf("cookies: entries[%d]: %w", i, err)
		}
		key := strings.Join([]string{c.Host, c.Name, or(c.Path, "/"), fmt.Sprint(c.Secure)}, "\x00")
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("cookies: entries[%d] repeats entries[%d]: one jar holds one cookie per host, name and path", i, prev)
		}
		seen[key] = i
	}
	return nil
}

// CheckCookie reports what is wrong with one cookie, or nil.
func CheckCookie(c Cookie) error {
	switch {
	case strings.TrimSpace(c.Host) == "":
		return fmt.Errorf("no host")
	case strings.ContainsAny(c.Host, "/:"):
		return fmt.Errorf("host %q is a URL, not a domain (write %q)", c.Host, hostOf(c.Host))
	case strings.TrimSpace(c.Name) == "":
		return fmt.Errorf("no name")
	case c.Path != "" && !strings.HasPrefix(c.Path, "/"):
		return fmt.Errorf("path %q does not start with /", c.Path)
	case c.SameSite != "" && !slices.Contains(SameSites, c.SameSite):
		return fmt.Errorf("samesite %q (want one of: %s)", c.SameSite, strings.Join(SameSites, ", "))
	case !c.Expires.IsZero() && c.Expires.Before(c.Created):
		return fmt.Errorf("expires before it was created")
	}
	return nil
}

// hostOf is the host a URL names, for a message suggesting it.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return strings.Trim(raw, "/:")
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
