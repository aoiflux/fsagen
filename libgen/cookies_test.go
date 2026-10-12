package libgen

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// chromiumCookieColumns are the columns of Chromium's cookie store at version
// 24, in order (net/extras/sqlite/sqlite_persistent_cookie_store.cc).
var chromiumCookieColumns = []string{
	"creation_utc", "host_key", "top_frame_site_key", "name", "value", "encrypted_value", "path",
	"expires_utc", "is_secure", "is_httponly", "last_access_utc", "has_expires", "is_persistent",
	"priority", "samesite", "source_scheme", "source_port", "last_update_utc", "source_type",
	"has_cross_site_ancestor",
}

func testJar() CookieJar {
	set := time.Date(2026, 3, 11, 9, 16, 5, 0, time.UTC)
	return CookieJar{Cookies: []Cookie{
		{Host: ".adnet.test", Name: "uid", Value: "a1b2c3", Created: set, Expires: set.AddDate(1, 0, 0), Secure: true, SameSite: "none"},
		{Host: "lure.example", Name: "session", Value: "s3ss10n", Created: set.Add(time.Minute), HTTPOnly: true, Secure: true},
		{Host: ".trackco.test", Name: "px", Value: "1", Path: "/p", Created: set, Expires: set.AddDate(0, 0, 30)},
	}}
}

// TestCookieJarSchema: the jar is Chromium's own table, column for column,
// at the version its meta row claims.
func TestCookieJarSchema(t *testing.T) {
	data, err := ChromeCookies(testJar(), prng.Root(5).Stream())
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	if got := queryStrings(t, db, "SELECT name FROM pragma_table_info('cookies') ORDER BY cid"); strings.Join(got, ",") != strings.Join(chromiumCookieColumns, ",") {
		t.Errorf("columns = %v\nwant %v", got, chromiumCookieColumns)
	}
	if got := queryStrings(t, db, "SELECT key || '=' || value FROM meta ORDER BY key"); strings.Join(got, ",") != "last_compatible_version=24,version=24" {
		t.Errorf("meta = %v", got)
	}
	if got := queryStrings(t, db, "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'cookies'"); strings.Join(got, ",") != "cookies_unique_index" {
		t.Errorf("indexes = %v", got)
	}
}

// TestCookieJarReadsAsAToolReadsIt: the query Mutant's browser_cookies runs
// returns every cookie; by default the value is empty and encrypted_value is
// shaped as Chrome's v10 AES-GCM output, and plaintext puts the value back.
func TestCookieJarReadsAsAToolReadsIt(t *testing.T) {
	jar := testJar()
	data, err := ChromeCookies(jar, prng.Root(5).Stream())
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	rows, err := db.Query(`SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var host, name, value, path string
		var enc []byte
		var expires, secure, httponly int64
		if err := rows.Scan(&host, &name, &value, &enc, &path, &expires, &secure, &httponly); err != nil {
			t.Fatal(err)
		}
		c := jar.Cookies[n]
		if host != c.Host || name != c.Name || path != or(c.Path, "/") || expires != chromeTime(c.Expires) || (secure == 1) != c.Secure || (httponly == 1) != c.HTTPOnly {
			t.Errorf("row %d = %s %s %s %d %d %d", n, host, name, path, expires, secure, httponly)
		}
		if value != "" || !bytes.HasPrefix(enc, []byte("v10")) || len(enc) != 3+12+len(c.Value)+16 {
			t.Errorf("row %d: value %q, encrypted_value %d bytes %q...; want empty and v10 + 12 + %d + 16", n, value, len(enc), enc[:min(3, len(enc))], len(c.Value))
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != len(jar.Cookies) {
		t.Fatalf("%d rows, want %d", n, len(jar.Cookies))
	}
	// A session cookie neither expires nor persists.
	if got := queryInts(t, db, "SELECT has_expires + is_persistent FROM cookies WHERE name = 'session'"); got[0] != 0 {
		t.Errorf("session cookie has_expires+is_persistent = %d, want 0", got[0])
	}
	// SameSite none is 0, unspecified -1; a secure cookie came from https on 443.
	if got := queryStrings(t, db, "SELECT samesite || ' ' || source_scheme || ' ' || source_port FROM cookies ORDER BY rowid"); strings.Join(got, "|") != "0 2 443|-1 2 443|-1 1 80" {
		t.Errorf("samesite/scheme/port = %v", got)
	}

	jar.Plaintext = true
	plain, err := ChromeCookies(jar, prng.Root(5).Stream())
	if err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, openDB(t, plain), "SELECT value || ':' || length(encrypted_value) FROM cookies ORDER BY rowid"); strings.Join(got, ",") != "a1b2c3:0,s3ss10n:0,1:0" {
		t.Errorf("plaintext values = %v", got)
	}
}

// TestCookieJarDeterministic: one seed, one jar, byte for byte.
func TestCookieJarDeterministic(t *testing.T) {
	a, err := ChromeCookies(testJar(), prng.Root(7).Stream())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ChromeCookies(testJar(), prng.Root(7).Stream())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two jars from one seed differ")
	}
}

// TestCookiesRefused: what Chrome could not have stored is refused.
func TestCookiesRefused(t *testing.T) {
	set := time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	for name, c := range map[string][]Cookie{
		"no host":  {{Name: "a", Created: set}},
		"url host": {{Host: "https://a.example/", Name: "a", Created: set}},
		"no name":  {{Host: "a.example", Created: set}},
		"path":     {{Host: "a.example", Name: "a", Path: "p", Created: set}},
		"samesite": {{Host: "a.example", Name: "a", SameSite: "loose", Created: set}},
		"expiry":   {{Host: "a.example", Name: "a", Created: set, Expires: set.Add(-time.Hour)}},
		"repeat":   {{Host: "a.example", Name: "a", Created: set}, {Host: "a.example", Name: "a", Path: "/", Created: set}},
	} {
		if _, err := ChromeCookies(CookieJar{Cookies: c}, prng.Root(1).Stream()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
