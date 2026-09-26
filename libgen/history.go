package libgen

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// Browser history is where a scenario's story usually lives, and the two
// engines disagree about almost everything: the table names, the column
// names and, worst of all, the epoch. Chrome counts microseconds from
// 1601-01-01 and Firefox microseconds from 1970-01-01, so a database filled
// with Unix seconds is not wrong by a rounding error but by four centuries,
// and every tool reading it reports a date in 1601. These builders write the
// tables the parsers actually read, with each engine's own epoch.

// Transitions are the ways a scenario can say a page was reached.
var Transitions = []string{"link", "typed", "bookmark", "generated", "form_submit", "reload"}

// transitionCodes maps a transition to Chrome's core type and Firefox's
// visit_type, which are numbered differently.
var transitionCodes = map[string]struct{ chrome, firefox int }{
	"link":        {0, 1},
	"typed":       {1, 2},
	"bookmark":    {2, 3},
	"generated":   {5, 1},
	"form_submit": {7, 1},
	"reload":      {8, 9},
}

// chromeChain marks a visit that is a navigation on its own rather than one
// hop of a redirect chain, which is how Chrome records an ordinary click.
const chromeChain = 0x30000000

// Visit is one page view.
type Visit struct {
	URL        string
	Title      string
	Time       time.Time
	Transition string // one of Transitions; empty means link
	// FromVisit is the 1-based position of the visit this one came from,
	// which is how a redirect or a click-through is recorded. Zero means none.
	FromVisit int
}

// Download is one completed download, which Chrome records and Firefox does
// not (Firefox keeps them in another database).
type Download struct {
	URL        string
	TargetPath string
	Start      time.Time
	End        time.Time
	Received   int64
	Total      int64
	MimeType   string
}

// HistorySpec is what a scenario says a profile's history holds.
type HistorySpec struct {
	Visits    []Visit
	Downloads []Download
}

// unixToChrome is the number of seconds between Chrome's epoch and the Unix
// one. The difference is over four centuries, which is more than a
// time.Duration holds, so the arithmetic cannot go through Sub.
const unixToChrome = 11644473600

// chromeTime converts to microseconds since 1601.
func chromeTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	u := t.UTC()
	return (u.Unix()+unixToChrome)*1_000_000 + int64(u.Nanosecond())/1000
}

// prTime converts to Firefox's PRTime: microseconds since the Unix epoch.
func prTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixMicro()
}

// urls groups the visits by page, keeping the order each page first appears
// so that row ids do not depend on a map.
type pageRow struct {
	url, title string
	visits     []int // indices into the spec's visit list
	typed      int
	last       time.Time
}

func pages(visits []Visit) ([]*pageRow, map[string]int) {
	var out []*pageRow
	index := map[string]int{}
	for i, v := range visits {
		id, seen := index[v.URL]
		if !seen {
			id = len(out) + 1
			index[v.URL] = id
			out = append(out, &pageRow{url: v.URL})
		}
		p := out[id-1]
		p.visits = append(p.visits, i)
		if v.Title != "" {
			p.title = v.Title
		}
		if v.Transition == "typed" {
			p.typed++
		}
		if v.Time.After(p.last) {
			p.last = v.Time
		}
	}
	return out, index
}

// ChromeHistory writes a Chrome "History" database.
func ChromeHistory(spec HistorySpec, s *prng.Stream) ([]byte, error) {
	for _, v := range spec.Visits {
		if _, ok := transitionCodes[or(v.Transition, "link")]; !ok {
			return nil, fmt.Errorf("history: unknown transition %q (want one of: %s)", v.Transition, strings.Join(Transitions, ", "))
		}
	}
	return buildSQLite(func(db *sql.DB) error {
		if err := execAll(db,
			`CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)`,
			`CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL)`,
			`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL, incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL)`,
			`CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL, target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, danger_type INTEGER NOT NULL, interrupt_reason INTEGER NOT NULL, hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL, last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL, site_url VARCHAR NOT NULL, tab_url VARCHAR NOT NULL, tab_referrer_url VARCHAR NOT NULL, http_method VARCHAR NOT NULL, by_ext_id VARCHAR NOT NULL, by_ext_name VARCHAR NOT NULL, etag VARCHAR NOT NULL, last_modified VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL, original_mime_type VARCHAR(255) NOT NULL)`,
			`CREATE TABLE downloads_url_chains(id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index))`,
			`CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL)`,
			`CREATE INDEX visits_url_index ON visits (url)`,
			`CREATE INDEX visits_from_index ON visits (from_visit)`,
			`CREATE INDEX visits_time_index ON visits (visit_time)`,
		); err != nil {
			return err
		}
		for _, kv := range [][2]string{{"version", "61"}, {"last_compatible_version", "16"}} {
			if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES(?,?)`, kv[0], kv[1]); err != nil {
				return err
			}
		}

		rows, index := pages(spec.Visits)
		for id, p := range rows {
			if _, err := db.Exec(`INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES(?,?,?,?,?,?,0)`,
				id+1, p.url, p.title, len(p.visits), p.typed, chromeTime(p.last)); err != nil {
				return err
			}
		}
		for i, v := range spec.Visits {
			code := transitionCodes[or(v.Transition, "link")].chrome | chromeChain
			if _, err := db.Exec(`INSERT INTO visits(id, url, visit_time, from_visit, transition, visit_duration) VALUES(?,?,?,?,?,?)`,
				i+1, index[v.URL], chromeTime(v.Time), v.FromVisit, code, 0); err != nil {
				return err
			}
		}
		for i, d := range spec.Downloads {
			site := origin(d.URL)
			if _, err := db.Exec(`INSERT INTO downloads(id, guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, hash, end_time, opened, last_access_time, transient, referrer, site_url, tab_url, tab_referrer_url, http_method, by_ext_id, by_ext_name, etag, last_modified, mime_type, original_mime_type)
				VALUES(?,?,?,?,?,?,?,1,0,0,?,?,0,?,0,?,?,?,'','GET','','','','',?,?)`,
				i+1, s.UUID(), d.TargetPath, d.TargetPath, chromeTime(d.Start), d.Received, d.Total,
				[]byte{}, chromeTime(d.End), chromeTime(d.End), d.URL, site, d.URL, d.MimeType, d.MimeType); err != nil {
				return err
			}
			if _, err := db.Exec(`INSERT INTO downloads_url_chains(id, chain_index, url) VALUES(?,0,?)`, i+1, d.URL); err != nil {
				return err
			}
		}
		return nil
	})
}

// FirefoxPlaces writes a Firefox "places.sqlite" database.
func FirefoxPlaces(spec HistorySpec, s *prng.Stream) ([]byte, error) {
	for _, v := range spec.Visits {
		if _, ok := transitionCodes[or(v.Transition, "link")]; !ok {
			return nil, fmt.Errorf("history: unknown transition %q (want one of: %s)", v.Transition, strings.Join(Transitions, ", "))
		}
	}
	return buildSQLite(func(db *sql.DB) error {
		if err := execAll(db,
			`PRAGMA user_version = 77`,
			`CREATE TABLE moz_origins(id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, host TEXT NOT NULL, frecency INTEGER NOT NULL, UNIQUE (prefix, host))`,
			`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL, description TEXT, preview_image_url TEXT, origin_id INTEGER REFERENCES moz_origins(id))`,
			`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER)`,
			`CREATE INDEX moz_places_url_hashindex ON moz_places (url_hash)`,
			`CREATE INDEX moz_historyvisits_placedateindex ON moz_historyvisits (place_id, visit_date)`,
		); err != nil {
			return err
		}

		rows, index := pages(spec.Visits)
		origins := map[string]int{}
		for id, p := range rows {
			prefix, host := splitOrigin(p.url)
			key := prefix + host
			oid, seen := origins[key]
			if !seen {
				oid = len(origins) + 1
				origins[key] = oid
				if _, err := db.Exec(`INSERT INTO moz_origins(id, prefix, host, frecency) VALUES(?,?,?,?)`, oid, prefix, host, 100); err != nil {
					return err
				}
			}
			typed := 0
			if p.typed > 0 {
				typed = 1
			}
			if _, err := db.Exec(`INSERT INTO moz_places(id, url, title, rev_host, visit_count, hidden, typed, frecency, last_visit_date, guid, origin_id) VALUES(?,?,?,?,?,0,?,?,?,?,?)`,
				id+1, p.url, p.title, revHost(host), len(p.visits), typed, 100*len(p.visits), prTime(p.last), s.Text(12), oid); err != nil {
				return err
			}
		}
		session := int64(1)
		for i, v := range spec.Visits {
			code := transitionCodes[or(v.Transition, "link")].firefox
			if _, err := db.Exec(`INSERT INTO moz_historyvisits(id, from_visit, place_id, visit_date, visit_type, session) VALUES(?,?,?,?,?,?)`,
				i+1, v.FromVisit, index[v.URL], prTime(v.Time), code, session); err != nil {
				return err
			}
		}
		return nil
	})
}

// revHost is the host reversed with a trailing dot, which is how Firefox
// stores it so that "everything under example.com" is a prefix search.
func revHost(host string) string {
	r := []rune(strings.ToLower(host))
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r) + "."
}

func splitOrigin(raw string) (prefix, host string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "https://", "localhost"
	}
	return u.Scheme + "://", u.Host
}

func origin(raw string) string {
	prefix, host := splitOrigin(raw)
	return prefix + host + "/"
}
