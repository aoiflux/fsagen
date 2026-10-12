package compile

import "testing"

// TestCookieBlockRules: a cookie jar needs its block and takes no filler, and
// every cookie is checked as the builder will check it before anything is
// written.
func TestCookieBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: Chrome/Default/Cookies\n    format: chrome_cookies\n"
	mustLoad(t, ModeManifest, head+"    cookies:\n      entries:\n        - { host: .adnet.test, name: uid, value: x, expires: '2027-01-01T00:00:00Z', secure: true, samesite: none }\n        - { host: lure.example, name: s, httponly: true }\n")

	for _, tc := range []struct{ name, body, want string }{
		{"no block", "", "needs a cookies block"},
		{"filler", "    content_len: 16\n    cookies: { entries: [ { host: a.example, name: a } ] }\n", "a cookie jar is as big as its cookies"},
		{"empty", "    cookies: { entries: [] }\n", "needs at least one entry"},
		{"url host", "    cookies: { entries: [ { host: 'https://a.example/', name: a } ] }\n", "is a URL, not a domain"},
		{"no name", "    cookies: { entries: [ { host: a.example } ] }\n", "no name"},
		{"samesite", "    cookies: { entries: [ { host: a.example, name: a, samesite: loose } ] }\n", "samesite \"loose\""},
		{"bad time", "    cookies: { entries: [ { host: a.example, name: a, expires: soon } ] }\n", "entries[0].expires"},
		{"expiry", "    cookies: { entries: [ { host: a.example, name: a, created: '2026-02-01T00:00:00Z', expires: '2026-01-01T00:00:00Z' } ] }\n", "expires before it was created"},
		{"repeat", "    cookies: { entries: [ { host: a.example, name: a }, { host: a.example, name: a, path: / } ] }\n", "entries[1] repeats entries[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
	mustFail(t, ModeManifest, "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: a.txt\n    format: text\n    cookies: { entries: [ { host: a.example, name: a } ] }\n", "only applies with format: chrome_cookies")
}
