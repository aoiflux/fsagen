package compile

import "testing"

// TestHistoryRedirectRules: a redirect says how a visit was reached from the
// one before it, so it needs that visit; a chain is a line, so no visit is
// redirected onward twice; and a download's url chain ends at its url.
func TestHistoryRedirectRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n    path: History\n    format: chrome_history\n    history:\n"
	mustLoad(t, ModeManifest, head+`      visits:
        - { url: 'https://a.example/', transition: typed }
        - { url: 'https://b.test/c', from_visit: 1 }
        - { url: 'https://b.test/r', from_visit: 2, redirect: server }
        - { url: 'https://c.example/', from_visit: 3, redirect: client }
      downloads:
        - url: https://c.example/f.exe
          target_path: C:\f.exe
          url_chain: [https://b.test/d, https://c.example/f.exe]
          referrer: https://c.example/
          tab_url: https://c.example/
          tab_referrer_url: https://b.test/r
`)

	for _, tc := range []struct{ name, body, want string }{
		{"unknown", "      visits:\n        - { url: 'https://a.example/' }\n        - { url: 'https://b.example/', from_visit: 1, redirect: meta }\n", "unknown redirect \"meta\""},
		{"no from_visit", "      visits:\n        - { url: 'https://a.example/', redirect: server }\n", "a redirect needs from_visit"},
		{"forked", "      visits:\n        - { url: 'https://a.example/' }\n        - { url: 'https://b.example/', from_visit: 1, redirect: server }\n        - { url: 'https://c.example/', from_visit: 1, redirect: server }\n", "both redirected from visit 1"},
		{"chain end", "      downloads:\n        - { url: 'https://a.example/f', target_path: 'C:\\f', url_chain: ['https://a.example/f', 'https://b.example/g'] }\n", "url_chain must end at url"},
		{"chain empty", "      downloads:\n        - { url: 'https://a.example/f', target_path: 'C:\\f', url_chain: ['', 'https://a.example/f'] }\n", "url_chain[0] is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
