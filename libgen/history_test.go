package libgen

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// TestRedirectChainTransitions: an ad click redirected twice by servers is one
// chain of three visits. Chrome marks the click as the chain's start, the last
// hop as its end and each hop after the click with how it was reached; Firefox
// gives a server-redirected visit its own type. A visit outside any chain
// keeps both chain bits, as an ordinary click does.
func TestRedirectChainTransitions(t *testing.T) {
	start := time.Date(2026, 3, 11, 9, 16, 0, 0, time.UTC)
	spec := HistorySpec{Visits: []Visit{
		{URL: "https://search.example/?q=invoice", Time: start, Transition: "typed"},
		{URL: "https://clk.adnet.test/c", Time: start.Add(time.Second), FromVisit: 1},
		{URL: "https://rtb.adnet.test/r", Time: start.Add(2 * time.Second), FromVisit: 2, Redirect: "server"},
		{URL: "https://lure.example/inv", Time: start.Add(3 * time.Second), FromVisit: 3, Redirect: "server"},
		{URL: "https://lure.example/inv/download", Time: start.Add(time.Minute), FromVisit: 4},
		{URL: "https://cdn.adnet.test/frame", Time: start.Add(2 * time.Minute), FromVisit: 5, Redirect: "client"},
	}}

	chrome, err := ChromeHistory(spec, prng.Root(3).Stream())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range queryInts(t, openDB(t, chrome), "SELECT transition FROM visits ORDER BY id") {
		got = append(got, fmt.Sprintf("%#08x", c))
	}
	// typed=1 and link=0 in the core byte; 0x10000000 starts a chain,
	// 0x20000000 ends one, 0x80000000 is a server and 0x40000000 a client redirect.
	want := []string{"0x30000001", "0x10000000", "0x80000000", "0xa0000000", "0x10000000", "0x60000000"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("chrome transitions = %v, want %v", got, want)
	}

	firefox, err := FirefoxPlaces(spec, prng.Root(3).Stream())
	if err != nil {
		t.Fatal(err)
	}
	// 2 TYPED, 1 LINK, 6 REDIRECT_TEMPORARY; a client redirect keeps LINK.
	if types := queryInts(t, openDB(t, firefox), "SELECT visit_type FROM moz_historyvisits ORDER BY id"); fmt.Sprint(types) != "[2 1 6 6 1 1]" {
		t.Errorf("firefox visit types = %v, want [2 1 6 6 1 1]", types)
	}
}

// TestDownloadURLChain: a download reached through redirects records every
// URL requested, in order, and the pages around it; without them it records
// its own URL as before.
func TestDownloadURLChain(t *testing.T) {
	when := time.Date(2026, 3, 11, 9, 17, 0, 0, time.UTC)
	spec := HistorySpec{Downloads: []Download{
		{
			URL: "https://lure.example/f.exe", TargetPath: `C:\f.exe`, Start: when, End: when,
			URLChain:       []string{"https://clk.adnet.test/d", "https://rtb.adnet.test/d", "https://lure.example/f.exe"},
			Referrer:       "https://lure.example/inv/download",
			TabURL:         "https://lure.example/inv/download",
			TabReferrerURL: "https://lure.example/inv",
		},
		{URL: "https://plain.example/a.zip", TargetPath: `C:\a.zip`, Start: when, End: when},
	}}
	data, err := ChromeHistory(spec, prng.Root(3).Stream())
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, data)
	chain := queryStrings(t, db, "SELECT id || ':' || chain_index || ' ' || url FROM downloads_url_chains ORDER BY id, chain_index")
	want := []string{
		"1:0 https://clk.adnet.test/d", "1:1 https://rtb.adnet.test/d", "1:2 https://lure.example/f.exe",
		"2:0 https://plain.example/a.zip",
	}
	if strings.Join(chain, "|") != strings.Join(want, "|") {
		t.Errorf("url chains = %v, want %v", chain, want)
	}
	pages := queryStrings(t, db, "SELECT referrer || ' ' || tab_url || ' [' || tab_referrer_url || ']' FROM downloads ORDER BY id")
	wantPages := []string{
		"https://lure.example/inv/download https://lure.example/inv/download [https://lure.example/inv]",
		"https://plain.example/a.zip https://plain.example/a.zip []",
	}
	if strings.Join(pages, "|") != strings.Join(wantPages, "|") {
		t.Errorf("download pages = %v, want %v", pages, wantPages)
	}
}

// TestRedirectsRefused: the builder refuses what the compiler refuses, for a
// caller that does not go through it.
func TestRedirectsRefused(t *testing.T) {
	for name, spec := range map[string]HistorySpec{
		"no from_visit": {Visits: []Visit{{URL: "https://a.example/", Redirect: "server"}}},
		"unknown":       {Visits: []Visit{{URL: "https://a.example/"}, {URL: "https://b.example/", FromVisit: 1, Redirect: "meta"}}},
		"forked": {Visits: []Visit{{URL: "https://a.example/"},
			{URL: "https://b.example/", FromVisit: 1, Redirect: "server"}, {URL: "https://c.example/", FromVisit: 1, Redirect: "client"}}},
		"chain end": {Downloads: []Download{{URL: "https://a.example/f", URLChain: []string{"https://b.example/f"}}}},
	} {
		if _, err := ChromeHistory(spec, prng.Root(1).Stream()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
