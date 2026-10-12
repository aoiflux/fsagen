package compile

import (
	"testing"

	"github.com/aoiflux/fsagen/spec"
)

// TestEvtxBlockRules: a .evtx with an evtx block is an event log without
// saying so; a log needs its block and takes no filler; and each event is
// checked against what its event takes before anything is written.
func TestEvtxBlockRules(t *testing.T) {
	const head = "start: 2026-01-01T00:00:00Z\noperations:\n  - action: create\n"
	p := mustLoad(t, ModeManifest, head+"    path: Logs/Security.evtx\n    evtx: { events: [ { event_id: 4624, data: { TargetUserName: user1, LogonType: 10 } } ] }\n")
	if got := p.Ops[0].Format; got != spec.FormatEvtx {
		t.Errorf("format %q, want evtx inferred from .evtx", got)
	}
	if got := EvtxChannel(p.Ops[0].Evtx); got != "Security" {
		t.Errorf("channel %q, want Security from event 4624", got)
	}

	for _, tc := range []struct{ name, body, want string }{
		{"no block", "    path: a.evtx\n", "needs an evtx block"},
		{"filler", "    path: a.evtx\n    content_len: 16\n    evtx: { events: [ { event_id: 4624 } ] }\n", "no region for filler"},
		{"wrong format", "    path: a.txt\n    format: text\n    evtx: { events: [ { event_id: 4624 } ] }\n", "only applies with format: evtx"},
		{"no events", "    path: a.evtx\n    evtx: { channel: Security }\n", "at least one event"},
		{"wrong channel", "    path: a.evtx\n    evtx: { channel: System, events: [ { event_id: 4624 } ] }\n", "logged to Security"},
		{"two channels", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624 }, { event_id: 7045 } ] }\n", "logged to System"},
		{"no provider", "    path: a.evtx\n    evtx: { events: [ { event_id: 4625 } ] }\n", "needs the provider"},
		{"big id", "    path: a.evtx\n    evtx: { events: [ { event_id: 70000, provider: X } ] }\n", "16 bits"},
		{"unknown data", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, data: { Username: user1 } } ] }\n", `no data named "Username"`},
		{"bad number", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, data: { LogonType: interactive } } ] }\n", "LogonType is a uint32"},
		{"bad sid", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, data: { TargetUserSid: user1 } } ] }\n", "not a SID"},
		{"bad guid", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, data: { LogonGuid: '{1}' } } ] }\n", "not a GUID"},
		{"bad time", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, time: soon } ] }\n", "events[0].time"},
		{"level", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, level: 300 } ] }\n", "level 300"},
		{"keywords", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, keywords: audit } ] }\n", "keywords"},
		{"user sid", "    path: a.evtx\n    evtx: { events: [ { event_id: 4624, user_sid: S-1 } ] }\n", "user_sid"},
		{"provider guid", "    path: a.evtx\n    evtx: { events: [ { event_id: 1, provider: X, provider_guid: nope } ] }\n", "provider_guid"},
		{"record id", "    path: a.evtx\n    evtx: { first_record_id: -1, events: [ { event_id: 4624 } ] }\n", "first_record_id"},
		{"computer", "    path: a.evtx\n    evtx: { computer: ' ', events: [ { event_id: 4624 } ] }\n", "computer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, ModeManifest, head+tc.body, tc.want)
		})
	}
}
