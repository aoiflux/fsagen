package compile

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// EvtxBuiltin returns the built-in shape of an event, when it has one: its
// id is one fsagen knows, and it names no provider or the one Windows logs
// it with. An event with a known id from another provider is that
// provider's own event.
func EvtxBuiltin(ev spec.EvtxEvent) (libgen.EvtxBuiltin, bool) {
	b, ok := libgen.EvtxBuiltins(ev.EventID)
	if !ok || (ev.Provider != "" && ev.Provider != b.Event.Provider) {
		return libgen.EvtxBuiltin{}, false
	}
	return b, true
}

// EvtxChannel is the channel a log is for: the one the block names, or the
// one its first built-in event is logged to, or Application.
func EvtxChannel(e *spec.EvtxSpec) string {
	if e.Channel != "" {
		return e.Channel
	}
	for _, ev := range e.Events {
		if b, ok := EvtxBuiltin(ev); ok {
			return b.Channel
		}
	}
	return "Application"
}

// checkEvtx validates an evtx block against what an event log can hold.
func checkEvtx(op *Op, at func(string, string, ...any)) {
	e := op.Evtx
	if len(e.Events) == 0 {
		at("evtx", "needs at least one event; a log that was just cleared holds the 1102 that says so")
	}
	for _, f := range []field{{"channel", e.Channel}, {"computer", e.Computer}} {
		if f.val != "" && (strings.TrimSpace(f.val) == "" || strings.ContainsFunc(f.val, func(r rune) bool { return r < 0x20 })) {
			at("evtx", "%s %q must be a name: not blank, no control characters", f.key, f.val)
		}
	}
	if e.FirstRecordID < 0 || uint64(e.FirstRecordID)+uint64(len(e.Events)) > libgen.MaxEvtxRecordIDs {
		at("evtx", "first_record_id %d is out of range", e.FirstRecordID)
	}
	channel := EvtxChannel(e)
	for i, ev := range e.Events {
		checkEvtxEvent(ev, i, channel, at)
	}
}

// checkEvtxEvent checks one event: its numbers fit their fields, its times
// and identifiers parse, and its data are what its event takes.
func checkEvtxEvent(ev spec.EvtxEvent, i int, channel string, at func(string, string, ...any)) {
	where := "events[" + strconv.Itoa(i) + "]"
	if ev.EventID < 0 || ev.EventID > 0xFFFF {
		at("evtx", "%s: event_id %d does not fit 16 bits", where, ev.EventID)
	}
	b, builtin := EvtxBuiltin(ev)
	switch {
	case builtin && b.Channel != channel:
		at("evtx", "%s: event %d is logged to %s, not to this log's channel, %s", where, ev.EventID, b.Channel, channel)
	case !builtin && strings.TrimSpace(ev.Provider) == "":
		at("evtx", "%s: event %d is not built in (those are %s), so it needs the provider that logs it", where, ev.EventID, builtinIDs())
	}
	checkFiletimeField(at, "evtx", field{where + ".time", ev.Time})
	if ev.ProviderGUID != "" {
		if _, err := libgen.ParseGUID(ev.ProviderGUID); err != nil {
			at("evtx", "%s: provider_guid: %v", where, err)
		}
	}
	for _, n := range []struct {
		key  string
		val  *int
		bits int
	}{{"version", ev.Version, 8}, {"level", ev.Level, 8}, {"task", ev.Task, 16}, {"opcode", ev.Opcode, 8}, {"process_id", ev.ProcessID, 32}, {"thread_id", ev.ThreadID, 32}} {
		if n.val != nil && (*n.val < 0 || int64(*n.val) >= 1<<n.bits) {
			at("evtx", "%s: %s %d does not fit %d bits", where, n.key, *n.val, n.bits)
		}
	}
	if ev.Keywords != "" {
		if _, err := libgen.EvtxValue("hex64", ev.Keywords); err != nil {
			at("evtx", "%s: keywords: %v", where, err)
		}
	}
	if ev.UserSID != "" {
		if _, err := libgen.EncodeSID(ev.UserSID); err != nil {
			at("evtx", "%s: user_sid: %v", where, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(ev.Data)) {
		value := ev.Data[name]
		if !builtin {
			if strings.TrimSpace(name) == "" {
				at("evtx", "%s: a data name is blank", where)
			}
			continue
		}
		f := slices.IndexFunc(b.Event.Fields, func(f libgen.EvtxField) bool { return f.Name == name })
		if f < 0 {
			at("evtx", "%s: event %d has no data named %q (it has: %s)", where, ev.EventID, name, fieldNames(b.Event.Fields))
			continue
		}
		if _, err := libgen.EvtxValue(b.Event.Fields[f].Type, value); err != nil {
			at("evtx", "%s: data %s is a %s: %v", where, name, b.Event.Fields[f].Type, err)
		}
	}
}

func builtinIDs() string {
	var out []string
	for _, id := range libgen.EvtxBuiltinIDs {
		out = append(out, strconv.Itoa(id))
	}
	return strings.Join(out, ", ")
}

func fieldNames(fields []libgen.EvtxField) string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Name)
	}
	return strings.Join(out, ", ")
}

// cloneEvtx copies an evtx block down to each event's data, so a playbook
// action repeated by a step renders its tokens into a map of its own.
func cloneEvtx(e *spec.EvtxSpec) *spec.EvtxSpec {
	v := *e
	v.Events = make([]spec.EvtxEvent, len(e.Events))
	for i, ev := range e.Events {
		ev.Data = maps.Clone(ev.Data)
		for _, p := range []**int{&ev.Version, &ev.Level, &ev.Task, &ev.Opcode, &ev.ProcessID, &ev.ThreadID} {
			if *p != nil {
				n := **p
				*p = &n
			}
		}
		v.Events[i] = ev
	}
	return &v
}
