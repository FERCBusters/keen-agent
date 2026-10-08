package main

import (
	"testing"
	"time"
)

func TestIPParsingAndFilters(t *testing.T) {
	for _, ip := range []string{"35.221.69.202", "2001:db8::1"} {
		e := parse(Config{}, Source{Parser: "nginx"}, ip+` - - [05/Oct/2026:02:18:12 +0000] "GET /test HTTP/1.1" 404 146`, time.Now())
		if e.Fields["client.ip"] != ip {
			t.Fatal(e)
		}
	}
	e := Event{Fields: map[string]string{"client.ip": "2001:db8::1", "status": "404"}}
	if !fieldFilterMatches(e, FieldFilter{"client.ip", "in_cidr", "2001:db8::/32"}) {
		t.Fatal("IPv6 mismatch")
	}
	if fieldFilterMatches(e, FieldFilter{"client.ip", "in_cidr", "192.0.2.0/24"}) {
		t.Fatal("cross-family match")
	}
	s := Source{IncludeWhen: []FieldFilter{{"status", "equals", "404"}}, ExcludeWhen: []FieldFilter{{"client.ip", "in_cidr", "2001:db8::/32"}}}
	if keepStructured(s, e) {
		t.Fatal("exclusion must win")
	}
	if keepStructured(s, Event{Fields: map[string]string{}}) {
		t.Fatal("missing include field")
	}
	if validateFilters([]FieldFilter{{"client.ip", "in_cidr", "bad"}}) == nil {
		t.Fatal("accepted bad CIDR")
	}
}
func TestFilteredCheckpointAndCounterAtomic(t *testing.T) {
	sp := testSpool(t)
	s := Source{Name: "nginx", ExcludeWhen: []FieldFilter{{"status", "equals", "200"}}}
	e := event()
	e.Fields["status"] = "200"
	if err := sp.addFiltered(s, []Event{e}, "file", Checkpoint{Offset: 30}); err != nil {
		t.Fatal(err)
	}
	n, _, r := sp.stats()
	if n != 0 || r != 0 || sp.filteredStats([]Source{s})[s.Name] != 1 {
		t.Fatal("bad filtering counters")
	}
	var state Checkpoint
	sp.checkpoint("file", &state)
	if state.Offset != 30 {
		t.Fatal(state)
	}
	sp.limit = 1
	if err := sp.addFiltered(s, []Event{e}, "file", Checkpoint{Offset: 99}); err == nil {
		t.Fatal("expected full")
	}
	sp.checkpoint("file", &state)
	if state.Offset != 30 || sp.filteredStats([]Source{s})[s.Name] != 1 {
		t.Fatal("failed transaction advanced state")
	}
}

func TestAndExclusions(t *testing.T) {
	s := Source{ExcludeMatch: "all", ExcludeWhen: []FieldFilter{{"client.ip", "in_cidr", "192.0.2.0/24"}, {"status", "equals", "200"}}}
	if keepStructured(s, Event{Fields: map[string]string{"client.ip": "192.0.2.3", "status": "200"}}) {
		t.Fatal("all matched but retained")
	}
	if !keepStructured(s, Event{Fields: map[string]string{"client.ip": "192.0.2.3", "status": "404"}}) {
		t.Fatal("partial match discarded")
	}
	if !keepStructured(s, Event{Fields: map[string]string{"status": "200"}}) {
		t.Fatal("missing field discarded")
	}
	if !keepStructured(Source{ExcludeMatch: "all"}, event()) {
		t.Fatal("empty AND discarded")
	}
}
